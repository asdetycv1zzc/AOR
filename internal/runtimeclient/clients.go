package runtimeclient

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/akimisaka/aor/internal/credentials"
	"github.com/akimisaka/aor/internal/runtimeconfig"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/minio/minio-go/v7"
	miniocredentials "github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	temporalclient "go.temporal.io/sdk/client"
)

var (
	ErrInvalidClientConfig   = errors.New("invalid runtime client configuration")
	ErrDependencyUnavailable = errors.New("runtime dependency unavailable")
)

const dependencyTimeout = 10 * time.Second

type Clients struct {
	config   runtimeconfig.Config
	database *sql.DB
	nats     *nats.Conn
	js       jetstream.JetStream
	temporal temporalclient.Client
	s3       *minio.Client
	http     *http.Client
	close    sync.Once
	closeErr error
}

func Open(ctx context.Context, config runtimeconfig.Config, resolver *credentials.SecretResolver) (*Clients, error) {
	if ctx == nil || resolver == nil || config.Validate() != nil {
		return nil, ErrInvalidClientConfig
	}
	clients := &Clients{
		config: config,
		http: &http.Client{
			Timeout: dependencyTimeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	opened := false
	defer func() {
		if !opened {
			_ = clients.Close()
		}
	}()

	if requiresDatabase(config.Component) {
		password, err := resolver.Resolve(ctx, config.Database.PasswordRef)
		if err != nil {
			return nil, unavailable("postgres")
		}
		database, err := openDatabase(ctx, config.Database, password)
		clear(password)
		if err != nil {
			return nil, unavailable("postgres")
		}
		clients.database = database
	}
	if requiresNATS(config.Component) {
		connection, js, err := openNATS(ctx, config)
		if err != nil {
			return nil, unavailable("nats")
		}
		clients.nats = connection
		clients.js = js
	}
	if requiresTemporal(config.Component) {
		connection, err := openTemporal(ctx, config.Temporal)
		if err != nil {
			return nil, unavailable("temporal")
		}
		clients.temporal = connection
	}
	if requiresS3(config.Component) {
		accessKey, err := resolver.Resolve(ctx, config.S3.AccessKeyRef)
		if err != nil {
			return nil, unavailable("s3")
		}
		secretKey, err := resolver.Resolve(ctx, config.S3.SecretKeyRef)
		if err != nil {
			clear(accessKey)
			return nil, unavailable("s3")
		}
		objectStore, err := openS3(ctx, config.S3, accessKey, secretKey)
		clear(accessKey)
		clear(secretKey)
		if err != nil {
			return nil, unavailable("s3")
		}
		clients.s3 = objectStore
	}
	if requiresOPA(config.Component) {
		if err := checkHTTPHealth(ctx, clients.http, config.OPA.URL+"/health"); err != nil {
			return nil, unavailable("opa")
		}
	}
	if requiresIdentity(config.Component) {
		if err := checkHTTPHealth(ctx, clients.http, config.Identity.JWKSURL); err != nil {
			return nil, unavailable("identity")
		}
	}
	if config.Component == "aor-worker" {
		for name, endpoint := range map[string]string{
			"aor-api":           config.Services.API,
			"aor-model-gateway": config.Services.ModelGateway,
			"aor-tool-broker":   config.Services.ToolBroker,
		} {
			if err := checkHTTPHealth(ctx, clients.http, strings.TrimRight(endpoint, "/")+"/health/ready"); err != nil {
				return nil, unavailable(name)
			}
		}
	}
	opened = true
	return clients, nil
}

func (clients *Clients) Database() *sql.DB {
	if clients == nil {
		return nil
	}
	return clients.database
}

func (clients *Clients) NATS() *nats.Conn {
	if clients == nil {
		return nil
	}
	return clients.nats
}

func (clients *Clients) JetStream() jetstream.JetStream {
	if clients == nil {
		return nil
	}
	return clients.js
}

func (clients *Clients) Temporal() temporalclient.Client {
	if clients == nil {
		return nil
	}
	return clients.temporal
}

func (clients *Clients) S3() *minio.Client {
	if clients == nil {
		return nil
	}
	return clients.s3
}

func (clients *Clients) Ready(ctx context.Context) error {
	if clients == nil || ctx == nil {
		return ErrInvalidClientConfig
	}
	if clients.database != nil {
		if err := clients.database.PingContext(ctx); err != nil {
			return unavailable("postgres")
		}
		var value int
		if err := clients.database.QueryRowContext(ctx, "SELECT 1").Scan(&value); err != nil || value != 1 {
			return unavailable("postgres")
		}
	}
	if clients.js != nil {
		if _, err := clients.js.AccountInfo(ctx); err != nil {
			return unavailable("nats")
		}
	}
	if clients.temporal != nil {
		if _, err := clients.temporal.CheckHealth(ctx, &temporalclient.CheckHealthRequest{}); err != nil {
			return unavailable("temporal")
		}
	}
	if clients.s3 != nil {
		exists, err := clients.s3.BucketExists(ctx, clients.config.S3.Bucket)
		if err != nil || !exists {
			return unavailable("s3")
		}
	}
	if requiresOPA(clients.config.Component) {
		if err := checkHTTPHealth(ctx, clients.http, clients.config.OPA.URL+"/health"); err != nil {
			return unavailable("opa")
		}
	}
	if requiresIdentity(clients.config.Component) {
		if err := checkHTTPHealth(ctx, clients.http, clients.config.Identity.JWKSURL); err != nil {
			return unavailable("identity")
		}
	}
	return nil
}

func (clients *Clients) Close() error {
	if clients == nil {
		return nil
	}
	clients.close.Do(func() {
		if clients.temporal != nil {
			clients.temporal.Close()
		}
		if clients.nats != nil {
			clients.nats.Close()
		}
		if clients.database != nil {
			clients.closeErr = clients.database.Close()
		}
	})
	return clients.closeErr
}

func openDatabase(ctx context.Context, config runtimeconfig.DatabaseConfig, password []byte) (*sql.DB, error) {
	dsn := &url.URL{
		Scheme: "postgresql",
		User:   url.UserPassword(config.User, string(password)),
		Host:   config.Address(),
		Path:   config.Name,
	}
	query := dsn.Query()
	query.Set("sslmode", config.SSLMode)
	dsn.RawQuery = query.Encode()
	database, err := sql.Open("pgx", dsn.String())
	if err != nil {
		return nil, err
	}
	database.SetMaxOpenConns(32)
	database.SetMaxIdleConns(8)
	database.SetConnMaxIdleTime(5 * time.Minute)
	database.SetConnMaxLifetime(30 * time.Minute)
	if err := database.PingContext(ctx); err != nil {
		_ = database.Close()
		return nil, err
	}
	return database, nil
}

func openNATS(ctx context.Context, config runtimeconfig.Config) (*nats.Conn, jetstream.JetStream, error) {
	connection, err := nats.Connect(
		config.NATS.URL,
		nats.Name(config.Component),
		nats.NoEcho(),
		nats.Timeout(dependencyTimeout),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(time.Second),
	)
	if err != nil {
		return nil, nil, err
	}
	js, err := jetstream.New(connection, jetstream.WithDefaultTimeout(dependencyTimeout))
	if err != nil {
		connection.Close()
		return nil, nil, err
	}
	_, err = js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:        config.NATS.Stream,
		Description: "AOR CloudEvents domain event stream",
		Subjects:    []string{"aor.>"},
		Retention:   jetstream.LimitsPolicy,
		Storage:     jetstream.FileStorage,
		Discard:     jetstream.DiscardOld,
		MaxAge:      30 * 24 * time.Hour,
		MaxMsgSize:  4 << 20,
		Replicas:    1,
	})
	if err != nil {
		connection.Close()
		return nil, nil, err
	}
	return connection, js, nil
}

func openTemporal(ctx context.Context, config runtimeconfig.TemporalConfig) (temporalclient.Client, error) {
	connection, err := temporalclient.DialContext(ctx, temporalclient.Options{
		HostPort:  config.Address,
		Namespace: config.Namespace,
	})
	if err != nil {
		return nil, err
	}
	if _, err := connection.CheckHealth(ctx, &temporalclient.CheckHealthRequest{}); err != nil {
		connection.Close()
		return nil, err
	}
	return connection, nil
}

func openS3(ctx context.Context, config runtimeconfig.S3Config, accessKey, secretKey []byte) (*minio.Client, error) {
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Host == "" {
		return nil, ErrInvalidClientConfig
	}
	client, err := minio.New(endpoint.Host, &minio.Options{
		Creds:        miniocredentials.NewStaticV4(string(accessKey), string(secretKey), ""),
		Secure:       endpoint.Scheme == "https",
		Region:       config.Region,
		BucketLookup: minio.BucketLookupPath,
		MaxRetries:   3,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			ForceAttemptHTTP2:     true,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: dependencyTimeout,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		},
	})
	if err != nil {
		return nil, err
	}
	exists, err := client.BucketExists(ctx, config.Bucket)
	if err != nil || !exists {
		return nil, ErrDependencyUnavailable
	}
	return client, nil
}

func checkHTTPHealth(ctx context.Context, client *http.Client, endpoint string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return ErrDependencyUnavailable
	}
	return nil
}

func unavailable(name string) error {
	return fmt.Errorf("%w: %s", ErrDependencyUnavailable, name)
}

func requiresDatabase(component string) bool {
	return component == "aor-server" || component == "aor-model-gateway" || component == "aor-tool-broker" || component == "aor-worker"
}

func requiresNATS(component string) bool {
	return component == "aor-server" || component == "aor-model-gateway" || component == "aor-tool-broker" || component == "aor-worker"
}

func requiresTemporal(component string) bool {
	return component == "aor-server" || component == "aor-worker"
}

func requiresS3(component string) bool {
	return component == "aor-server" || component == "aor-worker"
}

func requiresOPA(component string) bool {
	return component == "aor-server" || component == "aor-tool-broker" || component == "aor-worker"
}

func requiresIdentity(component string) bool {
	return component == "aor-server" || component == "aor-model-gateway" || component == "aor-tool-broker"
}

func clear(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
