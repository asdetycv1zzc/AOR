package command

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/akimisaka/aor/internal/credentials"
	"github.com/akimisaka/aor/internal/runtimeclient"
	"github.com/akimisaka/aor/internal/runtimeconfig"
	"github.com/akimisaka/aor/internal/version"
)

var ErrInvalidCommand = errors.New("invalid command")

const (
	defaultListenAddress = ":8080"
	defaultHealthURL     = "http://127.0.0.1:8080/health/ready"
)

type HandlerFactory func(runtimeconfig.Config, *runtimeclient.Clients) (http.Handler, error)

type ReadinessCheck func(context.Context) error

// Run preserves the version-only default while providing the long-running
// process and in-container health probe used by deployed profiles.
func Run(component string, factories ...HandlerFactory) error {
	if len(os.Args) == 1 || os.Args[1] == "version" {
		return WriteVersion(component)
	}
	if len(factories) > 1 {
		return ErrInvalidCommand
	}
	switch os.Args[1] {
	case "serve":
		var factory HandlerFactory
		if len(factories) == 1 {
			factory = factories[0]
		}
		return runServer(component, factory)
	case "healthcheck":
		return probeHealth(envOrDefault("AOR_HEALTHCHECK_URL", defaultHealthURL))
	default:
		return fmt.Errorf("%w: %s", ErrInvalidCommand, os.Args[1])
	}
}

func runServer(component string, factory HandlerFactory) error {
	config, err := runtimeconfig.Load(component, os.LookupEnv)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	resolver := credentials.NewSecretResolver(envOrDefault("AOR_SECRET_ROOT", credentials.DefaultSecretRoot))
	clients, err := runtimeclient.Open(ctx, config, resolver)
	if err != nil {
		return err
	}
	defer clients.Close()
	var domain http.Handler
	if factory != nil {
		domain, err = factory(config, clients)
		if err != nil || domain == nil {
			return ErrInvalidCommand
		}
		if closeable, ok := domain.(interface{ Close() error }); ok {
			defer closeable.Close()
		}
	}
	readiness := clients.Ready
	if domainReady, ok := domain.(interface{ Ready() error }); ok {
		readiness = func(checkCtx context.Context) error {
			if err := clients.Ready(checkCtx); err != nil {
				return err
			}
			return domainReady.Ready()
		}
	}
	listener, err := net.Listen("tcp", config.ListenAddress)
	if err != nil {
		return err
	}
	return ServeWithHandler(ctx, component, listener, readiness, domain)
}

// Serve runs a bounded health and identity surface. Domain APIs remain owned
// by their service packages; this process surface only reports lifecycle and
// dependency readiness.
func Serve(ctx context.Context, component string, listener net.Listener, dependencies []string) error {
	return ServeWithHandler(ctx, component, listener, func(checkCtx context.Context) error {
		return endpointsReady(checkCtx, dependencies)
	}, nil)
}

func ServeWithHandler(ctx context.Context, component string, listener net.Listener, readiness ReadinessCheck, domain http.Handler) error {
	if ctx == nil || component == "" || listener == nil {
		return ErrInvalidCommand
	}
	if readiness == nil {
		readiness = func(context.Context) error { return ErrInvalidCommand }
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", func(writer http.ResponseWriter, _ *http.Request) {
		writeStatus(writer, http.StatusOK, component, "live")
	})
	mux.HandleFunc("GET /health/ready", func(writer http.ResponseWriter, request *http.Request) {
		checkCtx, cancel := context.WithTimeout(request.Context(), 3*time.Second)
		defer cancel()
		if err := readiness(checkCtx); err != nil {
			writeStatus(writer, http.StatusServiceUnavailable, component, "not_ready")
			return
		}
		writeStatus(writer, http.StatusOK, component, "ready")
	})
	mux.HandleFunc("GET /version", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(version.Current(component))
	})
	if domain != nil {
		mux.Handle("/", domain)
	}

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	result := make(chan error, 1)
	go func() {
		err := server.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		result <- err
	}()

	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return err
		}
		return <-result
	}
}

func endpointsReady(ctx context.Context, endpoints []string) error {
	for _, endpoint := range endpoints {
		dialer := net.Dialer{Timeout: time.Second}
		connection, err := dialer.DialContext(ctx, "tcp", endpoint)
		if err != nil {
			return err
		}
		if err := connection.Close(); err != nil {
			return err
		}
	}
	return nil
}

func parseEndpoints(value string) ([]string, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	endpoints := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, raw := range parts {
		endpoint := strings.TrimSpace(raw)
		host, portText, err := net.SplitHostPort(endpoint)
		if err != nil || host == "" {
			return nil, fmt.Errorf("%w: dependency endpoint", ErrInvalidCommand)
		}
		port, conversionErr := strconv.Atoi(portText)
		if conversionErr != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("%w: dependency port", ErrInvalidCommand)
		}
		if _, exists := seen[endpoint]; exists {
			continue
		}
		seen[endpoint] = struct{}{}
		endpoints = append(endpoints, endpoint)
	}
	return endpoints, nil
}

func probeHealth(url string) error {
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get(url)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("health endpoint returned %d", response.StatusCode)
	}
	return nil
}

func writeStatus(writer http.ResponseWriter, status int, component, state string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(struct {
		Component string `json:"component"`
		Status    string `json:"status"`
	}{Component: component, Status: state})
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
