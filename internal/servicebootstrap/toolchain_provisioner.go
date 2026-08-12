package servicebootstrap

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/akimisaka/aor/internal/artifact"
	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/runtimeclient"
	"github.com/akimisaka/aor/internal/runtimeconfig"
	"github.com/akimisaka/aor/internal/toolchain"
	"github.com/akimisaka/aor/pkg/contracts"
)

type toolchainArtifactSource struct {
	catalog *artifact.PostgresS3Catalog
}

func (source toolchainArtifactSource) Open(ctx context.Context, tenantID, projectID, artifactID string, tool contracts.VersionedTool) (io.ReadCloser, error) {
	principalContext, err := authn.ContextWithPrincipal(ctx, authn.Principal{
		ID: "aor-toolchain-provisioner", Type: authn.PrincipalService, Role: authn.RoleService,
		TenantID: tenantID, ProjectID: projectID, Subject: "aor-toolchain-provisioner",
	})
	if err != nil {
		return nil, err
	}
	record, reader, err := source.catalog.Open(principalContext, tenantID, projectID, artifactID)
	if err != nil {
		return nil, err
	}
	if tool.Install == nil || record.URI != tool.Install.ArtifactRef || record.SHA256 != tool.Install.SourceSHA256 ||
		metadataString(record.Metadata, "kind") != "crosstool-ng-archive" ||
		metadataString(record.Metadata, "toolName") != tool.Name ||
		metadataString(record.Metadata, "toolVersion") != tool.Version ||
		canonicalToolchainArchitecture(metadataString(record.Metadata, "architecture")) != canonicalToolchainArchitecture(tool.Architecture) {
		_ = reader.Close()
		return nil, toolchain.ErrUploadedArchiveMetadata
	}
	return reader, nil
}

func metadataString(metadata map[string]any, key string) string {
	value, _ := metadata[key].(string)
	return value
}

func canonicalToolchainArchitecture(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "x86_64", "x64", "amd64":
		return "amd64"
	case "aarch64", "arm64":
		return "arm64"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

type toolchainProvisionerHandler struct {
	provisioner *toolchain.Provisioner
	cancel      context.CancelFunc
	done        chan struct{}
	close       sync.Once
}

func ToolchainProvisioner(config runtimeconfig.Config, clients *runtimeclient.Clients) (http.Handler, error) {
	if config.Component != "aor-toolchain-provisioner" || clients == nil || clients.Database() == nil || clients.S3() == nil {
		return nil, runtimeclient.ErrInvalidClientConfig
	}
	store, err := toolchain.NewInstallStore(clients.Database())
	if err != nil {
		return nil, err
	}
	catalog, err := artifact.NewPostgresS3Catalog(clients.Database(), clients.S3(), config.S3.Bucket, time.Now)
	if err != nil {
		return nil, err
	}
	prober, err := toolchain.NewUnixProbeClient(config.ToolchainProbeSocket)
	if err != nil {
		return nil, err
	}
	installer, err := toolchain.NewArchiveInstaller(toolchain.ArchiveInstallerConfig{
		ToolchainRoot: config.ToolchainRoot,
		WorkRoot:      config.ToolchainWorkRoot,
		Prober:        prober,
	})
	if err != nil {
		return nil, err
	}
	provisioner, err := toolchain.NewProvisioner(store, installer, time.Second, time.Now, toolchainArtifactSource{catalog: catalog})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	handler := &toolchainProvisionerHandler{provisioner: provisioner, cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(handler.done)
		provisioner.Run(ctx)
	}()
	return handler, nil
}

func (handler *toolchainProvisionerHandler) ServeHTTP(writer http.ResponseWriter, _ *http.Request) {
	writer.WriteHeader(http.StatusNotFound)
}

func (handler *toolchainProvisionerHandler) Ready() error {
	if handler == nil || handler.provisioner == nil {
		return toolchain.ErrProvisionerUnavailable
	}
	return handler.provisioner.Ready()
}

func (handler *toolchainProvisionerHandler) Close() error {
	if handler == nil {
		return nil
	}
	handler.close.Do(func() {
		handler.cancel()
	})
	select {
	case <-handler.done:
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("toolchain provisioner shutdown timed out")
	}
}
