package servicebootstrap

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/akimisaka/aor/internal/runtimeclient"
	"github.com/akimisaka/aor/internal/runtimeconfig"
	"github.com/akimisaka/aor/internal/toolchain"
)

type toolchainProvisionerHandler struct {
	provisioner *toolchain.Provisioner
	cancel      context.CancelFunc
	done        chan struct{}
	close       sync.Once
}

func ToolchainProvisioner(config runtimeconfig.Config, clients *runtimeclient.Clients) (http.Handler, error) {
	if config.Component != "aor-toolchain-provisioner" || clients == nil || clients.Database() == nil {
		return nil, runtimeclient.ErrInvalidClientConfig
	}
	store, err := toolchain.NewInstallStore(clients.Database())
	if err != nil {
		return nil, err
	}
	installer, err := toolchain.NewArchiveInstaller(toolchain.ArchiveInstallerConfig{
		ToolchainRoot: config.ToolchainRoot,
		WorkRoot:      config.ToolchainWorkRoot,
	})
	if err != nil {
		return nil, err
	}
	provisioner, err := toolchain.NewProvisioner(store, installer, time.Second, time.Now)
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
