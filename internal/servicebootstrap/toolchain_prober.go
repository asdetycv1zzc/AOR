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

type toolchainProberHandler struct {
	server *toolchain.ProbeServer
	cancel context.CancelFunc
	done   chan error
	close  sync.Once
}

func ToolchainProber(config runtimeconfig.Config, _ *runtimeclient.Clients) (http.Handler, error) {
	if config.Component != "aor-toolchain-prober" {
		return nil, runtimeclient.ErrInvalidClientConfig
	}
	server, err := toolchain.NewProbeServer(config.ToolchainProbeSocket, config.ToolchainWorkRoot)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	handler := &toolchainProberHandler{server: server, cancel: cancel, done: make(chan error, 1)}
	go func() { handler.done <- server.Run(ctx) }()
	return handler, nil
}

func (handler *toolchainProberHandler) ServeHTTP(writer http.ResponseWriter, _ *http.Request) {
	writer.WriteHeader(http.StatusNotFound)
}

func (handler *toolchainProberHandler) Ready() error {
	if handler == nil || handler.server == nil {
		return toolchain.ErrProvisionerUnavailable
	}
	return handler.server.Ready()
}

func (handler *toolchainProberHandler) Close() error {
	if handler == nil {
		return nil
	}
	handler.close.Do(func() {
		handler.cancel()
		_ = handler.server.Close()
	})
	select {
	case err := <-handler.done:
		return err
	case <-time.After(5 * time.Second):
		return errors.New("toolchain prober shutdown timed out")
	}
}
