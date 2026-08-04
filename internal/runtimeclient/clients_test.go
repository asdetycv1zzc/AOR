package runtimeclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/akimisaka/aor/internal/credentials"
	"github.com/akimisaka/aor/internal/runtimeconfig"
)

func TestOpenRejectsInvalidArgumentsBeforeConnecting(t *testing.T) {
	resolver := credentials.NewSecretResolver(t.TempDir())
	if clients, err := Open(nil, runtimeconfig.Config{}, resolver); clients != nil || !errors.Is(err, ErrInvalidClientConfig) {
		t.Fatalf("nil context result = %v, %v", clients, err)
	}
	if clients, err := Open(context.Background(), runtimeconfig.Config{}, nil); clients != nil || !errors.Is(err, ErrInvalidClientConfig) {
		t.Fatalf("nil resolver result = %v, %v", clients, err)
	}
}

func TestCheckHTTPHealthRejectsRedirectsAndFailures(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/ready":
			writer.WriteHeader(http.StatusNoContent)
		case "/redirect":
			http.Redirect(writer, request, "/ready", http.StatusFound)
		default:
			writer.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer server.Close()
	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if err := checkHTTPHealth(context.Background(), client, server.URL+"/ready"); err != nil {
		t.Fatalf("ready check: %v", err)
	}
	for _, endpoint := range []string{"/redirect", "/failed"} {
		if err := checkHTTPHealth(context.Background(), client, server.URL+endpoint); err == nil {
			t.Fatalf("endpoint %s passed", endpoint)
		}
	}
}

func TestClearOverwritesSecretBytes(t *testing.T) {
	value := []byte("not-a-real-secret")
	clear(value)
	for index, current := range value {
		if current != 0 {
			t.Fatalf("byte %d was not cleared", index)
		}
	}
}

func TestCloseIsNilSafeAndIdempotent(t *testing.T) {
	var clients *Clients
	if err := clients.Close(); err != nil {
		t.Fatalf("nil close: %v", err)
	}
	clients = &Clients{}
	if err := clients.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := clients.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}
