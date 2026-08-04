package command

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestServeReportsLifecycleAndDependencyReadiness(t *testing.T) {
	dependency, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dependency.Close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- Serve(ctx, "aor-test", listener, []string{dependency.Addr().String()})
	}()

	baseURL := "http://" + listener.Addr().String()
	waitForStatus(t, baseURL+"/health/live", http.StatusOK)
	waitForStatus(t, baseURL+"/health/ready", http.StatusOK)
	waitForStatus(t, baseURL+"/version", http.StatusOK)
	cancel()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestServeFailsReadinessWhenDependencyIsUnavailable(t *testing.T) {
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := closed.Addr().String()
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- Serve(ctx, "aor-test", listener, []string{endpoint})
	}()
	waitForStatus(t, "http://"+listener.Addr().String()+"/health/ready", http.StatusServiceUnavailable)
	cancel()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestServeWithHandlerMountsDomainRoutesAndUsesReadiness(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	domain := http.NewServeMux()
	domain.HandleFunc("GET /v1/test", func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusAccepted)
	})
	go func() {
		result <- ServeWithHandler(ctx, "aor-test", listener, func(context.Context) error { return nil }, domain)
	}()
	baseURL := "http://" + listener.Addr().String()
	waitForStatus(t, baseURL+"/v1/test", http.StatusAccepted)
	waitForStatus(t, baseURL+"/health/ready", http.StatusOK)
	cancel()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestParseEndpointsRejectsInvalidAndDeduplicates(t *testing.T) {
	endpoints, err := parseEndpoints("postgres:5432, postgres:5432,nats:4222")
	if err != nil {
		t.Fatal(err)
	}
	if len(endpoints) != 2 || endpoints[0] != "postgres:5432" || endpoints[1] != "nats:4222" {
		t.Fatalf("endpoints = %#v", endpoints)
	}
	for _, invalid := range []string{"postgres", ":5432", "postgres:0", "postgres:70000"} {
		if _, err := parseEndpoints(invalid); !errors.Is(err, ErrInvalidCommand) {
			t.Fatalf("parseEndpoints(%q) error = %v", invalid, err)
		}
	}
}

func waitForStatus(t *testing.T, url string, expected int) {
	t.Helper()
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(3 * time.Second)
	for {
		response, err := client.Get(url)
		if err == nil {
			response.Body.Close()
			if response.StatusCode == expected {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not return %d: %v", url, expected, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
