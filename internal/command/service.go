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

	"github.com/akimisaka/aor/internal/version"
)

var ErrInvalidCommand = errors.New("invalid command")

const (
	defaultListenAddress = ":8080"
	defaultHealthURL     = "http://127.0.0.1:8080/health/ready"
)

// Run preserves the version-only default while providing the long-running
// process and in-container health probe used by deployed profiles.
func Run(component string) error {
	if len(os.Args) == 1 || os.Args[1] == "version" {
		return WriteVersion(component)
	}
	switch os.Args[1] {
	case "serve":
		return runServer(component)
	case "healthcheck":
		return probeHealth(envOrDefault("AOR_HEALTHCHECK_URL", defaultHealthURL))
	default:
		return fmt.Errorf("%w: %s", ErrInvalidCommand, os.Args[1])
	}
}

func runServer(component string) error {
	dependencies, err := parseEndpoints(os.Getenv("AOR_REQUIRED_ENDPOINTS"))
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", envOrDefault("AOR_LISTEN_ADDR", defaultListenAddress))
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return Serve(ctx, component, listener, dependencies)
}

// Serve runs a bounded health and identity surface. Domain APIs remain owned
// by their service packages; this process surface only reports lifecycle and
// dependency readiness.
func Serve(ctx context.Context, component string, listener net.Listener, dependencies []string) error {
	if ctx == nil || component == "" || listener == nil {
		return ErrInvalidCommand
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", func(writer http.ResponseWriter, _ *http.Request) {
		writeStatus(writer, http.StatusOK, component, "live")
	})
	mux.HandleFunc("GET /health/ready", func(writer http.ResponseWriter, request *http.Request) {
		if err := endpointsReady(request.Context(), dependencies); err != nil {
			writeStatus(writer, http.StatusServiceUnavailable, component, "not_ready")
			return
		}
		writeStatus(writer, http.StatusOK, component, "ready")
	})
	mux.HandleFunc("GET /version", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(version.Current(component))
	})

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
