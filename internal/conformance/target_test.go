package conformance

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type targetRoundTripFunc func(*http.Request) (*http.Response, error)

func (function targetRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestRunnerUsesTargetAndPersistsRawBuildEvidence(t *testing.T) {
	requested := []string{}
	transport := targetRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requested = append(requested, request.URL.String())
		if !strings.HasPrefix(request.Header.Get("Traceparent"), "00-") || request.Header.Get("X-Request-ID") == "" {
			t.Fatal("target probe did not carry independent correlation")
		}
		body := ""
		switch request.URL.Path {
		case "/aor/health/ready":
			body = `{"component":"aor-api","status":"ready"}`
		case "/aor/version":
			body = `{"component":"aor-api","version":"2.0.0-rc.1","commit":"0123456789abcdef0123456789abcdef01234567","specVersion":"2.0.0","productionReady":false}`
		default:
			return nil, errors.New("unexpected target path")
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    request,
		}, nil
	})
	output := t.TempDir()
	runner := NewRunner(func() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) })
	runner.client = &http.Client{Transport: transport}
	evidence, err := runner.Run(context.Background(), Request{
		Root:           "../..",
		Target:         "http://preproduction.example/aor/",
		Profile:        "test",
		SpecVersion:    "2.0.0",
		ReleaseVersion: "2.0.0-rc.1",
		SourceCommit:   "0123456789abcdef0123456789abcdef01234567",
		OutputDir:      output,
		Groups:         []string{"state-machine"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(requested) != 2 || requested[0] != "http://preproduction.example/aor/health/ready" || requested[1] != "http://preproduction.example/aor/version" {
		t.Fatalf("target requests = %#v", requested)
	}
	if evidence.Target != "http://preproduction.example/aor" || len(evidence.Results) != 1 || len(evidence.Results[0].EvidenceURIs) != 3 {
		t.Fatalf("target evidence was not bound to the result: %#v", evidence)
	}
	for index, name := range []string{"target-health.json", "target-version.json"} {
		path := filepath.Join(output, "raw", name)
		encoded, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		digest := sha256.Sum256(encoded)
		if evidence.Results[0].EvidenceURIs[index+1] != "file:raw/"+name+"#sha256="+hex.EncodeToString(digest[:]) {
			t.Fatalf("raw evidence reference = %q", evidence.Results[0].EvidenceURIs[index+1])
		}
		var exchange targetExchangeEvidence
		if json.Unmarshal(encoded, &exchange) != nil || exchange.Response.StatusCode != http.StatusOK {
			t.Fatalf("invalid raw exchange: %s", encoded)
		}
		body, decodeErr := base64.StdEncoding.DecodeString(exchange.Response.BodyBase64)
		if decodeErr != nil || !json.Valid(body) {
			t.Fatalf("raw response body = %q, %v", body, decodeErr)
		}
	}
}

func TestTargetBuildMismatchFailsClosed(t *testing.T) {
	transport := targetRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		body := `{"component":"aor-api","status":"ready"}`
		if request.URL.Path == "/version" {
			body = `{"component":"aor-api","version":"2.0.0-rc.1","commit":"ffffffffffffffffffffffffffffffffffffffff","specVersion":"2.0.0","productionReady":false}`
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
	})
	runner := NewRunner(nil)
	runner.client = &http.Client{Transport: transport}
	evidence, err := runner.Run(context.Background(), Request{
		Root:           "../..",
		Target:         "http://preproduction.example",
		Profile:        "test",
		SpecVersion:    "2.0.0",
		ReleaseVersion: "2.0.0-rc.1",
		SourceCommit:   "0123456789abcdef0123456789abcdef01234567",
		OutputDir:      t.TempDir(),
		Groups:         []string{"state-machine"},
	})
	if !errors.Is(err, ErrGateFailed) || len(evidence.Exceptions) == 0 || !strings.Contains(evidence.Exceptions[0], "build identity") {
		t.Fatalf("mismatched target result = %v, %#v", err, evidence.Exceptions)
	}
	if len(evidence.Results) != 1 || len(evidence.Results[0].EvidenceURIs) != 3 {
		t.Fatalf("failure did not retain both raw target exchanges: %#v", evidence.Results)
	}
}

func TestProductionTargetRequiresHTTPSAndRawOutput(t *testing.T) {
	runner := NewRunner(nil)
	request := Request{
		Root:           "../..",
		Target:         "http://preproduction.example",
		Profile:        "production",
		SpecVersion:    "2.0.0",
		ReleaseVersion: "2.0.0-rc.1",
		SourceCommit:   "0123456789abcdef0123456789abcdef01234567",
	}
	if _, err := runner.Run(context.Background(), request); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("insecure production target error = %v", err)
	}
	request.Target = "https://preproduction.example"
	request.Groups = []string{"contracts"}
	if _, err := runner.Run(context.Background(), request); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("partial production groups error = %v", err)
	}
}
