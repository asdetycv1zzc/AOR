package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProjectCreateUsesHTTPSBearerAndIdempotency(t *testing.T) {
	var requestBody map[string]any
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/projects" || request.Method != http.MethodPost {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		if got := request.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Fatalf("Authorization = %q", got)
		}
		if got := request.Header.Get("Idempotency-Key"); got != "create-key" {
			t.Fatalf("Idempotency-Key = %q", got)
		}
		if err := json.NewDecoder(request.Body).Decode(&requestBody); err != nil {
			t.Fatal(err)
		}
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(response, `{"id":"project-one","state":"CREATED","stateVersion":1}`)
	}))
	defer server.Close()

	exitCode, stdout, stderr := runTestCLI(t, server, "", []string{
		"--server", server.URL, "--json", "project", "create", "--name", "Example", "--goal-agent-count", "2",
		"--data-classification", "confidential", "--idempotency-key", "create-key",
	})
	if exitCode != 0 || stderr != "" {
		t.Fatalf("exit = %d, stderr = %q", exitCode, stderr)
	}
	if requestBody["name"] != "Example" || requestBody["goalAgentCount"] != float64(2) || requestBody["dataClassification"] != "CONFIDENTIAL" {
		t.Fatalf("body = %#v", requestBody)
	}
	if !json.Valid([]byte(stdout)) || !strings.Contains(stdout, `"project-one"`) {
		t.Fatalf("stdout = %q", stdout)
	}
}

func TestProjectAbortRequiresAndUsesExplicitConfirmation(t *testing.T) {
	postCalled := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/v1/projects/project-one/state":
			response.Header().Set("Content-Type", "application/json")
			response.Header().Set("ETag", `"project-7"`)
			_, _ = io.WriteString(response, `{"id":"project-one","state":"EXECUTING","stateVersion":7}`)
		case request.Method == http.MethodPost && request.URL.Path == "/v1/projects/project-one:abort":
			postCalled = true
			if request.Header.Get("If-Match") != `"project-7"` {
				t.Fatalf("If-Match = %q", request.Header.Get("If-Match"))
			}
			var body struct {
				ExpectedVersion int64 `json:"expectedVersion"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil || body.ExpectedVersion != 7 {
				t.Fatalf("body = %#v, err = %v", body, err)
			}
			response.Header().Set("Content-Type", "application/json")
			response.WriteHeader(http.StatusAccepted)
			_, _ = io.WriteString(response, `{"id":"project-one","state":"ABORTED","stateVersion":8}`)
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	exitCode, _, _ := runTestCLI(t, server, "wrong\n", []string{"--server", server.URL, "project", "abort", "project-one"})
	if exitCode != 1 || postCalled {
		t.Fatalf("unconfirmed exit = %d, postCalled = %v", exitCode, postCalled)
	}
	exitCode, _, stderr := runTestCLI(t, server, "project-one\n", []string{"--server", server.URL, "project", "abort", "project-one"})
	if exitCode != 0 || !postCalled || !strings.Contains(stderr, "confirm abort") {
		t.Fatalf("confirmed exit = %d, postCalled = %v, stderr = %q", exitCode, postCalled, stderr)
	}
}

func TestTaskDecisionNormalizesSpecVocabulary(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.Method {
		case http.MethodGet:
			response.Header().Set("Content-Type", "application/json")
			response.Header().Set("ETag", `"task-3"`)
			_, _ = io.WriteString(response, `{"id":"task-one","version":3}`)
		case http.MethodPost:
			var body map[string]any
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["decision"] != "HAND_OFF_TO_HUMAN" || body["expectedVersion"] != float64(3) {
				t.Fatalf("body = %#v", body)
			}
			response.Header().Set("Content-Type", "application/json")
			response.WriteHeader(http.StatusAccepted)
			_, _ = io.WriteString(response, `{"commandId":"decision-one"}`)
		}
	}))
	defer server.Close()
	exitCode, _, stderr := runTestCLI(t, server, "", []string{
		"--server", server.URL, "task", "decide", "project-one", "task-one", "--decision", "HUMAN_TAKEOVER",
	})
	if exitCode != 0 || stderr != "" {
		t.Fatalf("exit = %d, stderr = %q", exitCode, stderr)
	}
}

func TestGoalDiffIsStableJSON(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/projects/project-one/goal/specs/2":
			_, _ = io.WriteString(response, `{"name":"old","nested":{"kept":true,"removed":1}}`)
		case "/v1/projects/project-one/goal/specs/3":
			_, _ = io.WriteString(response, `{"name":"new","nested":{"added":2,"kept":true}}`)
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	exitCode, stdout, stderr := runTestCLI(t, server, "", []string{
		"--server", server.URL, "--json", "goal", "diff", "project-one", "--from", "2", "--to", "3",
	})
	if exitCode != 0 || stderr != "" {
		t.Fatalf("exit = %d, stderr = %q", exitCode, stderr)
	}
	var result struct {
		Changes []jsonChange `json:"changes"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatal(err)
	}
	wantPaths := []string{"/name", "/nested/added", "/nested/removed"}
	if len(result.Changes) != len(wantPaths) {
		t.Fatalf("changes = %#v", result.Changes)
	}
	for index, want := range wantPaths {
		if result.Changes[index].Path != want {
			t.Fatalf("change[%d].Path = %q", index, result.Changes[index].Path)
		}
	}
}

func TestTokenCanBeReadOnceFromStdin(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer stdin-token" {
			t.Fatalf("Authorization = %q", request.Header.Get("Authorization"))
		}
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("ETag", `"1"`)
		_, _ = io.WriteString(response, `{"id":"project-one","state":"CREATED","stateVersion":1}`)
	}))
	defer server.Close()
	config := Config{
		Stdin: strings.NewReader("stdin-token\n"), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, HTTPClient: server.Client(),
		LookupEnv: func(string) (string, bool) { return "", false },
	}
	if err := Run(context.Background(), []string{"--server", server.URL, "--token-stdin", "project", "status", "project-one"}, config); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPServerIsRejected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("HTTP endpoint must not be called")
	}))
	defer server.Close()
	exitCode, _, stderr := runTestCLI(t, nil, "", []string{"--server", server.URL, "project", "status", "project-one"})
	if exitCode != 1 || !strings.Contains(stderr, "HTTPS") {
		t.Fatalf("exit = %d, stderr = %q", exitCode, stderr)
	}
}

func TestJSONServerErrorIsUsefulAndRedacted(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/problem+json")
		response.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(response, `{"error":{"code":"POLICY_DENIED","message":"request is not authorized","traceId":"trace-one"},"internal":"secret"}`)
	}))
	defer server.Close()
	exitCode, _, stderr := runTestCLI(t, server, "", []string{"--server", server.URL, "--json", "project", "status", "project-one"})
	if exitCode != 1 || !strings.Contains(stderr, "POLICY_DENIED") || !strings.Contains(stderr, "trace-one") || strings.Contains(stderr, "secret") {
		t.Fatalf("exit = %d, stderr = %q", exitCode, stderr)
	}
}

func TestContractGapsAreReportedBeforeNetworkAccess(t *testing.T) {
	config := Config{
		Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{},
		LookupEnv: func(string) (string, bool) { return "", false },
	}
	for _, args := range [][]string{
		{"audit", "show", "audit-one"},
		{"artifact", "download", "artifact://sha256/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	} {
		err := Run(context.Background(), args, config)
		var typed *commandError
		if !errors.As(err, &typed) || typed.code != "SERVER_CONTRACT_GAP" {
			t.Fatalf("Run(%v) error = %#v", args, err)
		}
	}
}

func TestArtifactDownloadResolvesPagesAndKeepsJSONOutputMachineReadable(t *testing.T) {
	const artifactURI = "artifact://sha256/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/projects/project-one/artifacts":
			response.Header().Set("Content-Type", "application/json")
			if request.URL.Query().Get("cursor") == "next-page" {
				_, _ = io.WriteString(response, `{"items":[{"id":"artifact-one","uri":"`+artifactURI+`"}]}`)
			} else {
				_, _ = io.WriteString(response, `{"items":[],"nextCursor":"next-page"}`)
			}
		case "/v1/projects/project-one/artifacts/artifact-one":
			response.Header().Set("Content-Type", "application/octet-stream")
			_, _ = io.WriteString(response, "artifact bytes")
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	exitCode, stdout, stderr := runTestCLI(t, server, "", []string{
		"--server", server.URL, "--json", "artifact", "download", artifactURI, "--project", "project-one",
	})
	if exitCode != 0 || stderr != "" {
		t.Fatalf("exit = %d, stderr = %q", exitCode, stderr)
	}
	var result struct {
		ContentBase64 string `json:"contentBase64"`
		ContentType   string `json:"contentType"`
		Size          int    `json:"size"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatal(err)
	}
	if result.ContentBase64 != "YXJ0aWZhY3QgYnl0ZXM=" || result.ContentType != "application/octet-stream" || result.Size != 14 {
		t.Fatalf("result = %#v", result)
	}
}

func TestResponseSizeIsBounded(t *testing.T) {
	response := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(strings.Repeat("x", maximumResponse+1))),
	}
	_, err := readResponse(response)
	var typed *commandError
	if !errors.As(err, &typed) || typed.code != "RESPONSE_TOO_LARGE" {
		t.Fatalf("error = %#v", err)
	}
}

func TestAllSPEC19CommandsAreRegistered(t *testing.T) {
	for _, command := range []string{
		"project create", "project status", "goal send", "goal diff", "goal approve", "task list", "task show",
		"task decide", "audit show", "artifact download", "knowledge refs", "budget show", "project pause", "project resume",
		"project abort", "admin doctor", "admin policy test", "admin sandbox probe",
	} {
		if _, found := commandDefinitions[command]; !found {
			t.Fatalf("command %q is not registered", command)
		}
	}
}

func runTestCLI(t *testing.T, server *httptest.Server, stdin string, args []string) (int, string, string) {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	var httpClient *http.Client
	if server != nil {
		httpClient = server.Client()
	}
	exitCode := Main(context.Background(), args, Config{
		Stdin: strings.NewReader(stdin), Stdout: &stdout, Stderr: &stderr, HTTPClient: httpClient,
		LookupEnv: func(name string) (string, bool) {
			if name == "AOR_TOKEN" {
				return "test-token", true
			}
			return "", false
		},
	})
	return exitCode, stdout.String(), stderr.String()
}
