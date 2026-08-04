package cli

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	aorsdk "github.com/akimisaka/aor/sdk/go/aor"
)

type responseSnapshot struct {
	Version int64
	ETag    string
}

func (application *app) getProjectSnapshot(ctx context.Context, projectID string) (responseSnapshot, error) {
	client, err := application.api()
	if err != nil {
		return responseSnapshot{}, err
	}
	response, err := client.GetProjectState(ctx, aorsdk.RequestOptions{PathParameters: projectPath(projectID)})
	if err != nil {
		return responseSnapshot{}, requestFailure(err)
	}
	return readSnapshot(response, "stateVersion")
}

func (application *app) getTaskSnapshot(ctx context.Context, projectID, taskID string) (responseSnapshot, error) {
	client, err := application.api()
	if err != nil {
		return responseSnapshot{}, err
	}
	response, err := client.GetTask(ctx, aorsdk.RequestOptions{PathParameters: taskPath(projectID, taskID)})
	if err != nil {
		return responseSnapshot{}, requestFailure(err)
	}
	return readSnapshot(response, "version")
}

func readSnapshot(response *http.Response, versionField string) (responseSnapshot, error) {
	body, err := readResponse(response)
	if err != nil {
		return responseSnapshot{}, err
	}
	var value map[string]json.RawMessage
	if err := json.Unmarshal(body, &value); err != nil {
		return responseSnapshot{}, runtimeError("INVALID_SERVER_RESPONSE", "the server returned an invalid resource representation")
	}
	var version int64
	if raw, found := value[versionField]; !found || json.Unmarshal(raw, &version) != nil || version < 0 {
		return responseSnapshot{}, runtimeError("INVALID_SERVER_RESPONSE", "the server response does not contain a valid "+versionField)
	}
	etag := response.Header.Get("ETag")
	if etag == "" || len(etag) > 256 || strings.ContainsAny(etag, "\r\n\x00") {
		return responseSnapshot{}, runtimeError("INVALID_SERVER_RESPONSE", "the server response does not contain a valid ETag")
	}
	return responseSnapshot{Version: version, ETag: etag}, nil
}

func (application *app) emitResponse(response *http.Response) error {
	body, err := readResponse(response)
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return writeValue(application.config.Stdout, map[string]any{"status": response.StatusCode}, application.globals.json)
	}
	if json.Valid(body) {
		var value any
		if err := json.Unmarshal(body, &value); err != nil {
			return runtimeError("INVALID_SERVER_RESPONSE", "the server returned invalid JSON")
		}
		return writeValue(application.config.Stdout, value, application.globals.json)
	}
	if application.globals.json {
		return writeValue(application.config.Stdout, map[string]any{
			"contentBase64": base64.StdEncoding.EncodeToString(body),
			"contentType":   responseMediaType(response),
			"size":          len(body),
		}, true)
	}
	if _, err := application.config.Stdout.Write(body); err != nil {
		return runtimeError("OUTPUT_FAILED", "could not write command output")
	}
	return nil
}

func (application *app) emitArtifactContent(response *http.Response) error {
	body, err := readResponse(response)
	if err != nil {
		return err
	}
	if json.Valid(body) {
		return formatContractGap("artifact download", "the artifact endpoint returned metadata JSON and exposes no content response or download route")
	}
	if application.globals.json {
		return writeValue(application.config.Stdout, map[string]any{
			"contentBase64": base64.StdEncoding.EncodeToString(body),
			"contentType":   responseMediaType(response),
			"size":          len(body),
		}, true)
	}
	if _, err := application.config.Stdout.Write(body); err != nil {
		return runtimeError("OUTPUT_FAILED", "could not write artifact content")
	}
	return nil
}

func readResponse(response *http.Response) ([]byte, error) {
	if response == nil || response.Body == nil {
		return nil, runtimeError("INVALID_SERVER_RESPONSE", "the server returned no response")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumResponse+1))
	if err != nil {
		return nil, runtimeError("RESPONSE_READ_FAILED", "could not read the server response")
	}
	if len(body) > maximumResponse {
		return nil, runtimeError("RESPONSE_TOO_LARGE", "the server response exceeds 8 MiB")
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, serverFailure(response.StatusCode, body)
	}
	return body, nil
}

func serverFailure(status int, body []byte) error {
	var problem struct {
		Title string `json:"title"`
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			TraceID string `json:"traceId"`
		} `json:"error"`
	}
	message := http.StatusText(status)
	code := "HTTP_" + strconv.Itoa(status)
	if json.Unmarshal(body, &problem) == nil {
		if problem.Error.Code != "" {
			code = problem.Error.Code
		}
		if problem.Error.Message != "" {
			message = problem.Error.Message
		} else if problem.Title != "" {
			message = problem.Title
		}
		if problem.Error.TraceID != "" {
			message += " (trace " + problem.Error.TraceID + ")"
		}
	}
	return runtimeError(code, "server returned "+strconv.Itoa(status)+": "+message)
}

func requestFailure(err error) error {
	if err == nil {
		return nil
	}
	return runtimeError("REQUEST_FAILED", "AOR API request failed: "+err.Error())
}

func commandHeaders(idempotencyKey, etag string) http.Header {
	headers := make(http.Header)
	headers.Set("Idempotency-Key", idempotencyKey)
	if etag != "" {
		headers.Set("If-Match", etag)
	}
	return headers
}

func idempotencyKey(arguments parsedArguments) (string, error) {
	if configured := arguments.value("idempotency-key"); configured != "" {
		if len(configured) > 256 || !utf8.ValidString(configured) || strings.ContainsAny(configured, "\r\n\x00") {
			return "", usageError("--idempotency-key is invalid")
		}
		return configured, nil
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", runtimeError("RANDOM_SOURCE_FAILED", "could not create an idempotency key")
	}
	return "aor-cli-" + hex.EncodeToString(random), nil
}

func projectPath(projectID string) map[string]string {
	return map[string]string{"projectId": projectID}
}

func taskPath(projectID, taskID string) map[string]string {
	return map[string]string{"projectId": projectID, "taskId": taskID}
}

func versionPath(projectID string, version int64) map[string]string {
	return map[string]string{"projectId": projectID, "version": strconv.FormatInt(version, 10)}
}

func readBoundedFile(path string) ([]byte, error) {
	if path == "" {
		return nil, usageError("a file path is required")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, runtimeError("INPUT_READ_FAILED", "could not open input file "+path)
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, maximumRequestBody+1))
	if err != nil {
		return nil, runtimeError("INPUT_READ_FAILED", "could not read input file "+path)
	}
	if len(contents) > maximumRequestBody {
		return nil, runtimeError("INPUT_TOO_LARGE", "input file exceeds 1 MiB")
	}
	return contents, nil
}

func readJSONObject(path string) (map[string]any, error) {
	if path == "" {
		return map[string]any{}, nil
	}
	contents, err := readBoundedFile(path)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(contents)))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil || value == nil {
		return nil, usageError("--file must contain one JSON object")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return nil, usageError("--file must contain one JSON object")
	}
	return value, nil
}

func parsePage(body []byte) ([]json.RawMessage, error) {
	items, _, err := parsePageWithCursor(body)
	return items, err
}

func parsePageWithCursor(body []byte) ([]json.RawMessage, string, error) {
	var page struct {
		Items      []json.RawMessage `json:"items"`
		NextCursor string            `json:"nextCursor"`
	}
	if err := json.Unmarshal(body, &page); err != nil || page.Items == nil {
		return nil, "", runtimeError("INVALID_SERVER_RESPONSE", "the server returned an invalid page")
	}
	if len(page.NextCursor) > 512 || strings.ContainsAny(page.NextCursor, "\r\n\x00") {
		return nil, "", runtimeError("INVALID_SERVER_RESPONSE", "the server returned an invalid page cursor")
	}
	return page.Items, page.NextCursor, nil
}

func responseMediaType(response *http.Response) string {
	value, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil {
		return ""
	}
	return strings.ToLower(value)
}

func validateURI(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, usageError("artifact URI is invalid")
	}
	return parsed, nil
}

func requirePositiveInteger(arguments parsedArguments, name string) (int64, error) {
	raw := arguments.value(name)
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value < 1 {
		return 0, usageError("--" + name + " must be a positive integer")
	}
	return value, nil
}

func requireValue(arguments parsedArguments, name string) (string, error) {
	value := arguments.value(name)
	if strings.TrimSpace(value) == "" {
		return "", usageError("--" + name + " is required")
	}
	return value, nil
}

func ensureIdentifier(value, label string) error {
	if value == "" || len(value) > 256 || !utf8.ValidString(value) || strings.ContainsAny(value, "\x00\r\n") {
		return usageError(label + " is invalid")
	}
	return nil
}

func formatContractGap(command, detail string) error {
	return runtimeError("SERVER_CONTRACT_GAP", fmt.Sprintf("%s cannot be completed by the current OpenAPI contract: %s", command, detail))
}
