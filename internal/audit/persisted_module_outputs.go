package audit

import (
	"context"
	"io"

	"github.com/akimisaka/aor/internal/artifact"
	"github.com/akimisaka/aor/pkg/contracts"
)

type PersistedOutputOpener interface {
	OpenByIdempotencyKey(context.Context, string, string, string) (artifact.Record, io.ReadCloser, error)
}

type PersistedModuleTestOutputs struct {
	Stdout    []byte
	Stderr    []byte
	Result    []byte
	StdoutRef string
	StderrRef string
	ResultRef string
}

// ReadPersistedModuleTestOutputs resolves outputs by their durable publication
// keys. Content-addressed artifact metadata cannot distinguish duplicate empty
// stdout and stderr objects.
func ReadPersistedModuleTestOutputs(ctx context.Context, opener PersistedOutputOpener, tenantID, projectID, taskID, attemptSeriesID string, attempt int) (PersistedModuleTestOutputs, error) {
	if ctx == nil || ctx.Err() != nil || opener == nil || tenantID == "" || projectID == "" || taskID == "" || attemptSeriesID == "" || attempt < 1 || attempt > 3 {
		return PersistedModuleTestOutputs{}, ErrInvalidInput
	}
	result, resultRef, err := readPersistedCheckOutput(ctx, opener, tenantID, projectID, taskID, attemptSeriesID, attempt, "module-tests", "result")
	if err != nil {
		return PersistedModuleTestOutputs{}, err
	}
	stdout, stdoutRef, err := readPersistedCheckOutput(ctx, opener, tenantID, projectID, taskID, attemptSeriesID, attempt, "module-tests", "stdout")
	if err != nil {
		return PersistedModuleTestOutputs{}, err
	}
	stderr, stderrRef, err := readPersistedCheckOutput(ctx, opener, tenantID, projectID, taskID, attemptSeriesID, attempt, "module-tests", "stderr")
	if err != nil {
		return PersistedModuleTestOutputs{}, err
	}
	return PersistedModuleTestOutputs{
		Stdout: stdout, Stderr: stderr, Result: result,
		StdoutRef: stdoutRef, StderrRef: stderrRef, ResultRef: resultRef,
	}, nil
}

func readPersistedCheckOutput(ctx context.Context, opener PersistedOutputOpener, tenantID, projectID, taskID, attemptSeriesID string, attempt int, checkID, kind string) ([]byte, string, error) {
	manifest := contracts.SubmissionManifest{ProjectID: projectID, ModuleTaskID: taskID, AttemptSeriesID: attemptSeriesID, Attempt: attempt}
	artifactID := auditArtifactID(DeterministicInput{Manifest: manifest}, checkID, kind)
	key := auditPublicationKey("audit-check-output", taskID, artifactID)
	record, reader, err := opener.OpenByIdempotencyKey(ctx, tenantID, projectID, key)
	if err != nil {
		return nil, "", err
	}
	if reader == nil {
		return nil, "", artifact.ErrIntegrity
	}
	content, readErr := io.ReadAll(io.LimitReader(reader, int64(moduleTestOutputLimit)+1))
	closeErr := reader.Close()
	if readErr != nil {
		return nil, "", readErr
	}
	if len(content) > moduleTestOutputLimit {
		return nil, "", artifact.ErrIntegrity
	}
	if closeErr != nil {
		return nil, "", closeErr
	}
	expectedDigest := digestBytes(content)
	expectedURI, uriErr := artifact.URIFromDigest(expectedDigest)
	if uriErr != nil || record.TenantID != tenantID || record.ProjectID != projectID || record.URI != expectedURI || record.SHA256 != expectedDigest || record.SizeBytes != int64(len(content)) || record.CreatedByPrincipal != "aor-audit-service" {
		return nil, "", artifact.ErrIntegrity
	}
	expectedContentType := "application/octet-stream"
	if kind == "stdout" || kind == "stderr" {
		expectedContentType = "text/plain; charset=utf-8"
	}
	// Publication keys bind the logical task/check output. Artifact records are
	// content-addressed, so duplicate output bytes intentionally reuse the first
	// record and its sourceArtifactId/taskId metadata.
	if record.ContentType != expectedContentType || record.Metadata == nil || record.Metadata["kind"] != "audit-check-output" || record.Metadata["retentionPolicy"] != "audit-evidence" {
		return nil, "", artifact.ErrIntegrity
	}
	encrypted, ok := record.Metadata["encrypted"].(bool)
	if !ok || !encrypted {
		return nil, "", artifact.ErrIntegrity
	}
	return content, record.URI, nil
}
