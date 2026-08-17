package audit

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/akimisaka/aor/internal/artifact"
	"github.com/akimisaka/aor/pkg/contracts"
)

type fakePersistedOutput struct {
	record  artifact.Record
	content []byte
}

type fakePersistedOutputOpener struct {
	outputs map[string]fakePersistedOutput
	keys    []string
}

func (opener *fakePersistedOutputOpener) OpenByIdempotencyKey(_ context.Context, tenantID, projectID, key string) (artifact.Record, io.ReadCloser, error) {
	if tenantID != "tenant-1" || projectID != "project-1" {
		return artifact.Record{}, nil, artifact.ErrNotFound
	}
	opener.keys = append(opener.keys, key)
	output, ok := opener.outputs[key]
	if !ok {
		return artifact.Record{}, nil, artifact.ErrNotFound
	}
	return output.record, io.NopCloser(bytes.NewReader(output.content)), nil
}

func TestReadPersistedModuleTestOutputsUsesPublicationKeys(t *testing.T) {
	manifest := contracts.SubmissionManifest{ProjectID: "project-1", ModuleTaskID: "task-1", AttemptSeriesID: "series-1", Attempt: 2}
	input := DeterministicInput{Manifest: manifest}
	keys := map[string]string{}
	for _, kind := range []string{"result", "stdout", "stderr"} {
		artifactID := auditArtifactID(input, "module-tests", kind)
		keys[kind] = auditPublicationKey("audit-check-output", manifest.ModuleTaskID, artifactID)
	}
	opener := &fakePersistedOutputOpener{outputs: map[string]fakePersistedOutput{
		keys["result"]: {record: persistedOutputRecord("tenant-1", manifest.ProjectID, auditArtifactID(input, "module-tests", "result"), "result", []byte(`{"command":["/bin/sh","verify.sh"],"exitCode":7,"status":"FAIL"}`)), content: []byte(`{"command":["/bin/sh","verify.sh"],"exitCode":7,"status":"FAIL"}`)},
		keys["stdout"]: {record: persistedOutputRecord("tenant-1", manifest.ProjectID, auditArtifactID(input, "module-tests", "stdout"), "stdout", []byte{}), content: []byte{}},
		keys["stderr"]: {record: persistedOutputRecord("tenant-1", manifest.ProjectID, auditArtifactID(input, "module-tests", "stderr"), "stderr", []byte{}), content: []byte{}},
	}}

	outputs, err := ReadPersistedModuleTestOutputs(context.Background(), opener, "tenant-1", manifest.ProjectID, manifest.ModuleTaskID, manifest.AttemptSeriesID, manifest.Attempt)
	if err != nil {
		t.Fatal(err)
	}
	if len(outputs.Stdout) != 0 || len(outputs.Stderr) != 0 || string(outputs.Result) != `{"command":["/bin/sh","verify.sh"],"exitCode":7,"status":"FAIL"}` {
		t.Fatalf("persisted outputs = %#v", outputs)
	}
	resultURI, _ := artifact.URIFromDigest(digestBytes([]byte(`{"command":["/bin/sh","verify.sh"],"exitCode":7,"status":"FAIL"}`)))
	emptyURI, _ := artifact.URIFromDigest(digestBytes(nil))
	if outputs.StdoutRef != emptyURI || outputs.StderrRef != emptyURI || outputs.ResultRef != resultURI {
		t.Fatalf("persisted output refs = %#v", outputs)
	}
	if len(opener.keys) != 3 || opener.keys[0] != keys["result"] || opener.keys[1] != keys["stdout"] || opener.keys[2] != keys["stderr"] {
		t.Fatalf("publication keys = %#v", opener.keys)
	}
	if keys["stdout"] == keys["stderr"] {
		t.Fatal("empty stdout and stderr publication keys were conflated")
	}

	delete(opener.outputs, keys["stderr"])
	_, err = ReadPersistedModuleTestOutputs(context.Background(), opener, "tenant-1", manifest.ProjectID, manifest.ModuleTaskID, manifest.AttemptSeriesID, manifest.Attempt)
	if !errors.Is(err, artifact.ErrNotFound) {
		t.Fatalf("missing stderr error = %v", err)
	}
}

func persistedOutputRecord(tenantID, projectID, artifactID, kind string, content []byte) artifact.Record {
	digest := digestBytes(content)
	uri, _ := artifact.URIFromDigest(digest)
	contentType := "application/octet-stream"
	if kind == "stdout" || kind == "stderr" {
		contentType = "text/plain; charset=utf-8"
	}
	return artifact.Record{
		TenantID: tenantID, ProjectID: projectID, URI: uri, SHA256: digest, SizeBytes: int64(len(content)),
		ContentType: contentType, CreatedByPrincipal: "aor-audit-service",
		Metadata: map[string]any{"kind": "audit-check-output", "sourceArtifactId": artifactID, "taskId": "task-1", "retentionPolicy": "audit-evidence", "encrypted": true},
	}
}
