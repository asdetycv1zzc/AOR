package asyncapi

import (
	"testing"
)

func TestV1ConsumerIgnoresAdditiveEventAndDataFields(t *testing.T) {
	payload := []byte(`{"specversion":"1.0","id":"event_1","source":"urn:aor:service:orchestrator","type":"io.aor.project.created.v1","subject":"projects/prj_1","time":"2030-01-01T00:00:00Z","datacontenttype":"application/json","dataschema":"https://schemas.aor.local/events/project-created.v1.schema.json","traceparent":"00-00000000000000000000000000000001-0000000000000001-01","aorprojectid":"prj_1","aortaskidreason":"NOT_CREATED","aoragentrunidreason":"NOT_CREATED","futureEnvelopeField":{"enabled":true},"data":{"projectId":"prj_1","aggregateVersion":1,"futureOptionalField":"ignored"}}`)
	decoded, err := DecodeProjectEventV1(payload)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.ProjectID != "prj_1" || decoded.AggregateVersion != 1 || decoded.Type != "io.aor.project.created.v1" {
		t.Fatalf("decoded = %#v", decoded)
	}
}
