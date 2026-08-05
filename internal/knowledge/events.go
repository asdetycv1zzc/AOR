package knowledge

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/observability"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
	"github.com/google/uuid"
)

const (
	knowledgeUpdatedEventType = "io.aor.knowledge.updated.v1"
	knowledgeAggregateType    = "knowledge"
	knowledgeUpdatedKeyID     = "aor-knowledge-updated-hs256-v1"
)

// KnowledgeUpdatedEvent is the signed record emitted after an immutable
// snapshot has been committed and its effective search index has been built.
type KnowledgeUpdatedEvent struct {
	KnowledgeUpdateVersion int                  `json:"knowledgeUpdateVersion"`
	TenantID               string               `json:"tenantId"`
	ProjectID              string               `json:"projectId"`
	AggregateVersion       int64                `json:"aggregateVersion"`
	PreviousRevision       string               `json:"previousRevision,omitempty"`
	Revision               string               `json:"revision"`
	ProposalDigest         string               `json:"proposalDigest"`
	IndexedRevision        string               `json:"indexedRevision"`
	IndexedDocuments       int                  `json:"indexedDocuments"`
	IndexBuiltAt           time.Time            `json:"indexBuiltAt"`
	CuratorPrincipalID     string               `json:"curatorPrincipalId"`
	TaskID                 string               `json:"taskId"`
	ApprovalID             string               `json:"approvalId"`
	LeaseID                string               `json:"leaseId"`
	OccurredAt             time.Time            `json:"occurredAt"`
	Signature              *contracts.Signature `json:"signature,omitempty"`
}

type KnowledgeUpdatedSigner interface {
	Sign(context.Context, []byte) (*contracts.Signature, error)
	Verify(context.Context, []byte, *contracts.Signature) bool
}

type KnowledgeUpdatedPublisher interface {
	Publish(context.Context, Access, string, UpdateResult, IndexSnapshot) error
}

type HMACKnowledgeUpdatedSigner struct {
	key []byte
}

func NewHMACKnowledgeUpdatedSigner(key []byte) (*HMACKnowledgeUpdatedSigner, error) {
	if len(key) < 32 {
		return nil, invalid("knowledge event signing key")
	}
	return &HMACKnowledgeUpdatedSigner{key: append([]byte(nil), key...)}, nil
}

func (signer *HMACKnowledgeUpdatedSigner) Sign(ctx context.Context, payload []byte) (*contracts.Signature, error) {
	if signer == nil || len(signer.key) < 32 || len(payload) == 0 {
		return nil, invalid("knowledge event signature")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	protected := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","kid":"` + knowledgeUpdatedKeyID + `","typ":"JOSE"}`))
	payload64 := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, signer.key)
	_, _ = mac.Write([]byte(protected + "." + payload64))
	jws := protected + ".." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return &contracts.Signature{Type: "detached-jws", KID: knowledgeUpdatedKeyID, JWS: jws}, nil
}

func (signer *HMACKnowledgeUpdatedSigner) Verify(ctx context.Context, payload []byte, signature *contracts.Signature) bool {
	if signer == nil || signature == nil || signature.Type != "detached-jws" || signature.KID != knowledgeUpdatedKeyID {
		return false
	}
	expected, err := signer.Sign(ctx, payload)
	return err == nil && hmac.Equal([]byte(expected.JWS), []byte(signature.JWS))
}

type EventKnowledgeUpdatedPublisher struct {
	store  eventing.Store
	signer KnowledgeUpdatedSigner
	clock  func() time.Time
}

func NewEventKnowledgeUpdatedPublisher(store eventing.Store, signer KnowledgeUpdatedSigner, clock func() time.Time) (*EventKnowledgeUpdatedPublisher, error) {
	if store == nil || signer == nil {
		return nil, invalid("knowledge event publisher")
	}
	if clock == nil {
		clock = time.Now
	}
	return &EventKnowledgeUpdatedPublisher{store: store, signer: signer, clock: clock}, nil
}

func (publisher *EventKnowledgeUpdatedPublisher) Publish(ctx context.Context, access Access, previousRevision string, result UpdateResult, index IndexSnapshot) error {
	if publisher == nil || publisher.store == nil || publisher.signer == nil {
		return aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "knowledge event publisher"})
	}
	if ctx == nil {
		return invalid("knowledge event context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if access.Approval == nil || access.Lease == nil || access.Principal.ID == "" || access.TaskID == "" ||
		result.Manifest.TenantID != access.TenantID || result.Manifest.ProjectID != access.ProjectID ||
		result.Manifest.Revision == "" || result.Digest == "" || index.TenantID != access.TenantID ||
		index.ProjectID != access.ProjectID || index.Revision != result.Manifest.Revision || index.BuiltAt.IsZero() || index.Documents < 0 {
		return invalid("knowledge event")
	}

	projection, found, err := publisher.store.Load(ctx, access.TenantID, knowledgeAggregateType, access.ProjectID)
	if err != nil {
		return err
	}
	previousVersion := int64(0)
	if found {
		prior, decodeErr := publisher.decodeProjection(ctx, projection, access.TenantID, access.ProjectID)
		if decodeErr != nil {
			return decodeErr
		}
		if prior.Revision == result.Manifest.Revision {
			if prior.ProposalDigest != result.Digest || prior.IndexedRevision != index.Revision {
				return aorerrors.New(aorerrors.CodeArtifactHashMismatch, "", map[string]any{"scope": "knowledge event replay"})
			}
			return nil
		}
		if prior.Revision != previousRevision {
			return aorerrors.New(aorerrors.CodeStateVersionConflict, "", map[string]any{"scope": "knowledge event revision"})
		}
		previousVersion = projection.Version
	}

	event := KnowledgeUpdatedEvent{
		KnowledgeUpdateVersion: 1,
		TenantID:               access.TenantID,
		ProjectID:              access.ProjectID,
		AggregateVersion:       previousVersion + 1,
		PreviousRevision:       previousRevision,
		Revision:               result.Manifest.Revision,
		ProposalDigest:         result.Digest,
		IndexedRevision:        index.Revision,
		IndexedDocuments:       index.Documents,
		IndexBuiltAt:           index.BuiltAt,
		CuratorPrincipalID:     access.Principal.ID,
		TaskID:                 access.TaskID,
		ApprovalID:             access.Approval.ID,
		LeaseID:                access.Lease.ID,
		OccurredAt:             publisher.clock().UTC(),
	}
	unsigned, err := canonicalKnowledgeUpdatedEvent(event)
	if err != nil {
		return err
	}
	event.Signature, err = publisher.signer.Sign(ctx, unsigned)
	if err != nil {
		return err
	}
	if err := validateKnowledgeUpdatedEvent(event); err != nil {
		return err
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	payloadDigest, err := canonicaljson.Digest(payload)
	if err != nil {
		return err
	}
	requestDigest, err := knowledgeUpdatedRequestDigest(event)
	if err != nil {
		return err
	}
	eventID, err := uuid.NewV7()
	if err != nil {
		return err
	}
	traceparent, tracestate, err := knowledgeEventTrace(ctx)
	if err != nil {
		return err
	}
	domainEvent := eventing.DomainEvent{
		EventID: eventID.String(), TenantID: access.TenantID, ProjectID: access.ProjectID,
		AggregateType: knowledgeAggregateType, AggregateID: access.ProjectID, AggregateVersion: event.AggregateVersion,
		Type: knowledgeUpdatedEventType, Payload: payload, PayloadSHA256: payloadDigest, OccurredAt: event.OccurredAt,
		CorrelationID: "corr_" + result.Digest[len("sha256:"):len("sha256:")+32], CausationID: access.Approval.ID,
		Traceparent: traceparent, Tracestate: tracestate, TaskID: access.TaskID, AgentRunReason: "UNAVAILABLE",
	}
	transaction, err := publisher.store.Execute(ctx, eventing.TransactionRequest{
		TenantID: access.TenantID, PrincipalID: access.Principal.ID,
		IdempotencyKey: "knowledge-updated:" + result.Manifest.Revision, RequestSHA256: requestDigest,
		Updates: []eventing.ProjectionUpdate{{
			TenantID: access.TenantID, ProjectID: access.ProjectID, AggregateType: knowledgeAggregateType,
			AggregateID: access.ProjectID, ExpectedVersion: previousVersion, NextVersion: previousVersion + 1, State: payload,
		}},
		Events: []eventing.DomainEvent{domainEvent}, Result: payload, ResultSHA256: payloadDigest,
	})
	if err != nil {
		recovered, recoveredFound, loadErr := publisher.store.Load(ctx, access.TenantID, knowledgeAggregateType, access.ProjectID)
		if loadErr == nil && recoveredFound {
			prior, decodeErr := publisher.decodeProjection(ctx, recovered, access.TenantID, access.ProjectID)
			if decodeErr == nil && prior.Revision == result.Manifest.Revision && prior.ProposalDigest == result.Digest {
				return nil
			}
		}
		return err
	}
	var committed KnowledgeUpdatedEvent
	if err := json.Unmarshal(transaction.Result, &committed); err != nil {
		return aorerrors.Wrap(aorerrors.CodeArtifactHashMismatch, "", err, map[string]any{"scope": "knowledge event result"})
	}
	if err := publisher.verifyEvent(ctx, committed, access.TenantID, access.ProjectID, previousVersion+1); err != nil {
		return err
	}
	if committed.Revision != result.Manifest.Revision || committed.ProposalDigest != result.Digest {
		return aorerrors.New(aorerrors.CodeArtifactHashMismatch, "", map[string]any{"scope": "knowledge event result"})
	}
	return nil
}

func (publisher *EventKnowledgeUpdatedPublisher) decodeProjection(ctx context.Context, projection eventing.Projection, tenantID, projectID string) (KnowledgeUpdatedEvent, error) {
	if projection.TenantID != tenantID || projection.ProjectID != projectID || projection.AggregateType != knowledgeAggregateType || projection.AggregateID != projectID {
		return KnowledgeUpdatedEvent{}, aorerrors.New(aorerrors.CodeArtifactHashMismatch, "", map[string]any{"scope": "knowledge event projection"})
	}
	var event KnowledgeUpdatedEvent
	if err := json.Unmarshal(projection.State, &event); err != nil {
		return KnowledgeUpdatedEvent{}, aorerrors.Wrap(aorerrors.CodeArtifactHashMismatch, "", err, map[string]any{"scope": "knowledge event projection"})
	}
	if err := publisher.verifyEvent(ctx, event, tenantID, projectID, projection.Version); err != nil {
		return KnowledgeUpdatedEvent{}, err
	}
	return event, nil
}

func (publisher *EventKnowledgeUpdatedPublisher) verifyEvent(ctx context.Context, event KnowledgeUpdatedEvent, tenantID, projectID string, version int64) error {
	if err := validateKnowledgeUpdatedEvent(event); err != nil || event.TenantID != tenantID || event.ProjectID != projectID || event.AggregateVersion != version {
		return aorerrors.New(aorerrors.CodeArtifactHashMismatch, "", map[string]any{"scope": "knowledge event integrity"})
	}
	unsigned, err := canonicalKnowledgeUpdatedEvent(event)
	if err != nil || !publisher.signer.Verify(ctx, unsigned, event.Signature) {
		return aorerrors.New(aorerrors.CodeArtifactHashMismatch, "", map[string]any{"scope": "knowledge event signature"})
	}
	return nil
}

func canonicalKnowledgeUpdatedEvent(event KnowledgeUpdatedEvent) ([]byte, error) {
	event.Signature = nil
	encoded, err := json.Marshal(event)
	if err != nil {
		return nil, err
	}
	return canonicaljson.Canonicalize(encoded)
}

func knowledgeUpdatedRequestDigest(event KnowledgeUpdatedEvent) (string, error) {
	request := struct {
		TenantID         string `json:"tenantId"`
		ProjectID        string `json:"projectId"`
		PreviousRevision string `json:"previousRevision,omitempty"`
		Revision         string `json:"revision"`
		ProposalDigest   string `json:"proposalDigest"`
	}{event.TenantID, event.ProjectID, event.PreviousRevision, event.Revision, event.ProposalDigest}
	encoded, err := json.Marshal(request)
	if err != nil {
		return "", err
	}
	return canonicaljson.Digest(encoded)
}

func validateKnowledgeUpdatedEvent(event KnowledgeUpdatedEvent) error {
	if event.KnowledgeUpdateVersion != 1 || event.TenantID == "" || event.ProjectID == "" || event.AggregateVersion < 1 ||
		(event.PreviousRevision != "" && !revisionPattern.MatchString(event.PreviousRevision)) ||
		!revisionPattern.MatchString(event.Revision) || !revisionPattern.MatchString(event.ProposalDigest) ||
		event.IndexedRevision != event.Revision || event.IndexedDocuments < 0 || event.IndexBuiltAt.IsZero() || event.CuratorPrincipalID == "" ||
		event.TaskID == "" || event.ApprovalID == "" || event.LeaseID == "" || event.OccurredAt.IsZero() ||
		event.Signature == nil || event.Signature.Type != "detached-jws" || event.Signature.KID != knowledgeUpdatedKeyID || len(event.Signature.JWS) < 16 {
		return invalid("knowledge updated event")
	}
	return nil
}

func knowledgeEventTrace(ctx context.Context) (string, string, error) {
	trace, found := observability.TraceFromContext(ctx)
	if !found {
		var err error
		trace, err = observability.NewRootTraceContext(false)
		if err != nil {
			return "", "", err
		}
	}
	traceparent, err := trace.TraceParent()
	return traceparent, trace.TraceState, err
}

var _ KnowledgeUpdatedSigner = (*HMACKnowledgeUpdatedSigner)(nil)
var _ KnowledgeUpdatedPublisher = (*EventKnowledgeUpdatedPublisher)(nil)
