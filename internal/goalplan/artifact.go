package goalplan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/idempotency"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
	"github.com/google/uuid"
)

type ArtifactKind string

const (
	ArtifactUserMessage            ArtifactKind = "USER_MESSAGE"
	ArtifactGoalDraft              ArtifactKind = "GOAL_DRAFT"
	ArtifactGoalChallenge          ArtifactKind = "GOAL_CHALLENGE"
	ArtifactGoalApproved           ArtifactKind = "GOAL_APPROVED"
	ArtifactPlanSpec               ArtifactKind = "PLAN_SPEC"
	ArtifactModuleSpec             ArtifactKind = "MODULE_SPEC"
	ArtifactPlanAnalysis           ArtifactKind = "PLAN_ANALYSIS"
	ArtifactKnowledgeUpdateRequest ArtifactKind = "KNOWLEDGE_UPDATE_REQUEST"
	ArtifactKnowledgeUpdateDraft   ArtifactKind = "KNOWLEDGE_UPDATE_DRAFT"
	MaximumArtifactBytes                        = 4 << 20
)

var ErrArtifactConflict = errors.New("immutable artifact conflict")

type SpecArtifact struct {
	TenantID       string       `json:"tenantId"`
	ProjectID      string       `json:"projectId"`
	Kind           ArtifactKind `json:"kind"`
	SpecID         string       `json:"specId"`
	Version        int          `json:"version"`
	ContentSHA256  string       `json:"contentSha256"`
	ArtifactSHA256 string       `json:"artifactSha256"`
	URI            string       `json:"uri"`
	MediaType      string       `json:"mediaType"`
	Content        []byte       `json:"content"`
	CreatedAt      time.Time    `json:"createdAt"`
	CreatedBy      string       `json:"createdBy"`
	SourceRunID    string       `json:"sourceRunId,omitempty"`
}

type ArtifactStore interface {
	Put(ctx context.Context, artifact SpecArtifact) (SpecArtifact, error)
	Get(ctx context.Context, tenantID, projectID string, kind ArtifactKind, specID string, version int) (SpecArtifact, bool, error)
}

type EventArtifactStore struct {
	store eventing.Store
	clock func() time.Time
}

func NewEventArtifactStore(store eventing.Store, clock func() time.Time) (*EventArtifactStore, error) {
	if store == nil {
		return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "artifact store"})
	}
	if clock == nil {
		clock = time.Now
	}
	return &EventArtifactStore{store: store, clock: clock}, nil
}

func (s *EventArtifactStore) Put(ctx context.Context, artifact SpecArtifact) (SpecArtifact, error) {
	artifact = cloneArtifact(artifact)
	artifact.CreatedAt = s.clock().UTC()
	if err := prepareArtifact(&artifact); err != nil {
		return SpecArtifact{}, err
	}
	aggregateID := artifactAggregateID(artifact.ProjectID, artifact.Kind, artifact.SpecID, artifact.Version)
	if current, found, err := s.Get(ctx, artifact.TenantID, artifact.ProjectID, artifact.Kind, artifact.SpecID, artifact.Version); err != nil {
		return SpecArtifact{}, err
	} else if found {
		if sameArtifact(current, artifact) {
			return current, nil
		}
		return SpecArtifact{}, ErrArtifactConflict
	}
	result, err := json.Marshal(artifact)
	if err != nil {
		return SpecArtifact{}, err
	}
	requestDigest, err := idempotency.RequestDigest(result)
	if err != nil {
		return SpecArtifact{}, err
	}
	payload, err := json.Marshal(struct {
		TenantID       string       `json:"tenantId"`
		ProjectID      string       `json:"projectId"`
		Kind           ArtifactKind `json:"kind"`
		SpecID         string       `json:"specId"`
		Version        int          `json:"version"`
		ContentSHA256  string       `json:"contentSha256"`
		ArtifactSHA256 string       `json:"artifactSha256"`
		URI            string       `json:"uri"`
	}{artifact.TenantID, artifact.ProjectID, artifact.Kind, artifact.SpecID, artifact.Version, artifact.ContentSHA256, artifact.ArtifactSHA256, artifact.URI})
	if err != nil {
		return SpecArtifact{}, err
	}
	eventID, err := uuid.NewV7()
	if err != nil {
		return SpecArtifact{}, err
	}
	event := eventing.DomainEvent{
		EventID: eventID.String(), TenantID: artifact.TenantID, ProjectID: artifact.ProjectID, AggregateType: "spec_artifact", AggregateID: aggregateID,
		AggregateVersion: 1, Type: "io.aor.artifact.spec-stored.v1", Payload: payload, PayloadSHA256: mustArtifactDigest(payload),
		OccurredAt: artifact.CreatedAt, CorrelationID: "corr_" + artifact.ArtifactSHA256[len("sha256:"):len("sha256:")+32],
	}
	transaction, err := s.store.Execute(ctx, eventing.TransactionRequest{
		TenantID: artifact.TenantID, PrincipalID: artifact.CreatedBy, IdempotencyKey: "store:" + aggregateID + ":" + artifact.ArtifactSHA256,
		RequestSHA256: requestDigest,
		Updates:       []eventing.ProjectionUpdate{{TenantID: artifact.TenantID, ProjectID: artifact.ProjectID, AggregateType: "spec_artifact", AggregateID: aggregateID, ExpectedVersion: 0, NextVersion: 1, State: result}},
		Events:        []eventing.DomainEvent{event}, Result: result, ResultSHA256: mustArtifactDigest(result),
	})
	if err != nil {
		return SpecArtifact{}, err
	}
	var stored SpecArtifact
	if err := json.Unmarshal(transaction.Result, &stored); err != nil {
		return SpecArtifact{}, err
	}
	return cloneArtifact(stored), nil
}

func (s *EventArtifactStore) Get(ctx context.Context, tenantID, projectID string, kind ArtifactKind, specID string, version int) (SpecArtifact, bool, error) {
	if tenantID == "" || projectID == "" || !kind.Valid() || specID == "" || version < 1 {
		return SpecArtifact{}, false, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "artifact lookup"})
	}
	projection, found, err := s.store.Load(ctx, tenantID, "spec_artifact", artifactAggregateID(projectID, kind, specID, version))
	if err != nil || !found {
		return SpecArtifact{}, found, err
	}
	var artifact SpecArtifact
	if err := json.Unmarshal(projection.State, &artifact); err != nil {
		return SpecArtifact{}, false, fmt.Errorf("decode spec artifact: %w", err)
	}
	if artifact.TenantID != tenantID || artifact.ProjectID != projectID || artifact.Kind != kind || artifact.SpecID != specID || artifact.Version != version {
		return SpecArtifact{}, false, aorerrors.New(aorerrors.CodeForbidden, "", nil)
	}
	if err := verifyArtifact(artifact); err != nil {
		return SpecArtifact{}, false, err
	}
	return cloneArtifact(artifact), true, nil
}

func (kind ArtifactKind) Valid() bool {
	switch kind {
	case ArtifactUserMessage, ArtifactGoalDraft, ArtifactGoalChallenge, ArtifactGoalApproved, ArtifactPlanSpec, ArtifactModuleSpec, ArtifactPlanAnalysis, ArtifactKnowledgeUpdateRequest, ArtifactKnowledgeUpdateDraft:
		return true
	default:
		return false
	}
}

func prepareArtifact(artifact *SpecArtifact) error {
	if artifact.TenantID == "" || artifact.ProjectID == "" || !artifact.Kind.Valid() || artifact.SpecID == "" || artifact.Version < 1 || artifact.CreatedBy == "" || len(artifact.Content) == 0 || len(artifact.Content) > MaximumArtifactBytes || artifact.CreatedAt.IsZero() {
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "spec artifact"})
	}
	digest, err := artifactDigest(artifact.Content)
	if err != nil {
		return err
	}
	if artifact.ArtifactSHA256 != "" && artifact.ArtifactSHA256 != digest {
		return aorerrors.New(aorerrors.CodeArtifactHashMismatch, "", nil)
	}
	artifact.ArtifactSHA256 = digest
	if artifact.ContentSHA256 == "" {
		artifact.ContentSHA256 = digest
	}
	if (contracts.SpecRef{Version: artifact.Version, SHA256: artifact.ContentSHA256}).Validate() != nil {
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "artifact content digest"})
	}
	if artifact.MediaType == "" {
		if json.Valid(artifact.Content) {
			artifact.MediaType = "application/json"
		} else {
			artifact.MediaType = "text/plain; charset=utf-8"
		}
	}
	artifact.URI = "artifact://sha256/" + digest[len("sha256:"):]
	return nil
}

func verifyArtifact(artifact SpecArtifact) error {
	digest, err := artifactDigest(artifact.Content)
	if err != nil || digest != artifact.ArtifactSHA256 || artifact.URI != "artifact://sha256/"+digest[len("sha256:"):] {
		return aorerrors.New(aorerrors.CodeArtifactHashMismatch, "", nil)
	}
	return nil
}

func artifactDigest(content []byte) (string, error) {
	if json.Valid(content) {
		return canonicaljson.Digest(content)
	}
	digest := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func artifactAggregateID(projectID string, kind ArtifactKind, specID string, version int) string {
	digest := sha256.Sum256([]byte(projectID + "\x00" + string(kind) + "\x00" + specID + "\x00" + fmt.Sprint(version)))
	return hex.EncodeToString(digest[:])
}

func sameArtifact(left, right SpecArtifact) bool {
	return left.TenantID == right.TenantID && left.ProjectID == right.ProjectID && left.Kind == right.Kind && left.SpecID == right.SpecID && left.Version == right.Version && left.ContentSHA256 == right.ContentSHA256 && left.ArtifactSHA256 == right.ArtifactSHA256 && left.CreatedBy == right.CreatedBy && left.SourceRunID == right.SourceRunID
}

func cloneArtifact(value SpecArtifact) SpecArtifact {
	value.Content = append([]byte(nil), value.Content...)
	return value
}

func mustArtifactDigest(value []byte) string {
	digest, err := canonicaljson.Digest(value)
	if err != nil {
		panic(err)
	}
	return digest
}
