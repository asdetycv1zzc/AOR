package orchestrator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

const maximumGoalMessageBytes = 1 << 20

// GoalSpecProjection keeps immutable GoalSpec content and its explicit review
// status in the same tenant-scoped event-sourced aggregate.
type GoalSpecProjection struct {
	TenantID   string             `json:"tenantId"`
	ProjectID  string             `json:"projectId"`
	GoalSpecID string             `json:"goalSpecId"`
	RecordID   string             `json:"recordId"`
	Spec       contracts.GoalSpec `json:"spec"`
	Revision   int64              `json:"-"`
}

func prepareGoalCommand(request ProjectRequest, command state.ProjectCommand) (state.ProjectCommand, error) {
	var err error
	command, err = prepareProjectLifecycleCommand(request, command)
	if err != nil {
		return state.ProjectCommand{}, err
	}
	if command.GoalMessage != nil {
		message := *command.GoalMessage
		message.ID = stableID("msg", request.TenantID+"\x00"+request.ProjectID+"\x00"+request.PrincipalID+"\x00"+request.IdempotencyKey)
		message.TenantID = request.TenantID
		message.ProjectID = request.ProjectID
		message.CreatedBy = request.PrincipalID
		message.CreatedAt = time.Time{}
		digest := sha256.Sum256([]byte(message.Message))
		message.ContentSHA256 = "sha256:" + hex.EncodeToString(digest[:])
		message.ArtifactURI = "artifact://sha256/" + hex.EncodeToString(digest[:])
		switch command.Type {
		case state.ProjectCommandSubmitGoalMessage:
			if message.Kind == "" {
				message.Kind = state.GoalMessageUser
			}
			if message.Kind != state.GoalMessageUser {
				return state.ProjectCommand{}, invalidGoalCommand("goal message kind")
			}
		case state.ProjectCommandRejectGoal:
			if message.Kind == "" {
				message.Kind = state.GoalMessageRejection
			}
			if message.Kind != state.GoalMessageRejection {
				return state.ProjectCommand{}, invalidGoalCommand("goal rejection message kind")
			}
		case state.ProjectCommandRequestGoalChange:
			if message.Kind == "" {
				message.Kind = state.GoalMessageChangeRequest
			}
			if message.Kind != state.GoalMessageChangeRequest {
				return state.ProjectCommand{}, invalidGoalCommand("goal change message kind")
			}
		default:
			return state.ProjectCommand{}, invalidGoalCommand("unexpected goal message")
		}
		if message.Message == "" || len(message.Message) > maximumGoalMessageBytes || !utf8.ValidString(message.Message) || strings.ContainsRune(message.Message, '\x00') {
			return state.ProjectCommand{}, invalidGoalCommand("goal message content")
		}
		command.GoalMessage = &message
	} else if command.Type == state.ProjectCommandSubmitGoalMessage || command.Type == state.ProjectCommandRequestGoalChange {
		return state.ProjectCommand{}, invalidGoalCommand("goal message required")
	}
	if command.GoalSpec != nil {
		spec := cloneGoalSpec(*command.GoalSpec)
		if err := validateGoalSpecCommand(request.ProjectID, command.Goal, spec); err != nil {
			return state.ProjectCommand{}, err
		}
		command.GoalSpec = &spec
	}
	return command, nil
}

func goalDigestCommand(command state.ProjectCommand) state.ProjectCommand {
	digestCommand := command
	if command.Deletion != nil {
		deletion := *command.Deletion
		deletion.RequestedAt = time.Time{}
		deletion.StartedAt = cloneTimePointer(nil)
		deletion.CompletedAt = cloneTimePointer(nil)
		digestCommand.Deletion = &deletion
	}
	if command.LegalHold != nil {
		hold := *command.LegalHold
		hold.PlacedAt = time.Time{}
		digestCommand.LegalHold = &hold
	}
	if command.Approval != nil {
		approval := *command.Approval
		approval.IssuedAt = time.Time{}
		digestCommand.Approval = &approval
	}
	if command.GoalSpec != nil {
		spec := cloneGoalSpec(*command.GoalSpec)
		if spec.ApprovedBy != nil {
			actor := *spec.ApprovedBy
			actor.ApprovedAt = ""
			spec.ApprovedBy = &actor
		}
		digestCommand.GoalSpec = &spec
	}
	return digestCommand
}

func finalizeGoalCommand(command state.ProjectCommand) state.ProjectCommand {
	if command.Type == state.ProjectCommandRequestDeletion && command.Deletion != nil {
		deletion := *command.Deletion
		deletion.RequestedAt = command.At
		if deletion.EarliestExecutionAt.IsZero() {
			deletion.EarliestExecutionAt = command.At
		}
		command.Deletion = &deletion
	}
	if command.Type == state.ProjectCommandPlaceLegalHold && command.LegalHold != nil {
		hold := *command.LegalHold
		hold.PlacedAt = command.At
		command.LegalHold = &hold
	}
	if command.GoalMessage != nil {
		message := *command.GoalMessage
		message.CreatedAt = command.At
		command.GoalMessage = &message
	}
	return command
}

func prepareProjectLifecycleCommand(request ProjectRequest, command state.ProjectCommand) (state.ProjectCommand, error) {
	switch command.Type {
	case state.ProjectCommandRequestDeletion:
		if command.Deletion == nil {
			return state.ProjectCommand{}, invalidGoalCommand("deletion request required")
		}
		deletion := *command.Deletion
		deletion.ID = stableID("deletion", request.TenantID+"\x00"+request.ProjectID+"\x00"+request.PrincipalID+"\x00"+request.IdempotencyKey)
		deletion.RequestedBy = request.PrincipalID
		deletion.RequestedAt = time.Time{}
		deletion.Status = ""
		deletion.StartedAt = nil
		deletion.CompletedAt = nil
		deletion.ProofSHA256 = ""
		deletion.ProofArtifactURI = ""
		deletion.BackupExpiresAt = nil
		command.Deletion = &deletion
	case state.ProjectCommandPlaceLegalHold:
		if command.LegalHold == nil {
			return state.ProjectCommand{}, invalidGoalCommand("legal hold required")
		}
		hold := *command.LegalHold
		hold.ID = stableID("hold", request.TenantID+"\x00"+request.ProjectID+"\x00"+request.PrincipalID+"\x00"+request.IdempotencyKey)
		hold.PlacedBy = request.PrincipalID
		hold.PlacedAt = time.Time{}
		hold.ReleasedBy = ""
		hold.ReleasedAt = nil
		hold.ReleaseReason = ""
		command.LegalHold = &hold
	}
	return command, nil
}

func cloneTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := value.UTC()
	return &cloned
}

func (s *Service) goalRelatedTransitions(ctx context.Context, request ProjectRequest, current state.Project, command state.ProjectCommand, requestDigest string) ([]eventing.ProjectionUpdate, []eventing.DomainEvent, error) {
	updates := make([]eventing.ProjectionUpdate, 0, 3)
	events := make([]eventing.DomainEvent, 0, 3)
	appendTransition := func(update eventing.ProjectionUpdate, event eventing.DomainEvent) {
		updates = append(updates, update)
		events = append(events, event)
	}

	if command.GoalMessage != nil {
		content, err := json.Marshal(command.GoalMessage)
		if err != nil {
			return nil, nil, err
		}
		if _, found, err := s.store.Load(ctx, request.TenantID, "goal_message", command.GoalMessage.ID); err != nil {
			return nil, nil, err
		} else if found {
			return nil, nil, aorerrors.New(aorerrors.CodeConflict, "", map[string]any{"scope": "goal message"})
		}
		update := eventing.ProjectionUpdate{TenantID: request.TenantID, ProjectID: request.ProjectID, AggregateType: "goal_message", AggregateID: command.GoalMessage.ID, ExpectedVersion: 0, NextVersion: 1, State: content}
		event := newEvent(request.TenantID, request.ProjectID, "goal_message", command.GoalMessage.ID, "io.aor.goal.message-stored.v1", 1, command.At, content, requestDigest)
		appendTransition(update, event)
	}

	if command.Type == state.ProjectCommandProposeGoal || command.Type == state.ProjectCommandSupersedeGoal {
		if command.GoalSpec == nil || command.Goal == nil {
			return updates, events, nil
		}
		if current.Goal != nil && current.Goal.Version < command.Goal.Version {
			oldUpdate, oldEvent, found, err := s.goalSpecStatusTransition(ctx, request, *current.Goal, contracts.GoalSuperseded, nil, command.At, requestDigest)
			if err != nil {
				return nil, nil, err
			}
			if found {
				appendTransition(oldUpdate, oldEvent)
			}
		}
		projection := GoalSpecProjection{
			TenantID: request.TenantID, ProjectID: request.ProjectID, GoalSpecID: command.Goal.ID,
			RecordID: goalSpecRecordID(request.TenantID, request.ProjectID, command.Goal.ID, command.Goal.Version), Spec: cloneGoalSpec(*command.GoalSpec),
		}
		content, err := json.Marshal(projection)
		if err != nil {
			return nil, nil, err
		}
		aggregateID := goalSpecAggregateID(request.ProjectID, command.Goal.ID, command.Goal.Version)
		if _, found, err := s.store.Load(ctx, request.TenantID, "goal_spec", aggregateID); err != nil {
			return nil, nil, err
		} else if found {
			return nil, nil, aorerrors.New(aorerrors.CodeSpecSuperseded, "", nil)
		}
		update := eventing.ProjectionUpdate{TenantID: request.TenantID, ProjectID: request.ProjectID, AggregateType: "goal_spec", AggregateID: aggregateID, ExpectedVersion: 0, NextVersion: 1, State: content}
		event := newEvent(request.TenantID, request.ProjectID, "goal_spec", aggregateID, "io.aor.goal.spec-stored.v1", 1, command.At, content, requestDigest)
		appendTransition(update, event)
	}

	if command.Goal != nil {
		var status contracts.GoalStatus
		var approvedBy *contracts.ApprovalActor
		switch command.Type {
		case state.ProjectCommandApproveGoal:
			status = contracts.GoalApproved
			if command.Approval != nil {
				approvedBy = &contracts.ApprovalActor{ActorID: command.ActorID, ApprovedAt: command.Approval.IssuedAt.UTC().Format(time.RFC3339Nano)}
			}
		case state.ProjectCommandRejectGoal:
			status = contracts.GoalRejected
		case state.ProjectCommandRequestGoalChange:
			status = contracts.GoalSuperseded
		}
		if status != "" {
			update, event, found, err := s.goalSpecStatusTransition(ctx, request, *command.Goal, status, approvedBy, command.At, requestDigest)
			if err != nil {
				return nil, nil, err
			}
			if found {
				appendTransition(update, event)
			}
		}
	}
	return updates, events, nil
}

func (s *Service) goalSpecStatusTransition(ctx context.Context, request ProjectRequest, goal state.GoalRecord, status contracts.GoalStatus, approvedBy *contracts.ApprovalActor, at time.Time, requestDigest string) (eventing.ProjectionUpdate, eventing.DomainEvent, bool, error) {
	aggregateID := goalSpecAggregateID(request.ProjectID, goal.ID, goal.Version)
	stored, found, err := s.store.Load(ctx, request.TenantID, "goal_spec", aggregateID)
	if err != nil || !found {
		return eventing.ProjectionUpdate{}, eventing.DomainEvent{}, found, err
	}
	projection, err := decodeGoalSpecProjection(stored)
	if err != nil {
		return eventing.ProjectionUpdate{}, eventing.DomainEvent{}, false, err
	}
	if projection.GoalSpecID != goal.ID || projection.Spec.Content.Version != goal.Version || projection.Spec.ContentSHA256 != goal.SHA256 {
		return eventing.ProjectionUpdate{}, eventing.DomainEvent{}, false, aorerrors.New(aorerrors.CodeGoalHashMismatch, "", nil)
	}
	if status == contracts.GoalApproved && (projection.Spec.Status != contracts.GoalDraft || len(projection.Spec.Content.UnresolvedItems) != 0 || approvedBy == nil) {
		return eventing.ProjectionUpdate{}, eventing.DomainEvent{}, false, aorerrors.New(aorerrors.CodeGoalNotApproved, "", nil)
	}
	if status == contracts.GoalRejected && projection.Spec.Status != contracts.GoalDraft {
		return eventing.ProjectionUpdate{}, eventing.DomainEvent{}, false, aorerrors.New(aorerrors.CodeInvalidStateTransition, "", map[string]any{"scope": "goal spec rejection"})
	}
	if status == contracts.GoalSuperseded && (projection.Spec.Status == contracts.GoalSuperseded || projection.Spec.Status == contracts.GoalRejected) {
		return eventing.ProjectionUpdate{}, eventing.DomainEvent{}, false, nil
	}
	projection.Spec.Status = status
	projection.Spec.ApprovedBy = approvedBy
	content, err := json.Marshal(projection)
	if err != nil {
		return eventing.ProjectionUpdate{}, eventing.DomainEvent{}, false, err
	}
	eventType := "io.aor.goal.spec-" + strings.ToLower(string(status)) + ".v1"
	update := eventing.ProjectionUpdate{TenantID: request.TenantID, ProjectID: request.ProjectID, AggregateType: "goal_spec", AggregateID: aggregateID, ExpectedVersion: stored.Version, NextVersion: stored.Version + 1, State: content}
	event := newEvent(request.TenantID, request.ProjectID, "goal_spec", aggregateID, eventType, stored.Version+1, at, content, requestDigest)
	return update, event, true, nil
}

func (s *Service) GoalMessages(ctx context.Context, tenantID, projectID string) ([]state.GoalMessage, error) {
	projections, err := s.listGoalProjections(ctx, tenantID, projectID, "goal_message")
	if err != nil {
		return nil, err
	}
	messages := make([]state.GoalMessage, 0, len(projections))
	for _, projection := range projections {
		var message state.GoalMessage
		if err := json.Unmarshal(projection.State, &message); err != nil || message.TenantID != tenantID || message.ProjectID != projectID || message.ID != projection.AggregateID {
			return nil, aorerrors.New(aorerrors.CodeInternalError, "", map[string]any{"scope": "goal message projection"})
		}
		messages = append(messages, message)
	}
	sort.Slice(messages, func(left, right int) bool {
		if !messages[left].CreatedAt.Equal(messages[right].CreatedAt) {
			return messages[left].CreatedAt.Before(messages[right].CreatedAt)
		}
		return messages[left].ID < messages[right].ID
	})
	return messages, nil
}

func (s *Service) GoalSpecs(ctx context.Context, tenantID, projectID string) ([]GoalSpecProjection, error) {
	projections, err := s.listGoalProjections(ctx, tenantID, projectID, "goal_spec")
	if err != nil {
		return nil, err
	}
	goals := make([]GoalSpecProjection, 0, len(projections))
	versions := make(map[int]bool, len(projections))
	for _, stored := range projections {
		goal, decodeErr := decodeGoalSpecProjection(stored)
		if decodeErr != nil {
			return nil, decodeErr
		}
		if goal.TenantID != tenantID || goal.ProjectID != projectID || versions[goal.Spec.Content.Version] {
			return nil, aorerrors.New(aorerrors.CodeInternalError, "", map[string]any{"scope": "goal spec projection"})
		}
		versions[goal.Spec.Content.Version] = true
		goals = append(goals, goal)
	}
	sort.Slice(goals, func(left, right int) bool {
		return goals[left].Spec.Content.Version < goals[right].Spec.Content.Version
	})
	return goals, nil
}

func (s *Service) GoalSpec(ctx context.Context, tenantID, projectID string, version int) (GoalSpecProjection, bool, error) {
	if version < 1 {
		return GoalSpecProjection{}, false, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "goal version"})
	}
	goals, err := s.GoalSpecs(ctx, tenantID, projectID)
	if err != nil {
		return GoalSpecProjection{}, false, err
	}
	for _, goal := range goals {
		if goal.Spec.Content.Version == version {
			return goal, true, nil
		}
	}
	return GoalSpecProjection{}, false, nil
}

func (s *Service) listGoalProjections(ctx context.Context, tenantID, projectID, aggregateType string) ([]eventing.Projection, error) {
	if tenantID == "" || projectID == "" {
		return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "goal query"})
	}
	lister, ok := s.store.(eventing.ProjectionList)
	if !ok {
		return nil, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "goal projection list"})
	}
	return lister.ListProjections(ctx, tenantID, projectID, aggregateType)
}

func decodeGoalSpecProjection(stored eventing.Projection) (GoalSpecProjection, error) {
	var projection GoalSpecProjection
	if err := json.Unmarshal(stored.State, &projection); err != nil {
		return GoalSpecProjection{}, fmt.Errorf("decode goal spec projection: %w", err)
	}
	if projection.TenantID != stored.TenantID || projection.ProjectID != stored.ProjectID || projection.GoalSpecID == "" || projection.RecordID == "" || projection.Spec.Content.Version < 1 || projection.Spec.Content.ProjectID != stored.ProjectID {
		return GoalSpecProjection{}, aorerrors.New(aorerrors.CodeInternalError, "", map[string]any{"scope": "goal spec projection"})
	}
	if err := validateGoalSpecCommand(stored.ProjectID, &state.GoalRecord{ID: projection.GoalSpecID, Version: projection.Spec.Content.Version, SHA256: projection.Spec.ContentSHA256}, projection.Spec); err != nil {
		return GoalSpecProjection{}, err
	}
	projection.Revision = stored.Version
	return projection, nil
}

func validateGoalSpecCommand(projectID string, goal *state.GoalRecord, spec contracts.GoalSpec) error {
	if goal == nil || goal.ID == "" || spec.Content.ProjectID != projectID || spec.Content.Version != goal.Version || spec.ContentSHA256 != goal.SHA256 || spec.Validate() != nil {
		return invalidGoalCommand("goal spec binding")
	}
	content, err := json.Marshal(spec.Content)
	if err != nil {
		return err
	}
	digest, err := canonicaljson.Digest(content)
	if err != nil || digest != spec.ContentSHA256 {
		return aorerrors.New(aorerrors.CodeArtifactHashMismatch, "", map[string]any{"scope": "goal spec content"})
	}
	return nil
}

func cloneGoalSpec(spec contracts.GoalSpec) contracts.GoalSpec {
	encoded, err := json.Marshal(spec)
	if err != nil {
		return spec
	}
	var clone contracts.GoalSpec
	if json.Unmarshal(encoded, &clone) != nil {
		return spec
	}
	return clone
}

func goalSpecAggregateID(projectID, goalSpecID string, version int) string {
	return stableID("goal", projectID+"\x00"+goalSpecID+"\x00"+fmt.Sprint(version))
}

func goalSpecRecordID(tenantID, projectID, goalSpecID string, version int) string {
	value := sha256.Sum256([]byte(tenantID + "\x00" + projectID + "\x00" + goalSpecID + "\x00" + fmt.Sprint(version)))
	value[6] = value[6]&0x0f | 0x50
	value[8] = value[8]&0x3f | 0x80
	hexValue := hex.EncodeToString(value[:16])
	return hexValue[0:8] + "-" + hexValue[8:12] + "-" + hexValue[12:16] + "-" + hexValue[16:20] + "-" + hexValue[20:32]
}

func invalidGoalCommand(scope string) error {
	return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": scope})
}
