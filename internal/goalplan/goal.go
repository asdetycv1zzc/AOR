package goalplan

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/internal/orchestrator"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
)

type Negotiator struct {
	artifacts ArtifactStore
	invoker   AgentInvoker
	projects  ProjectCommander
	clock     func() time.Time
}

func NewNegotiator(artifacts ArtifactStore, invoker AgentInvoker, projects ProjectCommander, clock func() time.Time) (*Negotiator, error) {
	if artifacts == nil || invoker == nil || projects == nil {
		return nil, ErrInvalidRequest
	}
	if clock == nil {
		clock = time.Now
	}
	return &Negotiator{artifacts: artifacts, invoker: invoker, projects: projects, clock: clock}, nil
}

func (n *Negotiator) Negotiate(ctx context.Context, request NegotiationRequest) (NegotiationResult, error) {
	baseVersion := 1
	if request.PreviousRef != nil {
		baseVersion = request.PreviousRef.Version + 1
	}
	finalVersion := baseVersion
	if request.GoalAgentCount == 2 {
		finalVersion++
	}
	_, previous, previousApproved, _, err := n.validateNegotiation(ctx, request, finalVersion)
	if err != nil {
		return NegotiationResult{}, err
	}
	message, err := n.artifacts.Put(ctx, SpecArtifact{
		TenantID: request.TenantID, ProjectID: request.ProjectID, Kind: ArtifactUserMessage, SpecID: request.MessageID,
		Version: 1, Content: append([]byte(nil), request.UserInput...), CreatedBy: request.UserPrincipalID,
	})
	if err != nil {
		return NegotiationResult{}, err
	}
	if existing, found, lookupErr := n.artifacts.Get(ctx, request.TenantID, request.ProjectID, ArtifactGoalDraft, request.GoalSpecID, finalVersion); lookupErr != nil {
		return NegotiationResult{}, lookupErr
	} else if found {
		goal, decodeErr := decodeGoalArtifact(existing)
		if decodeErr != nil {
			return NegotiationResult{}, decodeErr
		}
		var challenge *ChallengeReport
		var challengeArtifact *SpecArtifact
		if request.GoalAgentCount == 2 {
			stored, challengeFound, challengeErr := n.artifacts.Get(ctx, request.TenantID, request.ProjectID, ArtifactGoalChallenge, request.GoalSpecID+"-challenge", baseVersion)
			if challengeErr != nil || !challengeFound {
				if challengeErr != nil {
					return NegotiationResult{}, challengeErr
				}
				return NegotiationResult{}, ErrArtifactNotFound
			}
			report, reportErr := decodeChallengeArtifact(stored)
			if reportErr != nil {
				return NegotiationResult{}, reportErr
			}
			challenge = &report
			challengeArtifact = &stored
		}
		outcome, publishErr := n.publishGoal(ctx, request, goal, previousApproved)
		return NegotiationResult{Goal: goal, Artifact: existing, Challenge: challenge, ChallengeArtifact: challengeArtifact, Project: outcome}, publishErr
	}

	inputs := []ArtifactPointer{artifactPointer(message)}
	if previous != nil {
		inputs = append(inputs, artifactPointer(*previous))
	}
	proposer, err := n.invoker.Invoke(ctx, AgentInvocation{
		InvocationID: request.IdempotencyKey + ":proposer:" + fmt.Sprint(baseVersion), TenantID: request.TenantID, ProjectID: request.ProjectID,
		Role: agentruntime.RoleGoalProposer, Stage: "GOAL_DRAFT", Inputs: inputs,
	})
	if err != nil {
		return NegotiationResult{}, err
	}
	provisionalGoal, provisionalContent, err := normalizeGoalRecord(proposer, request.ProjectID, baseVersion, n.clock())
	if err != nil {
		return NegotiationResult{}, err
	}
	provisional, err := n.artifacts.Put(ctx, SpecArtifact{
		TenantID: request.TenantID, ProjectID: request.ProjectID, Kind: ArtifactGoalDraft, SpecID: request.GoalSpecID,
		Version: baseVersion, ContentSHA256: provisionalGoal.ContentSHA256, Content: provisionalContent,
		CreatedBy: proposer.AgentInstanceID, SourceRunID: proposer.RunID,
	})
	if err != nil {
		return NegotiationResult{}, err
	}
	if request.GoalAgentCount == 1 {
		outcome, publishErr := n.publishGoal(ctx, request, provisionalGoal, previousApproved)
		return NegotiationResult{Goal: provisionalGoal, Artifact: provisional, Project: outcome}, publishErr
	}

	challenger, err := n.invoker.Invoke(ctx, AgentInvocation{
		InvocationID: request.IdempotencyKey + ":challenger:" + fmt.Sprint(baseVersion), TenantID: request.TenantID, ProjectID: request.ProjectID,
		Role: agentruntime.RoleGoalChallenger, Stage: "GOAL_CHALLENGE", Inputs: []ArtifactPointer{artifactPointer(message), artifactPointer(provisional)},
	})
	if err != nil {
		return NegotiationResult{}, err
	}
	if challenger.AgentInstanceID == proposer.AgentInstanceID {
		return NegotiationResult{}, ErrAgentOutput
	}
	report, reportContent, err := normalizeChallenge(challenger, request.ProjectID, contracts.SpecRef{Version: provisionalGoal.Content.Version, SHA256: provisionalGoal.ContentSHA256}, n.clock())
	if err != nil {
		return NegotiationResult{}, err
	}
	challengeArtifact, err := n.artifacts.Put(ctx, SpecArtifact{
		TenantID: request.TenantID, ProjectID: request.ProjectID, Kind: ArtifactGoalChallenge,
		SpecID: request.GoalSpecID + "-challenge", Version: baseVersion, ContentSHA256: report.SHA256,
		Content: reportContent, CreatedBy: challenger.AgentInstanceID, SourceRunID: challenger.RunID,
	})
	if err != nil {
		return NegotiationResult{}, err
	}
	revised, err := n.invoker.Invoke(ctx, AgentInvocation{
		InvocationID: request.IdempotencyKey + ":proposer:" + fmt.Sprint(finalVersion), TenantID: request.TenantID, ProjectID: request.ProjectID,
		Role: agentruntime.RoleGoalProposer, Stage: "GOAL_REVISION", Inputs: []ArtifactPointer{artifactPointer(message), artifactPointer(provisional), artifactPointer(challengeArtifact)},
	})
	if err != nil {
		return NegotiationResult{}, err
	}
	if revised.AgentInstanceID != proposer.AgentInstanceID {
		return NegotiationResult{}, ErrAgentOutput
	}
	goal, goalContent, err := normalizeGoalRecord(revised, request.ProjectID, finalVersion, n.clock())
	if err != nil {
		return NegotiationResult{}, err
	}
	finalArtifact, err := n.artifacts.Put(ctx, SpecArtifact{
		TenantID: request.TenantID, ProjectID: request.ProjectID, Kind: ArtifactGoalDraft, SpecID: request.GoalSpecID,
		Version: finalVersion, ContentSHA256: goal.ContentSHA256, Content: goalContent,
		CreatedBy: revised.AgentInstanceID, SourceRunID: revised.RunID,
	})
	if err != nil {
		return NegotiationResult{}, err
	}
	outcome, err := n.publishGoal(ctx, request, goal, previousApproved)
	return NegotiationResult{Goal: goal, Artifact: finalArtifact, Challenge: &report, ChallengeArtifact: &challengeArtifact, Project: outcome}, err
}

func (n *Negotiator) Approve(ctx context.Context, request ApprovalRequest) (orchestrator.ProjectOutcome, error) {
	approval := request.Approval
	now := n.clock().UTC()
	if request.TenantID == "" || request.ProjectID == "" || request.GoalSpecID == "" || request.ExpectedProjectVersion < 1 || request.GoalRef.Validate() != nil || request.UserPrincipalID == "" || request.IdempotencyKey == "" || approval.RecordID == "" || approval.ApprovalType != "GOAL_APPROVAL" || approval.SubjectType != "GOAL_SPEC" || approval.SubjectID != request.GoalSpecID || approval.SubjectVersion != request.GoalRef.Version || approval.SubjectSHA256 != request.GoalRef.SHA256 || approval.PrincipalID != request.UserPrincipalID || approval.Reason == "" || approval.IssuedAt.IsZero() || approval.IssuedAt.After(now) || approval.Signature == "" || approval.RevokedAt != nil || approval.ExpiresAt != nil && !approval.ExpiresAt.After(now) {
		return orchestrator.ProjectOutcome{}, ErrInvalidRequest
	}
	artifact, found, err := n.artifacts.Get(ctx, request.TenantID, request.ProjectID, ArtifactGoalDraft, request.GoalSpecID, request.GoalRef.Version)
	if err != nil || !found {
		if err != nil {
			return orchestrator.ProjectOutcome{}, err
		}
		return orchestrator.ProjectOutcome{}, ErrArtifactNotFound
	}
	goal, err := decodeGoalArtifact(artifact)
	if err != nil || goal.ContentSHA256 != request.GoalRef.SHA256 || len(goal.Content.UnresolvedItems) != 0 {
		return orchestrator.ProjectOutcome{}, ErrInvalidRequest
	}
	approvedBy := &contracts.ApprovalActor{ActorID: request.UserPrincipalID, ApprovedAt: approval.IssuedAt.UTC().Format(time.RFC3339Nano)}
	approved, content, err := encodeGoal(goal.Content, contracts.GoalApproved, approvedBy)
	if err != nil {
		return orchestrator.ProjectOutcome{}, err
	}
	binding := &state.ApprovalBinding{
		RecordID: approval.RecordID, ApprovalType: approval.ApprovalType, SubjectType: approval.SubjectType, SubjectID: approval.SubjectID,
		SubjectVersion: approval.SubjectVersion, SubjectSHA256: approval.SubjectSHA256, PrincipalID: approval.PrincipalID,
		Reason: approval.Reason, IssuedAt: approval.IssuedAt, ExpiresAt: approval.ExpiresAt, RevokedAt: approval.RevokedAt, Signature: approval.Signature,
	}
	if _, err := n.artifacts.Put(ctx, SpecArtifact{
		TenantID: request.TenantID, ProjectID: request.ProjectID, Kind: ArtifactGoalApproved, SpecID: request.GoalSpecID,
		Version: request.GoalRef.Version, ContentSHA256: approved.ContentSHA256, Content: content, CreatedBy: request.UserPrincipalID,
	}); err != nil {
		return orchestrator.ProjectOutcome{}, err
	}
	outcome, err := n.projects.HandleProject(ctx, orchestrator.ProjectRequest{
		TenantID: request.TenantID, ProjectID: request.ProjectID, PrincipalID: request.UserPrincipalID,
		IdempotencyKey: request.IdempotencyKey, ExpectedVersion: request.ExpectedProjectVersion,
		Command: state.ProjectCommand{Type: state.ProjectCommandApproveGoal, Goal: &state.GoalRecord{ID: request.GoalSpecID, Version: request.GoalRef.Version, SHA256: request.GoalRef.SHA256}, GoalSpec: &approved, Approval: binding},
	})
	if err != nil {
		return orchestrator.ProjectOutcome{}, err
	}
	return outcome, nil
}

func (n *Negotiator) validateNegotiation(ctx context.Context, request NegotiationRequest, finalVersion int) (state.Project, *SpecArtifact, bool, bool, error) {
	if request.TenantID == "" || request.ProjectID == "" || request.GoalSpecID == "" || request.MessageID == "" || request.UserPrincipalID == "" || len(request.UserInput) == 0 || len(request.UserInput) > 1<<20 || request.GoalAgentCount < 1 || request.GoalAgentCount > 2 || request.ExpectedProjectVersion < 1 || request.IdempotencyKey == "" {
		return state.Project{}, nil, false, false, ErrInvalidRequest
	}
	project, found, err := n.projects.Project(ctx, request.TenantID, request.ProjectID)
	if err != nil || !found || project.GoalAgentCount != request.GoalAgentCount {
		if err != nil {
			return state.Project{}, nil, false, false, err
		}
		return state.Project{}, nil, false, false, ErrInvalidRequest
	}
	if project.Version == request.ExpectedProjectVersion+1 && project.Goal != nil && project.Goal.ID == request.GoalSpecID && project.Goal.Version == finalVersion {
		return project, nil, request.SupersedeApprovedGoal, true, nil
	}
	if project.Version != request.ExpectedProjectVersion || request.MessageAccepted && !project.GoalProcessing {
		return state.Project{}, nil, false, false, ErrInvalidRequest
	}
	if request.PreviousRef == nil {
		if project.Goal != nil {
			return state.Project{}, nil, false, false, ErrInvalidRequest
		}
		return project, nil, false, false, nil
	}
	if request.PreviousRef.Validate() != nil || project.Goal == nil || project.Goal.Version != request.PreviousRef.Version || project.Goal.SHA256 != request.PreviousRef.SHA256 || project.Goal.ID != request.GoalSpecID {
		return state.Project{}, nil, false, false, ErrInvalidRequest
	}
	if project.Goal.ApprovedBy != "" {
		if !request.SupersedeApprovedGoal {
			return state.Project{}, nil, false, false, ErrInvalidRequest
		}
		approved, approvedFound, approvedErr := n.artifacts.Get(ctx, request.TenantID, request.ProjectID, ArtifactGoalApproved, request.GoalSpecID, request.PreviousRef.Version)
		if approvedErr != nil {
			return state.Project{}, nil, false, false, approvedErr
		}
		if approvedFound {
			return project, &approved, true, false, nil
		}
		draft, draftFound, draftErr := n.artifacts.Get(ctx, request.TenantID, request.ProjectID, ArtifactGoalDraft, request.GoalSpecID, request.PreviousRef.Version)
		if draftErr != nil || !draftFound {
			if draftErr != nil {
				return state.Project{}, nil, false, false, draftErr
			}
			return state.Project{}, nil, false, false, ErrArtifactNotFound
		}
		return project, &draft, true, false, nil
	}
	draft, found, err := n.artifacts.Get(ctx, request.TenantID, request.ProjectID, ArtifactGoalDraft, request.GoalSpecID, request.PreviousRef.Version)
	if err != nil || !found {
		if err != nil {
			return state.Project{}, nil, false, false, err
		}
		return state.Project{}, nil, false, false, ErrArtifactNotFound
	}
	return project, &draft, false, false, nil
}

func (n *Negotiator) publishGoal(ctx context.Context, request NegotiationRequest, goal contracts.GoalSpec, supersede bool) (orchestrator.ProjectOutcome, error) {
	commandType := state.ProjectCommandProposeGoal
	if supersede {
		commandType = state.ProjectCommandSupersedeGoal
	}
	record := &state.GoalRecord{ID: request.GoalSpecID, Version: goal.Content.Version, SHA256: goal.ContentSHA256, UnresolvedItems: append([]string(nil), goal.Content.UnresolvedItems...)}
	var message *state.GoalMessage
	if !request.MessageAccepted {
		message = &state.GoalMessage{Kind: state.GoalMessageUser, Message: string(request.UserInput)}
	}
	return n.projects.HandleProject(ctx, orchestrator.ProjectRequest{
		TenantID: request.TenantID, ProjectID: request.ProjectID, PrincipalID: request.UserPrincipalID,
		IdempotencyKey: request.IdempotencyKey, ExpectedVersion: request.ExpectedProjectVersion,
		Command: state.ProjectCommand{Type: commandType, Goal: record, GoalSpec: &goal, GoalMessage: message, ImpactedTaskIDs: append([]string(nil), request.ImpactedTaskIDs...)},
	})
}

func normalizeGoalRecord(record AgentRecord, projectID string, version int, at time.Time) (contracts.GoalSpec, []byte, error) {
	if record.RunID == "" || record.AgentInstanceID == "" || record.Role != agentruntime.RoleGoalProposer || len(record.Payload) == 0 {
		return contracts.GoalSpec{}, nil, ErrAgentOutput
	}
	var content contracts.GoalContent
	if err := decodeStrict(record.Payload, &content); err != nil {
		return contracts.GoalSpec{}, nil, ErrAgentOutput
	}
	content.GoalSpecVersion = 1
	content.ProjectID = projectID
	content.Version = version
	content.CreatedAt = at.UTC().Format(time.RFC3339Nano)
	content.CreatedBy = contracts.AgentIdentity{AgentInstanceID: record.AgentInstanceID, Role: string(record.Role)}
	if err := validateGoalContent(content); err != nil {
		return contracts.GoalSpec{}, nil, err
	}
	return encodeGoal(content, contracts.GoalDraft, nil)
}

func normalizeChallenge(record AgentRecord, projectID string, goalRef contracts.SpecRef, at time.Time) (ChallengeReport, []byte, error) {
	if record.RunID == "" || record.AgentInstanceID == "" || record.Role != agentruntime.RoleGoalChallenger || len(record.Payload) == 0 {
		return ChallengeReport{}, nil, ErrAgentOutput
	}
	var draft struct {
		Findings []ChallengeFinding `json:"findings"`
	}
	if err := decodeStrict(record.Payload, &draft); err != nil || draft.Findings == nil {
		return ChallengeReport{}, nil, ErrAgentOutput
	}
	report := ChallengeReport{ReportVersion: 1, ProjectID: projectID, GoalSpecRef: goalRef, Findings: append([]ChallengeFinding(nil), draft.Findings...), CreatedAt: at.UTC().Format(time.RFC3339Nano), CreatedBy: contracts.AgentIdentity{AgentInstanceID: record.AgentInstanceID, Role: string(record.Role)}}
	if err := validateChallenge(report); err != nil {
		return ChallengeReport{}, nil, err
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		return ChallengeReport{}, nil, err
	}
	report.SHA256, err = canonicaljson.DigestObjectWithoutFields(encoded, "sha256", "signature")
	if err != nil {
		return ChallengeReport{}, nil, err
	}
	encoded, err = json.Marshal(report)
	return report, encoded, err
}

func decodeGoalArtifact(artifact SpecArtifact) (contracts.GoalSpec, error) {
	var goal contracts.GoalSpec
	if err := decodeStrict(artifact.Content, &goal); err != nil || contracts.ValidateGoalJSON(artifact.Content) != nil || goal.ContentSHA256 != artifact.ContentSHA256 || goal.Content.Version != artifact.Version {
		return contracts.GoalSpec{}, ErrAgentOutput
	}
	return goal, nil
}

func decodeChallengeArtifact(artifact SpecArtifact) (ChallengeReport, error) {
	var report ChallengeReport
	if err := decodeStrict(artifact.Content, &report); err != nil || validateChallenge(report) != nil || report.SHA256 != artifact.ContentSHA256 {
		return ChallengeReport{}, ErrAgentOutput
	}
	digest, err := canonicaljson.DigestObjectWithoutFields(artifact.Content, "sha256", "signature")
	if err != nil || digest != report.SHA256 {
		return ChallengeReport{}, ErrAgentOutput
	}
	return report, nil
}

func artifactPointer(artifact SpecArtifact) ArtifactPointer {
	return ArtifactPointer{Kind: artifact.Kind, SpecID: artifact.SpecID, Version: artifact.Version, URI: artifact.URI, ContentSHA256: artifact.ContentSHA256}
}
