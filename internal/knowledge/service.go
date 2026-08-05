package knowledge

import (
	"context"
	"errors"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

type ServiceConfig struct {
	Repository Repository
	Authorizer authz.PolicyEvaluator
	Scopes     ScopeResolver
	Events     KnowledgeUpdatedPublisher
	Clock      func() time.Time
}

type Service struct {
	repository Repository
	authorizer authz.PolicyEvaluator
	scopes     ScopeResolver
	events     KnowledgeUpdatedPublisher
	clock      func() time.Time
	indexMu    sync.RWMutex
	indexes    map[string]indexedView
}

type visibleDocument struct {
	SourceProjectID string
	Revision        string
	Document        StoredDocument
}

type indexedView struct {
	TenantID  string
	ProjectID string
	Revision  string
	Documents map[string]visibleDocument
	Titles    map[string]map[string]struct{}
	Tags      map[string]map[string]struct{}
	Terms     map[string]map[string]struct{}
	BuiltAt   time.Time
}

func NewService(config ServiceConfig) (*Service, error) {
	if config.Repository == nil || config.Authorizer == nil || config.Scopes == nil {
		return nil, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "knowledge dependencies"})
	}
	return &Service{
		repository: config.Repository, authorizer: config.Authorizer, scopes: config.Scopes,
		events: config.Events, clock: config.Clock, indexes: make(map[string]indexedView),
	}, nil
}

func (service *Service) now() time.Time {
	if service != nil && service.clock != nil {
		return service.clock().UTC()
	}
	return time.Now().UTC()
}

// Initialize creates the immutable empty baseline used during project
// creation. The repository operation is idempotent, so a retry after a process
// restart converges on the original revision.
func (service *Service) Initialize(ctx context.Context, tenantID, projectID string, createdAt time.Time) (Manifest, error) {
	if service == nil || service.repository == nil {
		return Manifest{}, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "knowledge repository"})
	}
	return service.repository.Initialize(ctx, tenantID, projectID, createdAt)
}

func (service *Service) Search(ctx context.Context, request SearchRequest) (SearchResponse, error) {
	if err := service.authorize(ctx, request.Access, false); err != nil {
		return SearchResponse{}, err
	}
	query, err := normalizeSearch(request)
	if err != nil {
		return SearchResponse{}, err
	}
	revision, err := service.repository.Head(ctx, request.Access.TenantID, request.Access.ProjectID)
	if err != nil {
		return SearchResponse{}, err
	}
	if revision == "" {
		return SearchResponse{}, aorerrors.New(aorerrors.CodeNotFound, "", nil)
	}
	view, err := service.view(ctx, request.Access.TenantID, request.Access.ProjectID, revision)
	if err != nil {
		return SearchResponse{}, err
	}
	type scoredDocument struct {
		visible visibleDocument
		score   float64
		line    int
	}
	matches := make([]scoredDocument, 0)
	for _, documentPath := range searchCandidates(view, query) {
		visible := view.Documents[documentPath]
		score, line, matchesQuery := matchDocument(visible.Document, query)
		if matchesQuery {
			matches = append(matches, scoredDocument{visible: visible, score: score, line: line})
		}
	}
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].score != matches[j].score {
			return matches[i].score > matches[j].score
		}
		left := matches[i].visible.Document.Metadata
		right := matches[j].visible.Document.Metadata
		if trustRank(left.TrustLevel) != trustRank(right.TrustLevel) {
			return trustRank(left.TrustLevel) > trustRank(right.TrustLevel)
		}
		if left.Path != right.Path {
			return left.Path < right.Path
		}
		return matches[i].visible.SourceProjectID < matches[j].visible.SourceProjectID
	})
	if len(matches) > query.Limit {
		matches = matches[:query.Limit]
	}
	response := SearchResponse{Revision: revision, References: make([]Reference, 0, len(matches))}
	for _, match := range matches {
		lineStart := 1
		lineEnd := match.visible.Document.Metadata.LineCount
		if query.Text != "" {
			lineStart = match.line
			lineEnd = match.line
		}
		reference, err := service.reference(request.Access.TenantID, request.Access.ProjectID, revision, match.visible, lineStart, lineEnd, match.score)
		if err != nil {
			return SearchResponse{}, err
		}
		response.References = append(response.References, reference)
	}
	return response, nil
}

func (service *Service) ReadRange(ctx context.Context, request ReadRangeRequest) (ReadRangeResponse, error) {
	if err := service.authorize(ctx, request.Access, false); err != nil {
		return ReadRangeResponse{}, err
	}
	reference := request.Reference
	if reference.ScopeRevision == "" || !revisionPattern.MatchString(reference.ScopeRevision) || !revisionPattern.MatchString(reference.Revision) || !revisionPattern.MatchString(reference.SHA256) || reference.SourceProjectID == "" || len(reference.SourceProjectID) > 256 || reference.LineStart < 1 || reference.LineEnd < reference.LineStart {
		return ReadRangeResponse{}, invalid("knowledge reference")
	}
	documentPath, err := normalizePath(reference.Path)
	if err != nil {
		return ReadRangeResponse{}, err
	}
	view, err := service.view(ctx, request.Access.TenantID, request.Access.ProjectID, reference.ScopeRevision)
	if err != nil {
		return ReadRangeResponse{}, err
	}
	visible, exists := view.Documents[documentPath]
	if !exists || visible.SourceProjectID != reference.SourceProjectID || visible.Revision != reference.Revision || visible.Document.Metadata.SHA256 != reference.SHA256 {
		return ReadRangeResponse{}, aorerrors.New(aorerrors.CodeNotFound, "", nil)
	}
	expected, err := service.reference(request.Access.TenantID, request.Access.ProjectID, reference.ScopeRevision, visible, reference.LineStart, reference.LineEnd, reference.RetrievalScore)
	if err != nil {
		return ReadRangeResponse{}, err
	}
	if reference.LineEnd > visible.Document.Metadata.LineCount || reference.ResourceURI != expected.ResourceURI || reference.LocalPath != expected.LocalPath || reference.Encoding != "utf-8" || reference.LineEnding != "LF" || reference.ContentType != expected.ContentType || reference.TrustLevel != expected.TrustLevel || reference.Title != expected.Title || !sameStrings(reference.Tags, expected.Tags) || !sameSource(reference.Source, expected.Source) {
		return ReadRangeResponse{}, invalid("knowledge reference")
	}
	lines := splitLines(visible.Document.Content)
	lineStart := request.LineStart
	if lineStart == 0 {
		lineStart = reference.LineStart
	}
	lineEnd := request.LineEnd
	if lineEnd == 0 {
		lineEnd = reference.LineEnd
	}
	if lineStart < 1 || lineEnd < lineStart || lineStart > len(lines) {
		return ReadRangeResponse{}, invalid("line range")
	}
	if lineEnd > len(lines) {
		lineEnd = len(lines)
	}
	pageEnd := lineStart - 1
	pageBytes := 0
	terminalLF := visible.Document.Content[len(visible.Document.Content)-1] == '\n'
	for current := lineStart; current <= lineEnd && current-lineStart < MaxReadLines; current++ {
		additional := len(lines[current-1])
		if current < len(lines) || terminalLF {
			additional++
		}
		if pageBytes+additional > MaxReadBytes {
			break
		}
		pageBytes += additional
		pageEnd = current
	}
	if pageEnd < lineStart {
		return ReadRangeResponse{}, invalid("line exceeds read page")
	}
	pageReference, err := service.reference(request.Access.TenantID, request.Access.ProjectID, reference.ScopeRevision, visible, lineStart, pageEnd, reference.RetrievalScore)
	if err != nil {
		return ReadRangeResponse{}, err
	}
	pageContent := strings.Join(lines[lineStart-1:pageEnd], "\n")
	if pageEnd < len(lines) || terminalLF {
		pageContent += "\n"
	}
	response := ReadRangeResponse{Reference: pageReference, Content: pageContent}
	if pageEnd < lineEnd {
		response.NextLine = pageEnd + 1
	}
	return response, nil
}

func (service *Service) Manifest(ctx context.Context, access Access, revision string) (Manifest, error) {
	if err := service.authorize(ctx, access, false); err != nil {
		return Manifest{}, err
	}
	if revision == "" {
		var err error
		revision, err = service.repository.Head(ctx, access.TenantID, access.ProjectID)
		if err != nil {
			return Manifest{}, err
		}
	}
	if revision == "" {
		return Manifest{}, aorerrors.New(aorerrors.CodeNotFound, "", nil)
	}
	snapshot, err := service.repository.Load(ctx, access.TenantID, access.ProjectID, revision)
	if err != nil {
		return Manifest{}, err
	}
	return cloneManifest(snapshot.Manifest), nil
}

func (service *Service) Update(ctx context.Context, access Access, proposal UpdateProposal) (UpdateResult, error) {
	proposal = cloneProposal(proposal)
	digest, err := proposalDigest(proposal)
	if err != nil {
		return UpdateResult{}, err
	}
	if access.ParameterDigest != digest {
		return UpdateResult{}, aorerrors.New(aorerrors.CodeKnowledgeWriteForbidden, "", nil)
	}
	if access.Principal.Type != authn.PrincipalKnowledgeCurator || access.Principal.Role != authn.RoleKnowledgeCurator || access.Approval == nil || access.Lease == nil {
		return UpdateResult{}, aorerrors.New(aorerrors.CodeKnowledgeWriteForbidden, "", nil)
	}
	if service == nil || service.events == nil {
		return UpdateResult{}, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "knowledge event publisher"})
	}
	if err := service.authorize(ctx, access, true); err != nil {
		return UpdateResult{}, err
	}
	snapshot, err := service.prepareUpdate(ctx, access, proposal)
	if err != nil {
		var typed *aorerrors.Error
		if errors.As(err, &typed) && typed.Code == aorerrors.CodeStateVersionConflict {
			return service.resumeCommittedUpdate(ctx, access, proposal, digest)
		}
		return UpdateResult{}, err
	}
	updatedDocuments, err := service.resolveEffective(ctx, access.TenantID, access.ProjectID, "", &snapshot, make(map[string]bool))
	if err != nil {
		return UpdateResult{}, err
	}
	if err := service.validateTrustChange(ctx, access, proposal.BaseRevision, updatedDocuments); err != nil {
		return UpdateResult{}, err
	}
	// Revalidate immediately before the immutable snapshot and HEAD update.
	if err := service.authorize(ctx, access, true); err != nil {
		return UpdateResult{}, err
	}
	manifest, err := service.repository.Commit(ctx, CommitRequest{
		TenantID: access.TenantID, ProjectID: access.ProjectID,
		BaseRevision: proposal.BaseRevision, Snapshot: snapshot,
	})
	if err != nil {
		return UpdateResult{}, err
	}
	service.invalidate(access.TenantID, access.ProjectID)
	result := UpdateResult{Manifest: manifest, Digest: digest}
	view := buildIndexedView(access.TenantID, access.ProjectID, manifest.Revision, updatedDocuments, service.now())
	service.storeView(view)
	index := IndexSnapshot{TenantID: access.TenantID, ProjectID: access.ProjectID, Revision: manifest.Revision, BuiltAt: view.BuiltAt, Documents: len(updatedDocuments)}
	if err := service.events.Publish(ctx, access, proposal.BaseRevision, result, index); err != nil {
		return UpdateResult{}, err
	}
	return result, nil
}

// ValidateProposal runs the deterministic update checks against the current
// immutable head without committing a snapshot or requiring write proofs.
func (service *Service) ValidateProposal(ctx context.Context, access Access, proposal UpdateProposal) (ProposalValidation, error) {
	proposal = cloneProposal(proposal)
	if err := service.authorize(ctx, access, false); err != nil {
		return ProposalValidation{}, err
	}
	digest, err := proposalDigest(proposal)
	if err != nil {
		return ProposalValidation{}, err
	}
	snapshot, err := service.prepareUpdate(ctx, access, proposal)
	if err != nil {
		return ProposalValidation{}, err
	}
	documents, err := service.resolveEffective(ctx, access.TenantID, access.ProjectID, "", &snapshot, make(map[string]bool))
	if err != nil {
		return ProposalValidation{}, err
	}
	if err := service.validateTrustChange(ctx, access, proposal.BaseRevision, documents); err != nil {
		return ProposalValidation{}, err
	}
	report := buildValidationReport(proposal, digest, documents)
	validation := ProposalValidation{Digest: digest, DocumentCount: len(documents), Report: report}
	if !report.Passed {
		return validation, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "knowledge validation report", "reportSha256": report.SHA256})
	}
	return validation, nil
}

func (service *Service) resumeCommittedUpdate(ctx context.Context, access Access, proposal UpdateProposal, digest string) (UpdateResult, error) {
	current, err := service.repository.Head(ctx, access.TenantID, access.ProjectID)
	if err != nil {
		return UpdateResult{}, err
	}
	if current == "" || current == proposal.BaseRevision {
		return UpdateResult{}, aorerrors.New(aorerrors.CodeStateVersionConflict, "", nil)
	}
	committed, err := service.repository.Load(ctx, access.TenantID, access.ProjectID, current)
	if err != nil {
		return UpdateResult{}, err
	}
	candidate, err := service.prepareSnapshot(ctx, access, proposal, committed.Manifest.CreatedAt)
	if err != nil {
		return UpdateResult{}, err
	}
	candidateRevision, err := snapshotDigest(candidate)
	if err != nil {
		return UpdateResult{}, err
	}
	if candidateRevision != current {
		return UpdateResult{}, aorerrors.New(aorerrors.CodeStateVersionConflict, "", nil)
	}
	updatedDocuments, err := service.resolveEffective(ctx, access.TenantID, access.ProjectID, current, nil, make(map[string]bool))
	if err != nil {
		return UpdateResult{}, err
	}
	if err := service.validateTrustChange(ctx, access, proposal.BaseRevision, updatedDocuments); err != nil {
		return UpdateResult{}, err
	}
	if err := service.authorize(ctx, access, true); err != nil {
		return UpdateResult{}, err
	}
	service.invalidate(access.TenantID, access.ProjectID)
	view := buildIndexedView(access.TenantID, access.ProjectID, current, updatedDocuments, service.now())
	service.storeView(view)
	result := UpdateResult{Manifest: committed.Manifest, Digest: digest}
	index := IndexSnapshot{TenantID: access.TenantID, ProjectID: access.ProjectID, Revision: current, BuiltAt: view.BuiltAt, Documents: len(updatedDocuments)}
	if err := service.events.Publish(ctx, access, proposal.BaseRevision, result, index); err != nil {
		return UpdateResult{}, err
	}
	return result, nil
}

func (service *Service) validateTrustChange(ctx context.Context, access Access, baseRevision string, updatedDocuments map[string]visibleDocument) error {
	if baseRevision == "" {
		return nil
	}
	priorDocuments, err := service.resolveEffective(ctx, access.TenantID, access.ProjectID, baseRevision, nil, make(map[string]bool))
	if err != nil {
		return err
	}
	for documentPath, prior := range priorDocuments {
		updated, stillExists := updatedDocuments[documentPath]
		if stillExists && trustRank(updated.Document.Metadata.TrustLevel) < trustRank(prior.Document.Metadata.TrustLevel) {
			return aorerrors.New(aorerrors.CodeConflict, "", map[string]any{"scope": "trust downgrade"})
		}
	}
	return nil
}

func cloneProposal(input UpdateProposal) UpdateProposal {
	output := input
	output.Parents = append([]ParentSnapshot(nil), input.Parents...)
	output.Overrides = append([]string(nil), input.Overrides...)
	output.DeletePaths = append([]string(nil), input.DeletePaths...)
	output.Documents = make([]DocumentInput, len(input.Documents))
	for index, document := range input.Documents {
		document.Tags = append([]string(nil), document.Tags...)
		document.Content = append([]byte(nil), document.Content...)
		document.Source = cloneSource(document.Source)
		output.Documents[index] = document
	}
	return output
}

func (service *Service) RebuildIndex(ctx context.Context, access Access, revision string) (IndexSnapshot, error) {
	if err := service.authorize(ctx, access, false); err != nil {
		return IndexSnapshot{}, err
	}
	if revision == "" {
		var err error
		revision, err = service.repository.Head(ctx, access.TenantID, access.ProjectID)
		if err != nil {
			return IndexSnapshot{}, err
		}
	}
	if revision == "" {
		return IndexSnapshot{}, aorerrors.New(aorerrors.CodeNotFound, "", nil)
	}
	return service.rebuildIndex(ctx, access.TenantID, access.ProjectID, revision)
}

func (service *Service) rebuildIndex(ctx context.Context, tenantID, projectID, revision string) (IndexSnapshot, error) {
	documents, err := service.resolveEffective(ctx, tenantID, projectID, revision, nil, make(map[string]bool))
	if err != nil {
		return IndexSnapshot{}, err
	}
	view := buildIndexedView(tenantID, projectID, revision, documents, service.now())
	service.storeView(view)
	return IndexSnapshot{TenantID: tenantID, ProjectID: projectID, Revision: revision, BuiltAt: view.BuiltAt, Documents: len(documents)}, nil
}

func (service *Service) prepareUpdate(ctx context.Context, access Access, proposal UpdateProposal) (Snapshot, error) {
	current, err := service.repository.Head(ctx, access.TenantID, access.ProjectID)
	if err != nil {
		return Snapshot{}, err
	}
	if current != proposal.BaseRevision {
		return Snapshot{}, aorerrors.New(aorerrors.CodeStateVersionConflict, "", nil)
	}
	return service.prepareSnapshot(ctx, access, proposal, service.now())
}

func (service *Service) prepareSnapshot(ctx context.Context, access Access, proposal UpdateProposal, createdAt time.Time) (Snapshot, error) {
	snapshot := Snapshot{Manifest: Manifest{Version: 1, TenantID: access.TenantID, ProjectID: access.ProjectID}, Documents: make(map[string]StoredDocument)}
	if proposal.BaseRevision != "" {
		base, err := service.repository.Load(ctx, access.TenantID, access.ProjectID, proposal.BaseRevision)
		if err != nil {
			return Snapshot{}, err
		}
		snapshot = cloneSnapshot(base)
		snapshot.Manifest.Revision = ""
		snapshot.Manifest.Documents = nil
	}
	if proposal.Parents != nil {
		parents, err := validateParents(access.ProjectID, proposal.Parents, proposal.ParentOrderExplicit)
		if err != nil {
			return Snapshot{}, err
		}
		snapshot.Manifest.Parents = parents
		snapshot.Manifest.ParentOrderExplicit = proposal.ParentOrderExplicit
	}
	if proposal.Overrides != nil {
		overrides, err := normalizePathSet(proposal.Overrides)
		if err != nil {
			return Snapshot{}, err
		}
		snapshot.Manifest.Overrides = overrides
	}
	deleted := make(map[string]struct{}, len(proposal.DeletePaths))
	for _, candidate := range proposal.DeletePaths {
		documentPath, err := normalizePath(candidate)
		if err != nil {
			return Snapshot{}, err
		}
		if _, duplicate := deleted[documentPath]; duplicate {
			return Snapshot{}, invalid("duplicate delete path")
		}
		deleted[documentPath] = struct{}{}
		if _, exists := snapshot.Documents[documentPath]; !exists {
			return Snapshot{}, aorerrors.New(aorerrors.CodeNotFound, "", nil)
		}
		delete(snapshot.Documents, documentPath)
	}
	changed := make(map[string]struct{}, len(proposal.Documents))
	for _, input := range proposal.Documents {
		document, err := normalizeDocument(input)
		if err != nil {
			return Snapshot{}, err
		}
		if _, duplicate := changed[document.Metadata.Path]; duplicate {
			return Snapshot{}, invalid("duplicate document path")
		}
		if _, wasDeleted := deleted[document.Metadata.Path]; wasDeleted {
			return Snapshot{}, invalid("delete and update path")
		}
		changed[document.Metadata.Path] = struct{}{}
		snapshot.Documents[document.Metadata.Path] = document
	}
	snapshot.Manifest.CreatedAt = createdAt.UTC()
	return snapshot, nil
}

func (service *Service) authorize(ctx context.Context, access Access, write bool) error {
	if service == nil || service.repository == nil || service.authorizer == nil || service.scopes == nil {
		return aorerrors.New(aorerrors.CodeDependencyUnavailable, "", nil)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := access.Principal.Validate(); err != nil {
		return err
	}
	if access.TenantID == "" || access.ProjectID == "" || access.Principal.TenantID != "" && access.Principal.TenantID != access.TenantID || access.Principal.ProjectID != "" && access.Principal.ProjectID != access.ProjectID {
		return aorerrors.New(aorerrors.CodeForbidden, "", map[string]any{"scope": "knowledge project"})
	}
	project, err := service.scopes.ResolveProject(ctx, access.TenantID, access.ProjectID)
	if err != nil {
		return aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, map[string]any{"scope": "project scope"})
	}
	if project.TenantID != access.TenantID || project.ID != access.ProjectID {
		return aorerrors.New(aorerrors.CodeForbidden, "", map[string]any{"scope": "knowledge project"})
	}
	input := authz.PolicyInput{
		Principal: access.Principal, Project: project, Action: authz.ActionKnowledgeRead,
		Resource: authz.Resource{Type: "knowledge.snapshot", ID: access.ProjectID},
	}
	if write {
		input.Action = authz.ActionKnowledgeWrite
		input.Resource.Type = "KNOWLEDGE_CHANGE"
		input.ParameterDigest = access.ParameterDigest
		input.Lease = access.Lease
		input.Approval = access.Approval
		input.Budget = authz.BudgetScope{AccountID: access.BudgetAccountID, Available: access.BudgetAccountID != ""}
	}
	decision, err := service.authorizer.Evaluate(ctx, input)
	if err != nil {
		return err
	}
	if err := decision.Validate(service.now()); err != nil {
		return err
	}
	if decision.PolicyVersion == "" || access.PolicyVersion != "" && decision.PolicyVersion != access.PolicyVersion {
		return aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"policyVersion": decision.PolicyVersion})
	}
	if decision.Decision == authz.DecisionApprovalRequired {
		return aorerrors.New(aorerrors.CodeApprovalRequired, "", nil)
	}
	if decision.Decision != authz.DecisionAllow {
		if write {
			return aorerrors.New(aorerrors.CodeKnowledgeWriteForbidden, "", nil)
		}
		return aorerrors.New(aorerrors.CodeForbidden, "", nil)
	}
	return nil
}

func (service *Service) reference(tenantID, scopeProjectID, scopeRevision string, visible visibleDocument, lineStart, lineEnd int, score float64) (Reference, error) {
	localPath, err := service.repository.LocalPath(tenantID, visible.SourceProjectID, visible.Revision, visible.Document.Metadata.Path)
	if err != nil {
		return Reference{}, err
	}
	metadata := visible.Document.Metadata
	return Reference{
		ResourceURI: (&url.URL{Scheme: "file", Path: localPath}).String(), LocalPath: localPath,
		ScopeRevision: scopeRevision, SourceProjectID: visible.SourceProjectID, Path: metadata.Path,
		Revision: visible.Revision, SHA256: metadata.SHA256, LineStart: lineStart, LineEnd: lineEnd,
		Encoding: "utf-8", LineEnding: "LF", ContentType: metadata.ContentType,
		Title: metadata.Title, Tags: append([]string(nil), metadata.Tags...), TrustLevel: metadata.TrustLevel,
		Source:         cloneSource(metadata.Source),
		RetrievalScore: score,
	}, nil
}

type normalizedSearch struct {
	Path  string
	Title string
	Tags  []string
	Text  string
	Limit int
}

func normalizeSearch(request SearchRequest) (normalizedSearch, error) {
	query := normalizedSearch{Title: request.Title, Text: request.Text, Limit: request.Limit}
	if request.Path != "" {
		var err error
		query.Path, err = normalizePath(request.Path)
		if err != nil {
			return normalizedSearch{}, err
		}
	}
	if query.Title != "" && (len(query.Title) > 512 || strings.ContainsAny(query.Title, "\r\n\x00") || !utf8.ValidString(query.Title)) {
		return normalizedSearch{}, invalid("search title")
	}
	if query.Text != "" && (len(query.Text) > 4096 || strings.ContainsRune(query.Text, 0) || !utf8.ValidString(query.Text)) {
		return normalizedSearch{}, invalid("search text")
	}
	var err error
	query.Tags, err = normalizeTags(request.Tags)
	if err != nil {
		return normalizedSearch{}, err
	}
	if query.Path == "" && query.Title == "" && len(query.Tags) == 0 && strings.TrimSpace(query.Text) == "" {
		return normalizedSearch{}, invalid("search query")
	}
	if query.Limit == 0 {
		query.Limit = DefaultSearchLimit
	}
	if query.Limit < 1 || query.Limit > MaxSearchLimit {
		return normalizedSearch{}, invalid("search limit")
	}
	return query, nil
}

func matchDocument(document StoredDocument, query normalizedSearch) (float64, int, bool) {
	metadata := document.Metadata
	score := 0.0
	if query.Path != "" {
		if metadata.Path != query.Path {
			return 0, 0, false
		}
		score += 8
	}
	if query.Title != "" {
		if metadata.Title != query.Title {
			return 0, 0, false
		}
		score += 6
	}
	for _, tag := range query.Tags {
		if !contains(metadata.Tags, tag) {
			return 0, 0, false
		}
		score += 4
	}
	matchLine := 1
	if strings.TrimSpace(query.Text) != "" {
		needle := strings.ToLower(query.Text)
		found := false
		for index, line := range splitLines(document.Content) {
			if strings.Contains(strings.ToLower(line), needle) {
				matchLine = index + 1
				score += 2
				found = true
				break
			}
		}
		if !found {
			metadataText := strings.ToLower(metadata.Path + "\n" + metadata.Title + "\n" + strings.Join(metadata.Tags, "\n"))
			if !strings.Contains(metadataText, needle) {
				return 0, 0, false
			}
			score++
		}
	}
	return score, matchLine, true
}

func contains(values []string, expected string) bool {
	index := sort.SearchStrings(values, expected)
	return index < len(values) && values[index] == expected
}

func validateParents(projectID string, parents []ParentSnapshot, orderExplicit bool) ([]ParentSnapshot, error) {
	if len(parents) > 1 && !orderExplicit {
		return nil, invalid("parent order")
	}
	if len(parents) > 32 {
		return nil, invalid("parents")
	}
	seen := make(map[string]struct{}, len(parents))
	output := append([]ParentSnapshot(nil), parents...)
	for index, parent := range output {
		if parent.ProjectID == "" || parent.ProjectID == projectID || !revisionPattern.MatchString(parent.Revision) || parent.Order != index {
			return nil, invalid("parent snapshot")
		}
		if _, duplicate := seen[parent.ProjectID]; duplicate {
			return nil, invalid("duplicate parent")
		}
		seen[parent.ProjectID] = struct{}{}
	}
	return output, nil
}

func normalizePathSet(input []string) ([]string, error) {
	if len(input) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{}, len(input))
	output := make([]string, 0, len(input))
	for _, candidate := range input {
		normalized, err := normalizePath(candidate)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[normalized]; duplicate {
			return nil, invalid("duplicate path")
		}
		seen[normalized] = struct{}{}
		output = append(output, normalized)
	}
	sort.Strings(output)
	return output, nil
}

func indexKey(tenantID, projectID, revision string) string {
	return tenantID + "\x00" + projectID + "\x00" + revision
}

func (service *Service) view(ctx context.Context, tenantID, projectID, revision string) (indexedView, error) {
	key := indexKey(tenantID, projectID, revision)
	service.indexMu.RLock()
	cached, exists := service.indexes[key]
	service.indexMu.RUnlock()
	if exists {
		return cloneView(cached), nil
	}
	documents, err := service.resolveEffective(ctx, tenantID, projectID, revision, nil, make(map[string]bool))
	if err != nil {
		return indexedView{}, err
	}
	view := buildIndexedView(tenantID, projectID, revision, documents, service.now())
	service.indexMu.Lock()
	service.indexes[key] = cloneView(view)
	service.indexMu.Unlock()
	return view, nil
}

func (service *Service) invalidate(tenantID, projectID string) {
	prefix := tenantID + "\x00" + projectID + "\x00"
	service.indexMu.Lock()
	for key := range service.indexes {
		if strings.HasPrefix(key, prefix) {
			delete(service.indexes, key)
		}
	}
	service.indexMu.Unlock()
}

func (service *Service) storeView(view indexedView) {
	service.indexMu.Lock()
	service.indexes[indexKey(view.TenantID, view.ProjectID, view.Revision)] = cloneView(view)
	service.indexMu.Unlock()
}

func cloneView(input indexedView) indexedView {
	output := input
	output.Documents = make(map[string]visibleDocument, len(input.Documents))
	for documentPath, visible := range input.Documents {
		visible.Document = StoredDocument{Metadata: cloneMetadata(visible.Document.Metadata), Content: append([]byte(nil), visible.Document.Content...)}
		output.Documents[documentPath] = visible
	}
	output.Titles = cloneLookup(input.Titles)
	output.Tags = cloneLookup(input.Tags)
	output.Terms = cloneLookup(input.Terms)
	return output
}

func buildIndexedView(tenantID, projectID, revision string, documents map[string]visibleDocument, builtAt time.Time) indexedView {
	view := indexedView{
		TenantID: tenantID, ProjectID: projectID, Revision: revision, Documents: documents,
		Titles: make(map[string]map[string]struct{}), Tags: make(map[string]map[string]struct{}),
		Terms: make(map[string]map[string]struct{}), BuiltAt: builtAt,
	}
	for documentPath, visible := range documents {
		metadata := visible.Document.Metadata
		addLookup(view.Titles, metadata.Title, documentPath)
		for _, tag := range metadata.Tags {
			addLookup(view.Tags, tag, documentPath)
		}
		indexedText := metadata.Path + "\n" + metadata.Title + "\n" + strings.Join(metadata.Tags, "\n") + "\n" + string(visible.Document.Content)
		seenTerms := make(map[string]struct{})
		for _, term := range indexTerms(indexedText) {
			if _, exists := seenTerms[term]; exists {
				continue
			}
			seenTerms[term] = struct{}{}
			addLookup(view.Terms, term, documentPath)
		}
	}
	return view
}

func searchCandidates(view indexedView, query normalizedSearch) []string {
	var candidates map[string]struct{}
	if query.Path != "" {
		paths := make(map[string]struct{})
		if _, exists := view.Documents[query.Path]; exists {
			paths[query.Path] = struct{}{}
		}
		candidates = intersectPaths(candidates, paths)
	}
	if query.Title != "" {
		candidates = intersectPaths(candidates, view.Titles[query.Title])
	}
	for _, tag := range query.Tags {
		candidates = intersectPaths(candidates, view.Tags[tag])
	}
	if strings.TrimSpace(query.Text) != "" {
		for _, term := range queryTerms(query.Text) {
			candidates = intersectPaths(candidates, view.Terms[term])
		}
	}
	if candidates == nil {
		candidates = make(map[string]struct{}, len(view.Documents))
		for documentPath := range view.Documents {
			candidates[documentPath] = struct{}{}
		}
	}
	paths := make([]string, 0, len(candidates))
	for documentPath := range candidates {
		paths = append(paths, documentPath)
	}
	sort.Strings(paths)
	return paths
}

func textTokens(value string) []string {
	return strings.FieldsFunc(strings.ToLower(value), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsNumber(r) && r != '-' && r != '_'
	})
}

func indexTerms(value string) []string {
	terms := make([]string, 0)
	for _, token := range textTokens(value) {
		runes := []rune(token)
		for width := 1; width <= 3 && width <= len(runes); width++ {
			for start := 0; start+width <= len(runes); start++ {
				terms = append(terms, string(runes[start:start+width]))
			}
		}
	}
	return terms
}

func queryTerms(value string) []string {
	terms := make([]string, 0)
	for _, token := range textTokens(value) {
		runes := []rune(token)
		if len(runes) <= 3 {
			terms = append(terms, token)
			continue
		}
		for start := 0; start+3 <= len(runes); start++ {
			terms = append(terms, string(runes[start:start+3]))
		}
	}
	return terms
}

func intersectPaths(current, next map[string]struct{}) map[string]struct{} {
	if current == nil {
		result := make(map[string]struct{}, len(next))
		for documentPath := range next {
			result[documentPath] = struct{}{}
		}
		return result
	}
	result := make(map[string]struct{})
	for documentPath := range current {
		if _, exists := next[documentPath]; exists {
			result[documentPath] = struct{}{}
		}
	}
	return result
}

func addLookup(index map[string]map[string]struct{}, key, documentPath string) {
	paths := index[key]
	if paths == nil {
		paths = make(map[string]struct{})
		index[key] = paths
	}
	paths[documentPath] = struct{}{}
}

func cloneLookup(input map[string]map[string]struct{}) map[string]map[string]struct{} {
	output := make(map[string]map[string]struct{}, len(input))
	for key, paths := range input {
		output[key] = intersectPaths(nil, paths)
	}
	return output
}

func (service *Service) resolveEffective(ctx context.Context, tenantID, projectID, revision string, supplied *Snapshot, stack map[string]bool) (map[string]visibleDocument, error) {
	key := projectID + "\x00" + revision
	if stack[key] {
		return nil, aorerrors.New(aorerrors.CodeConflict, "", map[string]any{"scope": "knowledge inheritance cycle"})
	}
	stack[key] = true
	defer delete(stack, key)
	var snapshot Snapshot
	var err error
	if supplied != nil {
		snapshot = cloneSnapshot(*supplied)
	} else {
		snapshot, err = service.repository.Load(ctx, tenantID, projectID, revision)
		if err != nil {
			return nil, err
		}
	}
	parents, err := validateParents(projectID, snapshot.Manifest.Parents, snapshot.Manifest.ParentOrderExplicit)
	if err != nil {
		return nil, aorerrors.New(aorerrors.CodeConflict, "", map[string]any{"scope": "parent manifest"})
	}
	inherited := make(map[string][]visibleDocument)
	for _, parent := range parents {
		parentDocuments, err := service.resolveEffective(ctx, tenantID, parent.ProjectID, parent.Revision, nil, stack)
		if err != nil {
			return nil, err
		}
		for documentPath, visible := range parentDocuments {
			inherited[documentPath] = append(inherited[documentPath], visible)
		}
	}
	overrides := make(map[string]struct{}, len(snapshot.Manifest.Overrides))
	for _, documentPath := range snapshot.Manifest.Overrides {
		normalized, err := normalizePath(documentPath)
		if err != nil || normalized != documentPath {
			return nil, aorerrors.New(aorerrors.CodeConflict, "", map[string]any{"scope": "override manifest"})
		}
		if _, duplicate := overrides[documentPath]; duplicate {
			return nil, aorerrors.New(aorerrors.CodeConflict, "", map[string]any{"scope": "override manifest"})
		}
		overrides[documentPath] = struct{}{}
	}
	result := make(map[string]visibleDocument)
	for documentPath, candidates := range inherited {
		first := candidates[0]
		conflict := false
		for _, candidate := range candidates[1:] {
			if !sameVisibleDocument(first, candidate) {
				conflict = true
				break
			}
		}
		_, ownExists := snapshot.Documents[documentPath]
		_, override := overrides[documentPath]
		if conflict && (!ownExists || !override) {
			return nil, aorerrors.New(aorerrors.CodeConflict, "", map[string]any{"scope": "parent path conflict"})
		}
		if !conflict {
			result[documentPath] = first
		}
	}
	for documentPath, document := range snapshot.Documents {
		candidates := inherited[documentPath]
		_, override := overrides[documentPath]
		if len(candidates) > 0 && !override {
			return nil, aorerrors.New(aorerrors.CodeConflict, "", map[string]any{"scope": "undeclared knowledge override"})
		}
		if len(candidates) == 0 && override {
			return nil, aorerrors.New(aorerrors.CodeConflict, "", map[string]any{"scope": "orphan knowledge override"})
		}
		for _, candidate := range candidates {
			if trustRank(document.Metadata.TrustLevel) < trustRank(candidate.Document.Metadata.TrustLevel) {
				return nil, aorerrors.New(aorerrors.CodeConflict, "", map[string]any{"scope": "trust downgrade"})
			}
		}
		sourceRevision := revision
		if supplied != nil && sourceRevision == "" {
			digest, digestErr := snapshotDigest(snapshot)
			if digestErr != nil {
				return nil, digestErr
			}
			sourceRevision = digest
		}
		result[documentPath] = visibleDocument{SourceProjectID: projectID, Revision: sourceRevision, Document: StoredDocument{Metadata: cloneMetadata(document.Metadata), Content: append([]byte(nil), document.Content...)}}
	}
	for documentPath := range overrides {
		if _, own := snapshot.Documents[documentPath]; !own {
			return nil, aorerrors.New(aorerrors.CodeConflict, "", map[string]any{"scope": "missing knowledge override"})
		}
	}
	return result, nil
}

func sameVisibleDocument(left, right visibleDocument) bool {
	return left.Document.Metadata.SHA256 == right.Document.Metadata.SHA256 &&
		left.Document.Metadata.TrustLevel == right.Document.Metadata.TrustLevel &&
		left.Document.Metadata.Title == right.Document.Metadata.Title &&
		left.Document.Metadata.ContentType == right.Document.Metadata.ContentType
}
