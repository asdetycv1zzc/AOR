package knowledge

import (
	"context"
	"strings"
	"testing"

	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

func testSource(trust TrustLevel) *SourceReference {
	return &SourceReference{
		URI:      "https://docs.example/knowledge/authentication",
		Revision: "git:0123456789abcdef0123456789abcdef01234567",
		SHA256:   "sha256:" + strings.Repeat("b", 64), TrustLevel: trust,
	}
}

func TestSourceAttributionIsDigestBoundAndReturnedInReferences(t *testing.T) {
	proposal := UpdateProposal{Documents: []DocumentInput{{
		Path: "architecture/auth.md", Title: "Auth", TrustLevel: TrustCurated,
		Content: []byte("deny by default\n"), Source: testSource(TrustCurated),
	}}}
	first, err := ProposalDigest(proposal)
	if err != nil {
		t.Fatal(err)
	}
	changed := proposal
	changed.Documents = append([]DocumentInput(nil), proposal.Documents...)
	changed.Documents[0].Source = testSource(TrustSignedPolicy)
	second, err := ProposalDigest(changed)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("source attribution did not affect proposal digest")
	}

	fixture := newKnowledgeFixture(t, "project-a")
	result := commitProposal(t, fixture.service, "project-a", proposal)
	search, err := fixture.service.Search(context.Background(), SearchRequest{Access: readAccess("project-a"), Path: "architecture/auth.md"})
	if err != nil || len(search.References) != 1 || !sameSource(search.References[0].Source, proposal.Documents[0].Source) {
		t.Fatalf("source attribution was not returned: %#v err=%v", search.References, err)
	}
	if search.References[0].Revision != result.Manifest.Revision {
		t.Fatalf("reference revision mismatch: %#v", search.References[0])
	}
}

func TestDeterministicValidationReportGatesCuratedSourcesAndLinks(t *testing.T) {
	fixture := newKnowledgeFixture(t, "project-a")
	base := proposalRevision(t, fixture.service, "project-a")
	valid := UpdateProposal{BaseRevision: base, Documents: []DocumentInput{
		{Path: "architecture/auth.md", Title: "Auth", TrustLevel: TrustCurated, Content: []byte("See [policy](policy.md).\n"), Source: testSource(TrustCurated)},
		{Path: "architecture/policy.md", Title: "Policy", TrustLevel: TrustCurated, Content: []byte("deny by default\n"), Source: testSource(TrustCurated)},
	}}
	validation, err := fixture.service.ValidateProposal(context.Background(), readAccess("project-a"), valid)
	if err != nil || !validation.Report.Passed {
		t.Fatalf("valid proposal did not pass report: %#v err=%v", validation.Report, err)
	}
	if err := ValidateValidationReport(validation.Report); err != nil {
		t.Fatal(err)
	}

	missingSource := valid
	missingSource.Documents = append([]DocumentInput(nil), valid.Documents...)
	missingSource.Documents[0].Source = nil
	failed, err := fixture.service.ValidateProposal(context.Background(), readAccess("project-a"), missingSource)
	assertErrorCode(t, err, aorerrors.CodeInvalidArgument)
	if failed.Report.Passed || failed.Report.SHA256 == "" {
		t.Fatalf("missing source did not produce durable failed report: %#v", failed.Report)
	}

	brokenLink := valid
	brokenLink.Documents = append([]DocumentInput(nil), valid.Documents...)
	brokenLink.Documents[0].Content = []byte("See [missing](missing.md).\n")
	failed, err = fixture.service.ValidateProposal(context.Background(), readAccess("project-a"), brokenLink)
	assertErrorCode(t, err, aorerrors.CodeInvalidArgument)
	if failed.Report.Passed {
		t.Fatalf("broken link passed report: %#v", failed.Report)
	}
}

func TestUpdateEnforcesDeterministicValidationReport(t *testing.T) {
	fixture := newKnowledgeFixture(t, "project-a")
	missingSource := UpdateProposal{Documents: []DocumentInput{{
		Path: "architecture/auth.md", Title: "Auth", TrustLevel: TrustCurated, Content: []byte("deny by default\n"),
	}}}
	_, err := fixture.service.Update(context.Background(), curatorAccess("project-a", missingSource), missingSource)
	assertErrorCode(t, err, aorerrors.CodeInvalidArgument)
	if revision := proposalRevision(t, fixture.service, "project-a"); revision != "" {
		t.Fatalf("failed validation committed revision %s", revision)
	}

	brokenLink := UpdateProposal{Documents: []DocumentInput{{
		Path: "architecture/auth.md", Title: "Auth", TrustLevel: TrustProjectApproved, Content: []byte("See [missing](missing.md).\n"),
	}}}
	_, err = fixture.service.Update(context.Background(), curatorAccess("project-a", brokenLink), brokenLink)
	assertErrorCode(t, err, aorerrors.CodeInvalidArgument)

	lowTrust := UpdateProposal{Documents: []DocumentInput{{
		Path: "architecture/auth.md", Title: "Auth", TrustLevel: TrustProjectApproved, Content: []byte("deny by default\n"),
	}}}
	result, err := fixture.service.Update(context.Background(), curatorAccess("project-a", lowTrust), lowTrust)
	if err != nil || result.Manifest.Revision == "" {
		t.Fatalf("source-optional update failed: result=%#v err=%v", result, err)
	}
}

func TestCommittedUpdateResumeEnforcesDeterministicValidationReport(t *testing.T) {
	fixture := newKnowledgeFixture(t, "project-a")
	proposal := UpdateProposal{Documents: []DocumentInput{{
		Path: "architecture/auth.md", Title: "Auth", TrustLevel: TrustCurated, Content: []byte("deny by default\n"),
	}}}
	access := curatorAccess("project-a", proposal)
	snapshot, err := fixture.service.prepareSnapshot(context.Background(), access, proposal, knowledgeTestNow)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := fixture.repository.Commit(context.Background(), CommitRequest{
		TenantID: "tenant-1", ProjectID: "project-a", BaseRevision: proposal.BaseRevision, Snapshot: snapshot,
	})
	if err != nil || manifest.Revision == "" {
		t.Fatalf("seed commit failed: manifest=%#v err=%v", manifest, err)
	}

	_, err = fixture.service.Update(context.Background(), access, proposal)
	assertErrorCode(t, err, aorerrors.CodeInvalidArgument)
}
