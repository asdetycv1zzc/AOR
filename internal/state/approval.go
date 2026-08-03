package state

import (
	"time"

	"github.com/akimisaka/aor/pkg/contracts"
)

type ApprovalBinding struct {
	RecordID       string     `json:"recordId"`
	ApprovalType   string     `json:"approvalType"`
	SubjectType    string     `json:"subjectType"`
	SubjectID      string     `json:"subjectId"`
	SubjectVersion int        `json:"subjectVersion"`
	SubjectSHA256  string     `json:"subjectSha256"`
	PrincipalID    string     `json:"principalId"`
	Reason         string     `json:"reason"`
	IssuedAt       time.Time  `json:"issuedAt"`
	ExpiresAt      *time.Time `json:"expiresAt,omitempty"`
	RevokedAt      *time.Time `json:"revokedAt,omitempty"`
	Signature      string     `json:"signature"`
}

func (a ApprovalBinding) validAt(now time.Time, actorID, approvalType, subjectType, subjectID string, subjectVersion int, subjectSHA256 string) bool {
	if a.RecordID == "" || a.ApprovalType != approvalType || a.SubjectType != subjectType || a.SubjectID != subjectID || a.SubjectVersion != subjectVersion || a.SubjectSHA256 != subjectSHA256 {
		return false
	}
	if a.PrincipalID == "" || a.PrincipalID != actorID || a.Reason == "" || a.Signature == "" || a.IssuedAt.IsZero() || a.IssuedAt.After(now) || a.RevokedAt != nil {
		return false
	}
	if a.ExpiresAt != nil && !a.ExpiresAt.After(now) {
		return false
	}
	return contracts.SpecRef{Version: a.SubjectVersion, SHA256: a.SubjectSHA256}.Validate() == nil
}
