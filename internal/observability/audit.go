package observability

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const zeroAuditHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

type AuditEvent struct {
	EventID        string            `json:"event_id"`
	Type           string            `json:"type"`
	ProjectID      string            `json:"project_id,omitempty"`
	TaskID         string            `json:"task_id,omitempty"`
	PrincipalID    string            `json:"principal_id"`
	ArtifactID     string            `json:"artifact_id,omitempty"`
	ApprovalID     string            `json:"approval_id,omitempty"`
	PolicyVersion  string            `json:"policy_version,omitempty"`
	EvidenceSHA256 string            `json:"evidence_sha256,omitempty"`
	TraceID        string            `json:"trace_id,omitempty"`
	Details        map[string]string `json:"details,omitempty"`
}

type TrustedTimestamp struct {
	At          time.Time
	Source      string
	Uncertainty time.Duration
}

type TrustedClock interface {
	Now(context.Context) (TrustedTimestamp, error)
}

type SystemUTCClock struct{}

func (SystemUTCClock) Now(context.Context) (TrustedTimestamp, error) {
	return TrustedTimestamp{At: time.Now().UTC(), Source: "system-utc"}, nil
}

type AuditRecord struct {
	Sequence              uint64     `json:"sequence"`
	Timestamp             time.Time  `json:"timestamp"`
	TimeSource            string     `json:"time_source"`
	TimeUncertaintyMillis int64      `json:"time_uncertainty_ms"`
	Event                 AuditEvent `json:"event"`
	PreviousHash          string     `json:"previous_hash"`
	Hash                  string     `json:"hash"`
	Signature             string     `json:"signature"`
}

type AuditFilter struct {
	ProjectID   string
	TaskID      string
	PrincipalID string
	ArtifactID  string
	ApprovalID  string
	EventType   string
}

type AuditSigner interface {
	Sign(context.Context, []byte) (string, error)
	Verify(context.Context, []byte, string) error
}

type AuditStore interface {
	AuditDestination() string
	Last(context.Context) (AuditRecord, bool, error)
	Append(context.Context, AuditRecord) error
	Query(context.Context, AuditFilter) ([]AuditRecord, error)
}

type AuditLog struct {
	store  AuditStore
	signer AuditSigner
	clock  TrustedClock
	limits Limits
	mu     sync.Mutex
}

func NewAuditLog(store AuditStore, signer AuditSigner, clock TrustedClock, limits Limits) (*AuditLog, error) {
	if store == nil || signer == nil || clock == nil || store.AuditDestination() == "" {
		return nil, ErrAuditIntegrity
	}
	return &AuditLog{store: store, signer: signer, clock: clock, limits: limits.normalized()}, nil
}

func ValidateSinkSeparation(application ApplicationSink, audit AuditStore) error {
	if application == nil || audit == nil {
		return ErrSinkNotSeparated
	}
	applicationDestination := strings.TrimSpace(application.ApplicationDestination())
	auditDestination := strings.TrimSpace(audit.AuditDestination())
	if applicationDestination == "" || auditDestination == "" || strings.EqualFold(applicationDestination, auditDestination) {
		return ErrSinkNotSeparated
	}
	return nil
}

func (l *AuditLog) Append(ctx context.Context, event AuditEvent) (AuditRecord, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.appendLocked(ctx, event)
}

func (l *AuditLog) appendLocked(ctx context.Context, event AuditEvent) (AuditRecord, error) {
	if err := validateAuditEvent(event); err != nil {
		return AuditRecord{}, err
	}
	details, _, err := sanitizeAttributes(event.Details, l.limits)
	if err != nil {
		return AuditRecord{}, err
	}
	event.Details = details
	timestamp, err := l.clock.Now(ctx)
	if err != nil {
		return AuditRecord{}, err
	}
	if timestamp.At.IsZero() || timestamp.Source == "" || timestamp.Uncertainty < 0 {
		return AuditRecord{}, ErrAuditIntegrity
	}
	last, exists, err := l.store.Last(ctx)
	if err != nil {
		return AuditRecord{}, err
	}
	record := AuditRecord{
		Sequence: 1, Timestamp: timestamp.At.UTC(), TimeSource: timestamp.Source,
		TimeUncertaintyMillis: timestamp.Uncertainty.Milliseconds(), Event: event, PreviousHash: zeroAuditHash,
	}
	if exists {
		lastDigest, lastHash, digestErr := auditRecordDigest(last)
		if digestErr != nil || lastHash != last.Hash || last.Sequence == ^uint64(0) || l.signer.Verify(ctx, lastDigest, last.Signature) != nil {
			return AuditRecord{}, ErrAuditIntegrity
		}
		if timestamp.At.Before(last.Timestamp) {
			return AuditRecord{}, ErrAuditIntegrity
		}
		record.Sequence = last.Sequence + 1
		record.PreviousHash = last.Hash
	}
	digest, hash, err := auditRecordDigest(record)
	if err != nil {
		return AuditRecord{}, err
	}
	record.Hash = hash
	record.Signature, err = l.signer.Sign(ctx, digest)
	if err != nil {
		return AuditRecord{}, err
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return AuditRecord{}, err
	}
	if len(payload) > l.limits.MaxEventBytes {
		return AuditRecord{}, ErrEventTooLarge
	}
	if err := l.store.Append(ctx, record); err != nil {
		return AuditRecord{}, err
	}
	return record, nil
}

func (l *AuditLog) Query(ctx context.Context, readerPrincipal, reason string, filter AuditFilter) ([]AuditRecord, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !opaqueIDPattern.MatchString(readerPrincipal) || !opaqueIDPattern.MatchString(reason) {
		return nil, ErrAuditIntegrity
	}
	if err := validateAuditFilter(filter); err != nil {
		return nil, err
	}
	readID, err := randomHex(12)
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	readEvent := AuditEvent{
		EventID: "read:" + readID, Type: "AUDIT_LOG_READ",
		ProjectID: filter.ProjectID, TaskID: filter.TaskID, PrincipalID: readerPrincipal,
		ArtifactID: filter.ArtifactID, ApprovalID: filter.ApprovalID,
		Details: map[string]string{"query_reason": reason, "filter_principal_id": filter.PrincipalID, "filter_event_type": filter.EventType},
	}
	if _, err := l.appendLocked(ctx, readEvent); err != nil {
		return nil, err
	}
	return l.store.Query(ctx, filter)
}

func VerifyAuditChain(ctx context.Context, records []AuditRecord, signer AuditSigner) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if signer == nil {
		return ErrAuditIntegrity
	}
	previous := zeroAuditHash
	for index, record := range records {
		if record.Sequence != uint64(index+1) || record.PreviousHash != previous || record.Hash == "" || record.Signature == "" {
			return ErrAuditIntegrity
		}
		digest, hash, err := auditRecordDigest(record)
		if err != nil || subtle.ConstantTimeCompare([]byte(hash), []byte(record.Hash)) != 1 {
			return ErrAuditIntegrity
		}
		if err := signer.Verify(ctx, digest, record.Signature); err != nil {
			return ErrAuditIntegrity
		}
		previous = record.Hash
	}
	return nil
}

func auditRecordDigest(record AuditRecord) ([]byte, string, error) {
	payload := struct {
		Sequence              uint64     `json:"sequence"`
		Timestamp             time.Time  `json:"timestamp"`
		TimeSource            string     `json:"time_source"`
		TimeUncertaintyMillis int64      `json:"time_uncertainty_ms"`
		Event                 AuditEvent `json:"event"`
		PreviousHash          string     `json:"previous_hash"`
	}{
		Sequence: record.Sequence, Timestamp: record.Timestamp, TimeSource: record.TimeSource,
		TimeUncertaintyMillis: record.TimeUncertaintyMillis, Event: record.Event, PreviousHash: record.PreviousHash,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(encoded)
	return digest[:], "sha256:" + hex.EncodeToString(digest[:]), nil
}

var (
	auditTypePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,127}$`)
	digestPattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

var securityAuditTypes = map[string]struct{}{
	"PROMPT_INJECTION_DETECTED": {}, "POLICY_BYPASS_ATTEMPT": {}, "SECRET_EXPOSURE": {},
	"CROSS_PROJECT_ACCESS_ATTEMPT": {}, "SANDBOX_ESCAPE_SUSPECTED": {}, "UNAUTHORIZED_PATH_WRITE": {},
	"ARTIFACT_HASH_MISMATCH": {}, "AGENT_CARD_SIGNATURE_INVALID": {}, "STALE_AUTHORIZATION_COMMIT_ATTEMPT": {},
	"AUDIT_EVIDENCE_TAMPER": {}, "BUDGET_LEDGER_MISMATCH": {},
}

func validateAuditEvent(event AuditEvent) error {
	if !opaqueIDPattern.MatchString(event.EventID) || !auditTypePattern.MatchString(event.Type) || !opaqueIDPattern.MatchString(event.PrincipalID) {
		return ErrAuditIntegrity
	}
	for _, value := range []string{event.ProjectID, event.TaskID, event.ArtifactID, event.ApprovalID} {
		if value != "" && !opaqueIDPattern.MatchString(value) {
			return ErrAuditIntegrity
		}
	}
	if event.EvidenceSHA256 != "" && !digestPattern.MatchString(event.EvidenceSHA256) {
		return ErrAuditIntegrity
	}
	if event.TraceID != "" && !validHexID(event.TraceID, 16) {
		return ErrAuditIntegrity
	}
	if event.PolicyVersion != "" && !opaqueIDPattern.MatchString(event.PolicyVersion) {
		return ErrAuditIntegrity
	}
	if _, security := securityAuditTypes[event.Type]; security {
		if event.ProjectID == "" || event.TaskID == "" || event.PrincipalID == "" || event.PolicyVersion == "" || event.EvidenceSHA256 == "" || event.TraceID == "" {
			return ErrAuditSecurityContext
		}
	}
	return nil
}

func validateAuditFilter(filter AuditFilter) error {
	for _, value := range []string{filter.ProjectID, filter.TaskID, filter.PrincipalID, filter.ArtifactID, filter.ApprovalID} {
		if value != "" && !opaqueIDPattern.MatchString(value) {
			return ErrAuditIntegrity
		}
	}
	if filter.EventType != "" && !auditTypePattern.MatchString(filter.EventType) {
		return ErrAuditIntegrity
	}
	return nil
}

type HMACAuditSigner struct {
	key []byte
}

func NewHMACAuditSigner(key []byte) (*HMACAuditSigner, error) {
	if len(key) < 32 {
		return nil, ErrAuditIntegrity
	}
	return &HMACAuditSigner{key: append([]byte(nil), key...)}, nil
}

func (s *HMACAuditSigner) Sign(_ context.Context, digest []byte) (string, error) {
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write(digest)
	return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil)), nil
}

func (s *HMACAuditSigner) Verify(_ context.Context, digest []byte, signature string) error {
	if !strings.HasPrefix(signature, "hmac-sha256:") {
		return ErrAuditIntegrity
	}
	provided, err := hex.DecodeString(strings.TrimPrefix(signature, "hmac-sha256:"))
	if err != nil {
		return ErrAuditIntegrity
	}
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write(digest)
	if !hmac.Equal(mac.Sum(nil), provided) {
		return ErrAuditIntegrity
	}
	return nil
}

type MemoryAuditStore struct {
	Destination string
	mu          sync.Mutex
	records     []AuditRecord
}

func (s *MemoryAuditStore) AuditDestination() string {
	return s.Destination
}

func (s *MemoryAuditStore) Last(_ context.Context) (AuditRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.records) == 0 {
		return AuditRecord{}, false, nil
	}
	return cloneAuditRecord(s.records[len(s.records)-1]), true, nil
}

func (s *MemoryAuditStore) Append(_ context.Context, record AuditRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.records) == 0 {
		if record.Sequence != 1 || record.PreviousHash != zeroAuditHash {
			return ErrAuditIntegrity
		}
	} else {
		last := s.records[len(s.records)-1]
		if record.Sequence != last.Sequence+1 || record.PreviousHash != last.Hash {
			return ErrAuditIntegrity
		}
	}
	s.records = append(s.records, cloneAuditRecord(record))
	return nil
}

func (s *MemoryAuditStore) Query(_ context.Context, filter AuditFilter) ([]AuditRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return filterAuditRecords(s.records, filter), nil
}

func (s *MemoryAuditStore) Records() []AuditRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return filterAuditRecords(s.records, AuditFilter{})
}

type FileAuditStore struct {
	path        string
	destination string
	mu          sync.Mutex
}

func NewFileAuditStore(path, destination string) (*FileAuditStore, error) {
	if path == "" || destination == "" {
		return nil, ErrAuditIntegrity
	}
	return &FileAuditStore{path: path, destination: destination}, nil
}

func (s *FileAuditStore) AuditDestination() string {
	return s.destination
}

func (s *FileAuditStore) Last(ctx context.Context) (AuditRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	records, err := s.readLocked(ctx)
	if err != nil || len(records) == 0 {
		return AuditRecord{}, false, err
	}
	return records[len(records)-1], true, nil
}

func (s *FileAuditStore) Append(ctx context.Context, record AuditRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	records, err := s.readLocked(ctx)
	if err != nil {
		return err
	}
	if len(records) == 0 {
		if record.Sequence != 1 || record.PreviousHash != zeroAuditHash {
			return ErrAuditIntegrity
		}
	} else {
		last := records[len(records)-1]
		if record.Sequence != last.Sequence+1 || record.PreviousHash != last.Hash {
			return ErrAuditIntegrity
		}
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		return err
	}
	return file.Sync()
}

func (s *FileAuditStore) Query(ctx context.Context, filter AuditFilter) ([]AuditRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	records, err := s.readLocked(ctx)
	if err != nil {
		return nil, err
	}
	return filterAuditRecords(records, filter), nil
}

func (s *FileAuditStore) readLocked(ctx context.Context) ([]AuditRecord, error) {
	file, err := os.Open(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, ErrAuditIntegrity
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), DefaultLimits().MaxEventBytes+1024)
	records := []AuditRecord{}
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		var record AuditRecord
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return nil, ErrAuditIntegrity
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

func filterAuditRecords(records []AuditRecord, filter AuditFilter) []AuditRecord {
	result := make([]AuditRecord, 0)
	for _, record := range records {
		if filter.ProjectID != "" && record.Event.ProjectID != filter.ProjectID {
			continue
		}
		if filter.TaskID != "" && record.Event.TaskID != filter.TaskID {
			continue
		}
		if filter.PrincipalID != "" && record.Event.PrincipalID != filter.PrincipalID {
			continue
		}
		if filter.ArtifactID != "" && record.Event.ArtifactID != filter.ArtifactID {
			continue
		}
		if filter.ApprovalID != "" && record.Event.ApprovalID != filter.ApprovalID {
			continue
		}
		if filter.EventType != "" && record.Event.Type != filter.EventType {
			continue
		}
		result = append(result, cloneAuditRecord(record))
	}
	return result
}

func cloneAuditRecord(record AuditRecord) AuditRecord {
	copyRecord := record
	copyRecord.Event.Details = cloneStrings(record.Event.Details)
	return copyRecord
}
