package conformance

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const targetResponseLimit = 64 << 10

type targetExchangeEvidence struct {
	EvidenceVersion string                 `json:"evidenceVersion"`
	Request         targetEvidenceRequest  `json:"request"`
	Response        targetEvidenceResponse `json:"response"`
	TLS             *targetTLSEvidence     `json:"tls,omitempty"`
}

type targetEvidenceRequest struct {
	Method  string              `json:"method"`
	URL     string              `json:"url"`
	Headers map[string][]string `json:"headers"`
}

type targetEvidenceResponse struct {
	StatusCode int                 `json:"statusCode"`
	Headers    map[string][]string `json:"headers"`
	BodyBase64 string              `json:"bodyBase64"`
}

type targetTLSEvidence struct {
	ServerName            string   `json:"serverName"`
	Version               uint16   `json:"version"`
	CipherSuite           uint16   `json:"cipherSuite"`
	PeerCertificateSHA256 []string `json:"peerCertificateSha256"`
}

type targetHealth struct {
	Component string `json:"component"`
	Status    string `json:"status"`
}

type targetVersion struct {
	Component       string `json:"component"`
	Version         string `json:"version"`
	Commit          string `json:"commit"`
	SpecVersion     string `json:"specVersion"`
	ProductionReady bool   `json:"productionReady"`
}

func newTargetHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func normalizeTarget(raw, profile string) (string, error) {
	if strings.TrimSpace(raw) != raw || raw == "" || strings.ContainsRune(raw, 0) {
		return "", ErrInvalidRequest
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.IsAbs() == false || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" {
		return "", ErrInvalidRequest
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" || profile == "production" && parsed.Scheme != "https" {
		return "", ErrInvalidRequest
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	parsed.RawPath = ""
	return parsed.String(), nil
}

func (r *Runner) probeTarget(ctx context.Context, request Request) ([]string, error) {
	if request.OutputDir == "" {
		return nil, errors.New("raw evidence output directory is required")
	}
	traceparent, requestID, err := targetCorrelation()
	if err != nil {
		return nil, errors.New("request correlation generation failed")
	}
	healthURL, err := url.JoinPath(request.Target, "health", "ready")
	if err != nil {
		return nil, errors.New("health endpoint is invalid")
	}
	healthEvidence, healthBody, err := r.targetGET(ctx, healthURL, traceparent, requestID, request.Profile)
	if err != nil {
		return nil, fmt.Errorf("readiness probe failed: %w", err)
	}
	healthReference, err := writeTargetEvidence(request.OutputDir, "target-health.json", healthEvidence)
	if err != nil {
		return nil, fmt.Errorf("readiness evidence: %w", err)
	}
	var health targetHealth
	if err := decodeTargetJSON(healthBody, &health); err != nil || health.Component == "" || health.Status != "ready" {
		return []string{healthReference}, errors.New("readiness response is invalid")
	}

	traceparent, requestID, err = targetCorrelation()
	if err != nil {
		return []string{healthReference}, errors.New("request correlation generation failed")
	}
	versionURL, err := url.JoinPath(request.Target, "version")
	if err != nil {
		return []string{healthReference}, errors.New("version endpoint is invalid")
	}
	versionEvidence, versionBody, err := r.targetGET(ctx, versionURL, traceparent, requestID, request.Profile)
	if err != nil {
		return []string{healthReference}, fmt.Errorf("version probe failed: %w", err)
	}
	versionReference, err := writeTargetEvidence(request.OutputDir, "target-version.json", versionEvidence)
	if err != nil {
		return []string{healthReference}, fmt.Errorf("version evidence: %w", err)
	}
	var identity targetVersion
	if err := decodeTargetJSON(versionBody, &identity); err != nil || identity.Component == "" || identity.Component != health.Component || identity.SpecVersion != request.SpecVersion || identity.Version != request.ReleaseVersion || request.SourceCommit != "unknown" && identity.Commit != request.SourceCommit {
		return []string{healthReference, versionReference}, errors.New("target build identity does not match the requested release")
	}
	return []string{healthReference, versionReference}, nil
}

func (r *Runner) targetGET(ctx context.Context, endpoint, traceparent, requestID, profile string) (targetExchangeEvidence, []byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return targetExchangeEvidence{}, nil, errors.New("request is invalid")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("Traceparent", traceparent)
	request.Header.Set("X-Request-ID", requestID)
	request.Header.Set("User-Agent", "aor-conformance/2.0.0")

	client := r.client
	if client == nil {
		client = newTargetHTTPClient()
	}
	bounded := *client
	bounded.Timeout = 10 * time.Second
	bounded.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	response, err := bounded.Do(request)
	if err != nil {
		return targetExchangeEvidence{}, nil, errors.New("target request failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, targetResponseLimit+1))
	if err != nil || len(body) > targetResponseLimit {
		return targetExchangeEvidence{}, nil, errors.New("target response exceeds the evidence limit")
	}
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode != http.StatusOK || mediaErr != nil || mediaType != "application/json" {
		return targetExchangeEvidence{}, nil, errors.New("target returned an invalid HTTP response")
	}
	if profile == "production" && (response.TLS == nil || len(response.TLS.VerifiedChains) == 0) {
		return targetExchangeEvidence{}, nil, errors.New("production target did not provide a verified TLS identity")
	}
	evidence := targetExchangeEvidence{
		EvidenceVersion: "1.0",
		Request: targetEvidenceRequest{
			Method:  request.Method,
			URL:     request.URL.String(),
			Headers: evidenceHeaders(request.Header),
		},
		Response: targetEvidenceResponse{
			StatusCode: response.StatusCode,
			Headers:    evidenceHeaders(response.Header),
			BodyBase64: base64.StdEncoding.EncodeToString(body),
		},
	}
	if response.TLS != nil {
		tlsEvidence := &targetTLSEvidence{ServerName: response.TLS.ServerName, Version: response.TLS.Version, CipherSuite: response.TLS.CipherSuite}
		for _, certificate := range response.TLS.PeerCertificates {
			digest := sha256.Sum256(certificate.Raw)
			tlsEvidence.PeerCertificateSHA256 = append(tlsEvidence.PeerCertificateSHA256, "sha256:"+hex.EncodeToString(digest[:]))
		}
		evidence.TLS = tlsEvidence
	}
	return evidence, body, nil
}

func targetCorrelation() (string, string, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", "", err
	}
	traceparent := "00-" + hex.EncodeToString(value[:16]) + "-" + hex.EncodeToString(value[16:24]) + "-01"
	return traceparent, hex.EncodeToString(value[24:]), nil
}

func evidenceHeaders(header http.Header) map[string][]string {
	result := map[string][]string{}
	for _, name := range []string{"Accept", "Accept-Encoding", "Content-Type", "Date", "Traceparent", "Tracestate", "User-Agent", "X-Request-ID"} {
		if values := header.Values(name); len(values) > 0 {
			result[http.CanonicalHeaderKey(name)] = append([]string(nil), values...)
		}
	}
	return result
}

func decodeTargetJSON(value []byte, destination any) error {
	decoder := json.NewDecoder(strings.NewReader(string(value)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalidRequest
	}
	return nil
}

func writeTargetEvidence(outputDirectory, name string, evidence targetExchangeEvidence) (string, error) {
	rawDirectory := filepath.Join(outputDirectory, "raw")
	if err := os.MkdirAll(rawDirectory, 0o700); err != nil {
		return "", err
	}
	info, err := os.Lstat(rawDirectory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", ErrInvalidRequest
	}
	encoded, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return "", err
	}
	encoded = append(encoded, '\n')
	temporary, err := os.CreateTemp(rawDirectory, ".target-evidence-*.tmp")
	if err != nil {
		return "", err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return "", err
	}
	if _, err := temporary.Write(encoded); err != nil {
		temporary.Close()
		return "", err
	}
	if err := temporary.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(temporaryName, filepath.Join(rawDirectory, name)); err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return "file:raw/" + name + "#sha256=" + hex.EncodeToString(digest[:]), nil
}
