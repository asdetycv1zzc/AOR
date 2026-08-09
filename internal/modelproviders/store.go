package modelproviders

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	maximumAPIKeyBytes = 64 * 1024
	maximumModels      = 128
)

type Store struct {
	database *sql.DB
	aead     cipher.AEAD
	clock    func() time.Time
}

var _ SettingsStore = (*Store)(nil)

func NewPostgresStore(database *sql.DB, masterKey []byte) (*Store, error) {
	if database == nil || len(masterKey) != 32 {
		return nil, ErrInvalidSettings
	}
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, ErrInvalidSettings
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrInvalidSettings
	}
	return &Store{database: database, aead: aead, clock: time.Now}, nil
}

func (store *Store) List(ctx context.Context, tenantID string) ([]ProviderSettings, error) {
	if err := validateContextTenant(ctx, tenantID); err != nil {
		return nil, err
	}
	tx, err := store.begin(ctx, tenantID, true)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `
SELECT provider_id, provider, base_url, protocol, enabled, models_jsonb, version,
       input_micros_per_token, output_micros_per_token,
       api_key_ciphertext IS NOT NULL
FROM tenant_model_provider_settings
WHERE tenant_id = $1::uuid
ORDER BY provider_id`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	configured := make(map[string]ProviderSettings, 4)
	for rows.Next() {
		var id, provider, baseURL string
		var protocol Protocol
		var enabled, hasAPIKey bool
		var encoded []byte
		var version, inputMicros, outputMicros int64
		if err := rows.Scan(&id, &provider, &baseURL, &protocol, &enabled, &encoded, &version, &inputMicros, &outputMicros, &hasAPIKey); err != nil {
			return nil, err
		}
		settings, err := settingsFromCatalog(id, provider, baseURL, protocol, enabled, encoded, version, inputMicros, outputMicros)
		if err != nil {
			return nil, err
		}
		settings.APIKeyConfigured = hasAPIKey
		configured[id] = settings
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	result := make([]ProviderSettings, 0, len(Catalog()))
	for _, provider := range Catalog() {
		settings, found := configured[provider.ID]
		if !found {
			settings = defaultSettings(provider)
		}
		result = append(result, settings)
	}
	return result, nil
}

func (store *Store) Get(ctx context.Context, tenantID, providerID string) (ProviderSettings, bool, error) {
	if err := validateContextTenant(ctx, tenantID); err != nil || !safeProviderID(providerID) {
		if err == nil {
			err = ErrInvalidSettings
		}
		return ProviderSettings{}, false, err
	}
	tx, err := store.begin(ctx, tenantID, true)
	if err != nil {
		return ProviderSettings{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	var id, provider, baseURL string
	var protocol Protocol
	var enabled bool
	var encoded []byte
	var version, inputMicros, outputMicros int64
	var configured bool
	err = tx.QueryRowContext(ctx, `
SELECT provider_id, provider, base_url, protocol, enabled, models_jsonb, version,
       input_micros_per_token, output_micros_per_token,
       api_key_ciphertext IS NOT NULL
FROM tenant_model_provider_settings
WHERE tenant_id = $1::uuid AND provider_id = $2`, tenantID, providerID).
		Scan(&id, &provider, &baseURL, &protocol, &enabled, &encoded, &version, &inputMicros, &outputMicros, &configured)
	if errors.Is(err, sql.ErrNoRows) {
		if commitErr := tx.Commit(); commitErr != nil {
			return ProviderSettings{}, false, commitErr
		}
		catalog, _ := findCatalog(providerID)
		return defaultSettings(catalog), true, nil
	}
	if err != nil {
		return ProviderSettings{}, false, err
	}
	settings, err := settingsFromCatalog(id, provider, baseURL, protocol, enabled, encoded, version, inputMicros, outputMicros)
	if err != nil {
		return ProviderSettings{}, false, err
	}
	settings.APIKeyConfigured = configured
	if err := tx.Commit(); err != nil {
		return ProviderSettings{}, false, err
	}
	return settings, true, nil
}

func (store *Store) Resolve(ctx context.Context, tenantID, providerID string) (ResolvedSettings, bool, error) {
	if err := validateContextTenant(ctx, tenantID); err != nil || !safeProviderID(providerID) {
		if err == nil {
			err = ErrInvalidSettings
		}
		return ResolvedSettings{}, false, err
	}
	tx, err := store.begin(ctx, tenantID, true)
	if err != nil {
		return ResolvedSettings{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	var id, provider, baseURL string
	var protocol Protocol
	var enabled bool
	var encoded, nonce, ciphertext []byte
	var version, inputMicros, outputMicros int64
	err = tx.QueryRowContext(ctx, `
SELECT provider_id, provider, base_url, protocol, enabled, models_jsonb, api_key_nonce,
       api_key_ciphertext, version, input_micros_per_token,
       output_micros_per_token
FROM tenant_model_provider_settings
WHERE tenant_id = $1::uuid AND provider_id = $2`, tenantID, providerID).
		Scan(&id, &provider, &baseURL, &protocol, &enabled, &encoded, &nonce, &ciphertext, &version, &inputMicros, &outputMicros)
	if errors.Is(err, sql.ErrNoRows) {
		if commitErr := tx.Commit(); commitErr != nil {
			return ResolvedSettings{}, false, commitErr
		}
		return ResolvedSettings{}, false, nil
	}
	if err != nil {
		return ResolvedSettings{}, false, err
	}
	if !enabled || len(nonce) == 0 || len(ciphertext) == 0 {
		if commitErr := tx.Commit(); commitErr != nil {
			return ResolvedSettings{}, false, commitErr
		}
		return ResolvedSettings{}, false, nil
	}
	if len(nonce) != store.aead.NonceSize() || len(ciphertext) == 0 {
		return ResolvedSettings{}, false, ErrAPIKeyUnavailable
	}
	key, err := store.aead.Open(nil, nonce, ciphertext, associatedData(tenantID, id, version))
	if err != nil || len(key) == 0 {
		return ResolvedSettings{}, false, ErrAPIKeyUnavailable
	}
	settings, err := settingsFromCatalog(id, provider, baseURL, protocol, enabled, encoded, version, inputMicros, outputMicros)
	if err != nil {
		return ResolvedSettings{}, false, err
	}
	settings.APIKeyConfigured = true
	if err := tx.Commit(); err != nil {
		return ResolvedSettings{}, false, err
	}
	return ResolvedSettings{ProviderSettings: settings, APIKey: string(key)}, true, nil
}

func (store *Store) Put(ctx context.Context, tenantID, providerID string, request PutRequest) (ProviderSettings, error) {
	if err := validateContextTenant(ctx, tenantID); err != nil {
		return ProviderSettings{}, err
	}
	catalog, found := findCatalog(providerID)
	if request.Protocol == "" {
		request.Protocol = catalog.Protocol
	}
	invalidURL := request.BaseURL != "" && validateURL(request.BaseURL) != nil
	if !found || !safeProviderID(providerID) || !validProtocol(catalog, request.Protocol) || invalidURL || request.Enabled && request.BaseURL == "" || !validAPIKey(request.APIKey) && request.APIKey != "" {
		return ProviderSettings{}, ErrInvalidSettings
	}
	models := normalizedModels(catalog, nil)
	if len(models) == 0 || len(models) > maximumModels {
		return ProviderSettings{}, ErrInvalidSettings
	}
	tx, err := store.begin(ctx, tenantID, false)
	if err != nil {
		return ProviderSettings{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var oldNonce, oldCipher []byte
	var oldVersion int64
	err = tx.QueryRowContext(ctx, `
SELECT api_key_nonce, api_key_ciphertext, version
FROM tenant_model_provider_settings
WHERE tenant_id = $1::uuid AND provider_id = $2
FOR UPDATE`, tenantID, providerID).Scan(&oldNonce, &oldCipher, &oldVersion)
	existing := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return ProviderSettings{}, err
	}
	if !existing && request.Enabled && request.APIKey == "" {
		return ProviderSettings{}, ErrAPIKeyUnavailable
	}
	nonce, ciphertext := oldNonce, oldCipher
	nextVersion := oldVersion + 1
	if !existing {
		nextVersion = 1
	}
	if request.APIKey != "" {
		nonce = make([]byte, store.aead.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return ProviderSettings{}, err
		}
		ciphertext = store.aead.Seal(nil, nonce, []byte(request.APIKey), associatedData(tenantID, providerID, nextVersion))
	} else if len(oldNonce) != 0 && len(oldCipher) != 0 {
		key, openErr := store.aead.Open(nil, oldNonce, oldCipher, associatedData(tenantID, providerID, oldVersion))
		if openErr != nil || len(key) == 0 {
			return ProviderSettings{}, ErrAPIKeyUnavailable
		}
		nonce = make([]byte, store.aead.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return ProviderSettings{}, err
		}
		ciphertext = store.aead.Seal(nil, nonce, key, associatedData(tenantID, providerID, nextVersion))
		clearBytes(key)
	} else if request.Enabled {
		return ProviderSettings{}, ErrAPIKeyUnavailable
	} else {
		nonce, ciphertext = nil, nil
	}
	encoded, err := json.Marshal(models)
	if err != nil {
		return ProviderSettings{}, err
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO tenant_model_provider_settings
  (tenant_id, provider_id, provider, base_url, protocol, enabled, models_jsonb, api_key_nonce,
   api_key_ciphertext, version, input_micros_per_token, output_micros_per_token,
   updated_at)
VALUES ($1::uuid, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10, 1, 4, $11)
ON CONFLICT (tenant_id, provider_id) DO UPDATE SET
  provider = EXCLUDED.provider,
  base_url = EXCLUDED.base_url,
  protocol = EXCLUDED.protocol,
  enabled = EXCLUDED.enabled,
  models_jsonb = EXCLUDED.models_jsonb,
  api_key_nonce = EXCLUDED.api_key_nonce,
  api_key_ciphertext = EXCLUDED.api_key_ciphertext,
  version = EXCLUDED.version,
  updated_at = EXCLUDED.updated_at`, tenantID, providerID, catalog.ID, request.BaseURL, request.Protocol, request.Enabled, encoded, nonce, ciphertext, nextVersion, store.clock().UTC())
	if err != nil {
		return ProviderSettings{}, err
	}
	if err := tx.Commit(); err != nil {
		return ProviderSettings{}, err
	}
	settings, err := settingsFromCatalog(providerID, catalog.ID, request.BaseURL, request.Protocol, request.Enabled, encoded, nextVersion, 1, 4)
	if err != nil {
		return ProviderSettings{}, err
	}
	settings.APIKeyConfigured = len(ciphertext) != 0
	return settings, nil
}

func (store *Store) begin(ctx context.Context, tenantID string, readOnly bool) (*sql.Tx, error) {
	if store == nil || store.database == nil || store.aead == nil || ctx == nil || !validTenantID(tenantID) {
		return nil, ErrStoreUnavailable
	}
	tx, err := store.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: readOnly})
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('aor.tenant_id', $1, true)`, tenantID); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return tx, nil
}

func validateContextTenant(ctx context.Context, tenantID string) error {
	if ctx == nil || !validTenantID(tenantID) {
		return ErrInvalidSettings
	}
	return nil
}

func validTenantID(value string) bool {
	_, err := uuid.Parse(value)
	return err == nil
}

func safeProviderID(value string) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	_, found := findCatalog(value)
	return found
}

func validAPIKey(value string) bool {
	return value != "" && len(value) <= maximumAPIKeyBytes && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n\x00")
}

func normalizedModels(catalog ProviderCatalog, requested []string) []string {
	allowed := make(map[string]struct{}, len(catalog.Models))
	for _, model := range catalog.Models {
		allowed[model.ID] = struct{}{}
	}
	if len(requested) == 0 {
		requested = make([]string, 0, len(catalog.Models))
		for _, model := range catalog.Models {
			requested = append(requested, model.ID)
		}
	}
	seen := make(map[string]struct{}, len(requested))
	result := make([]string, 0, len(requested))
	for _, model := range requested {
		if _, ok := allowed[model]; !ok || model == "" || len(model) > 256 || strings.TrimSpace(model) != model {
			return nil
		}
		if _, duplicate := seen[model]; duplicate {
			return nil
		}
		seen[model] = struct{}{}
		result = append(result, model)
	}
	return result
}

func settingsFromCatalog(id, provider, baseURL string, protocol Protocol, enabled bool, encoded []byte, version, inputMicros, outputMicros int64) (ProviderSettings, error) {
	catalog, found := findCatalog(provider)
	if !found || !validProtocol(catalog, protocol) {
		return ProviderSettings{}, ErrInvalidSettings
	}
	var models []string
	if json.Unmarshal(encoded, &models) != nil || len(models) == 0 || normalizedModels(catalog, models) == nil {
		return ProviderSettings{}, ErrInvalidSettings
	}
	capability := modelCapabilities(catalog.Models[0])
	for _, model := range catalog.Models {
		if model.ID == models[0] {
			capability = modelCapabilities(model)
			break
		}
	}
	return ProviderSettings{
		ID: id, DisplayName: catalog.DisplayName, Provider: catalog.ID, BaseURL: baseURL,
		Protocol: protocol, Protocols: append([]Protocol(nil), catalog.Protocols...), Enabled: enabled,
		Models:              append([]string(nil), models...),
		InputMicrosPerToken: inputMicros, OutputMicrosPerToken: outputMicros,
		SupportsStreaming: capability.SupportsStreaming, SupportsToolCalls: capability.SupportsToolCalls,
		SupportsJSONSchema: capability.SupportsJSONSchema, SupportsSeed: capability.SupportsSeed,
		SupportsPromptCaching: capability.SupportsPromptCaching, MaxInputTokens: capability.MaxInputTokens,
		MaxOutputTokens: capability.MaxOutputTokens, AllowedDataClassifications: []string{"PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"},
		DataResidency: []string{"provider-defined"}, RetentionPolicy: "provider-defined", Modalities: []string{"text"}, Version: version,
	}, nil
}

func defaultSettings(catalog ProviderCatalog) ProviderSettings {
	models := make([]string, 0, len(catalog.Models))
	for _, model := range catalog.Models {
		models = append(models, model.ID)
	}
	encoded, _ := json.Marshal(models)
	settings, _ := settingsFromCatalog(catalog.ID, catalog.ID, "", catalog.Protocol, false, encoded, 0, 1, 4)
	return settings
}

func associatedData(tenantID, providerID string, version int64) []byte {
	return []byte(tenantID + "\x00" + providerID + "\x00" + formatVersion(version))
}

func formatVersion(value int64) string {
	return strconv.FormatInt(value, 10)
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
