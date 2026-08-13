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
SELECT provider_id, provider, display_name, base_url, protocol, enabled, models_jsonb,
       model_context_windows_jsonb, version,
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
	custom := make([]ProviderSettings, 0)
	for rows.Next() {
		var id, provider, displayName, baseURL string
		var protocol Protocol
		var enabled, hasAPIKey bool
		var encoded []byte
		var encodedContextWindows []byte
		var version, inputMicros, outputMicros int64
		if err := rows.Scan(&id, &provider, &displayName, &baseURL, &protocol, &enabled, &encoded, &encodedContextWindows, &version, &inputMicros, &outputMicros, &hasAPIKey); err != nil {
			return nil, err
		}
		settings, err := settingsFromStored(id, provider, displayName, baseURL, protocol, enabled, encoded, encodedContextWindows, version, inputMicros, outputMicros)
		if err != nil {
			return nil, err
		}
		settings.APIKeyConfigured = hasAPIKey
		if settings.Custom {
			custom = append(custom, settings)
		} else {
			configured[id] = settings
		}
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
	result := make([]ProviderSettings, 0, len(Catalog())+len(custom))
	for _, provider := range Catalog() {
		settings, found := configured[provider.ID]
		if !found {
			settings = defaultSettings(provider)
		}
		result = append(result, settings)
	}
	result = append(result, custom...)
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
	var id, provider, displayName, baseURL string
	var protocol Protocol
	var enabled bool
	var encoded []byte
	var encodedContextWindows []byte
	var version, inputMicros, outputMicros int64
	var configured bool
	err = tx.QueryRowContext(ctx, `
SELECT provider_id, provider, display_name, base_url, protocol, enabled, models_jsonb,
       model_context_windows_jsonb, version,
       input_micros_per_token, output_micros_per_token,
       api_key_ciphertext IS NOT NULL
FROM tenant_model_provider_settings
WHERE tenant_id = $1::uuid AND provider_id = $2`, tenantID, providerID).
		Scan(&id, &provider, &displayName, &baseURL, &protocol, &enabled, &encoded, &encodedContextWindows, &version, &inputMicros, &outputMicros, &configured)
	if errors.Is(err, sql.ErrNoRows) {
		if commitErr := tx.Commit(); commitErr != nil {
			return ProviderSettings{}, false, commitErr
		}
		catalog, found := findCatalog(providerID)
		if !found {
			return ProviderSettings{}, false, nil
		}
		return defaultSettings(catalog), true, nil
	}
	if err != nil {
		return ProviderSettings{}, false, err
	}
	settings, err := settingsFromStored(id, provider, displayName, baseURL, protocol, enabled, encoded, encodedContextWindows, version, inputMicros, outputMicros)
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
	var id, provider, displayName, baseURL string
	var protocol Protocol
	var enabled bool
	var encoded, encodedContextWindows, nonce, ciphertext []byte
	var version, inputMicros, outputMicros int64
	err = tx.QueryRowContext(ctx, `
SELECT provider_id, provider, display_name, base_url, protocol, enabled, models_jsonb,
       model_context_windows_jsonb, api_key_nonce, api_key_ciphertext, version, input_micros_per_token,
       output_micros_per_token
FROM tenant_model_provider_settings
WHERE tenant_id = $1::uuid AND provider_id = $2`, tenantID, providerID).
		Scan(&id, &provider, &displayName, &baseURL, &protocol, &enabled, &encoded, &encodedContextWindows, &nonce, &ciphertext, &version, &inputMicros, &outputMicros)
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
	settings, err := settingsFromStored(id, provider, displayName, baseURL, protocol, enabled, encoded, encodedContextWindows, version, inputMicros, outputMicros)
	if err != nil {
		return ResolvedSettings{}, false, err
	}
	settings.APIKeyConfigured = true
	if err := tx.Commit(); err != nil {
		return ResolvedSettings{}, false, err
	}
	apiKey := string(key)
	clearBytes(key)
	return ResolvedSettings{ProviderSettings: settings, APIKey: apiKey}, true, nil
}

func (store *Store) Put(ctx context.Context, tenantID, providerID string, request PutRequest) (ProviderSettings, error) {
	if err := validateContextTenant(ctx, tenantID); err != nil {
		return ProviderSettings{}, err
	}
	catalog, found := findCatalog(providerID)
	if request.Protocol == "" {
		if found {
			request.Protocol = catalog.Protocol
		} else {
			request.Protocol = ProtocolOpenAICompatible
		}
	}
	invalidURL := request.BaseURL != "" && validateURL(request.BaseURL) != nil
	if !safeProviderID(providerID) || !validProtocolValue(request.Protocol) || invalidURL || request.Enabled && request.BaseURL == "" || !validAPIKey(request.APIKey) && request.APIKey != "" {
		return ProviderSettings{}, ErrInvalidSettings
	}
	displayName := catalog.DisplayName
	models := normalizedModels(catalog, nil)
	if !found {
		displayName = strings.TrimSpace(request.DisplayName)
		models = normalizedCustomModels(request.Models)
	}
	if found && request.ModelContextWindowTokens != nil {
		catalogWindows := make(map[string]int, len(catalog.Models))
		for _, model := range catalog.Models {
			catalogWindows[model.ID] = model.ContextWindow
		}
		if !equalContextWindows(catalogWindows, request.ModelContextWindowTokens) {
			return ProviderSettings{}, ErrInvalidSettings
		}
	}
	if displayName == "" || len(displayName) > 128 || strings.ContainsAny(displayName, "\r\n\x00") || len(models) == 0 || len(models) > maximumModels {
		return ProviderSettings{}, ErrInvalidSettings
	}
	tx, err := store.begin(ctx, tenantID, false)
	if err != nil {
		return ProviderSettings{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var oldNonce, oldCipher, oldContextWindows []byte
	var oldVersion int64
	err = tx.QueryRowContext(ctx, `
SELECT api_key_nonce, api_key_ciphertext, model_context_windows_jsonb, version
FROM tenant_model_provider_settings
WHERE tenant_id = $1::uuid AND provider_id = $2
FOR UPDATE`, tenantID, providerID).Scan(&oldNonce, &oldCipher, &oldContextWindows, &oldVersion)
	existing := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return ProviderSettings{}, err
	}
	if !existing && request.Enabled && request.APIKey == "" {
		return ProviderSettings{}, ErrAPIKeyUnavailable
	}
	if !found && request.ModelContextWindowTokens == nil && existing {
		if json.Unmarshal(oldContextWindows, &request.ModelContextWindowTokens) != nil {
			return ProviderSettings{}, ErrInvalidSettings
		}
	}
	if !found && existing && !sameModelSet(models, request.ModelContextWindowTokens) {
		return ProviderSettings{}, ErrInvalidSettings
	}
	if !found && !validContextWindows(models, request.ModelContextWindowTokens) {
		return ProviderSettings{}, ErrInvalidSettings
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
	contextWindows := make(map[string]int, len(models))
	if found {
		for _, model := range catalog.Models {
			contextWindows[model.ID] = model.ContextWindow
		}
	} else {
		contextWindows = cloneContextWindows(request.ModelContextWindowTokens)
	}
	encodedContextWindows, err := json.Marshal(contextWindows)
	if err != nil {
		return ProviderSettings{}, err
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO tenant_model_provider_settings
	  (tenant_id, provider_id, provider, display_name, base_url, protocol, enabled, models_jsonb,
	   model_context_windows_jsonb, api_key_nonce,
	   api_key_ciphertext, version, input_micros_per_token, output_micros_per_token,
	   updated_at)
VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8::jsonb, $9::jsonb, $10, $11, $12, 1, 4, $13)
ON CONFLICT (tenant_id, provider_id) DO UPDATE SET
	  provider = EXCLUDED.provider,
	  display_name = EXCLUDED.display_name,
	  base_url = EXCLUDED.base_url,
  protocol = EXCLUDED.protocol,
  enabled = EXCLUDED.enabled,
  models_jsonb = EXCLUDED.models_jsonb,
  model_context_windows_jsonb = EXCLUDED.model_context_windows_jsonb,
  api_key_nonce = EXCLUDED.api_key_nonce,
  api_key_ciphertext = EXCLUDED.api_key_ciphertext,
  version = EXCLUDED.version,
	  updated_at = EXCLUDED.updated_at`, tenantID, providerID, providerID, displayName, request.BaseURL, request.Protocol, request.Enabled, encoded, encodedContextWindows, nonce, ciphertext, nextVersion, store.clock().UTC())
	if err != nil {
		return ProviderSettings{}, err
	}
	if err := tx.Commit(); err != nil {
		return ProviderSettings{}, err
	}
	settings, err := settingsFromStored(providerID, providerID, displayName, request.BaseURL, request.Protocol, request.Enabled, encoded, encodedContextWindows, nextVersion, 1, 4)
	if err != nil {
		return ProviderSettings{}, err
	}
	settings.APIKeyConfigured = len(ciphertext) != 0
	return settings, nil
}

func validContextWindows(models []string, windows map[string]int) bool {
	if len(windows) != len(models) {
		return false
	}
	allowed := make(map[string]struct{}, len(models))
	for _, model := range models {
		allowed[model] = struct{}{}
		window, found := windows[model]
		if !found || window < 1 || window > 10_000_000 {
			return false
		}
	}
	for model := range windows {
		if _, found := allowed[model]; !found {
			return false
		}
	}
	return true
}

func sameModelSet(models []string, windows map[string]int) bool {
	if len(models) != len(windows) {
		return false
	}
	for _, model := range models {
		if _, found := windows[model]; !found {
			return false
		}
	}
	return true
}

func cloneContextWindows(windows map[string]int) map[string]int {
	cloned := make(map[string]int, len(windows))
	for model, window := range windows {
		cloned[model] = window
	}
	return cloned
}

func equalContextWindows(left, right map[string]int) bool {
	if len(left) != len(right) {
		return false
	}
	for model, window := range left {
		if right[model] != window {
			return false
		}
	}
	return true
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
	if value == "" || len(value) > 128 || strings.ToLower(value) != value {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || index > 0 && (character == '-' || character == '_' || character == '.') {
			continue
		}
		return false
	}
	return true
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

func normalizedCustomModels(requested []string) []string {
	seen := make(map[string]struct{}, len(requested))
	result := make([]string, 0, len(requested))
	for _, model := range requested {
		if !validModelName(model) {
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

func settingsFromStored(id, provider, displayName, baseURL string, protocol Protocol, enabled bool, encoded, encodedContextWindows []byte, version, inputMicros, outputMicros int64) (ProviderSettings, error) {
	catalog, found := findCatalog(provider)
	if !safeProviderID(id) || id != provider || !validProtocolValue(protocol) {
		return ProviderSettings{}, ErrInvalidSettings
	}
	var storedModels []string
	if json.Unmarshal(encoded, &storedModels) != nil || len(storedModels) == 0 {
		return ProviderSettings{}, ErrInvalidSettings
	}
	custom := !found
	models := normalizedCustomModels(storedModels)
	if len(models) == 0 {
		return ProviderSettings{}, ErrInvalidSettings
	}
	capability := modelCapabilities(genericModel(models[0]))
	var contextWindows map[string]int
	if found {
		contextWindows = make(map[string]int, len(catalog.Models))
		if !validProtocol(catalog, protocol) {
			return ProviderSettings{}, ErrInvalidSettings
		}
		displayName = catalog.DisplayName
		models = normalizedModels(catalog, nil)
		capability = modelCapabilities(catalog.Models[0])
		for _, model := range catalog.Models {
			contextWindows[model.ID] = model.ContextWindow
		}
	} else {
		if displayName == "" || len(displayName) > 128 || strings.TrimSpace(displayName) != displayName || strings.ContainsAny(displayName, "\r\n\x00") || len(models) == 0 || json.Unmarshal(encodedContextWindows, &contextWindows) != nil || !validContextWindows(models, contextWindows) {
			return ProviderSettings{}, ErrInvalidSettings
		}
	}
	return ProviderSettings{
		ID: id, DisplayName: displayName, Provider: provider, Custom: custom, BaseURL: baseURL,
		Protocol: protocol, Protocols: supportedProtocols(), Enabled: enabled,
		Models:                   append([]string(nil), models...),
		ModelContextWindowTokens: contextWindows,
		InputMicrosPerToken:      inputMicros, OutputMicrosPerToken: outputMicros,
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
	contextWindows := make(map[string]int, len(catalog.Models))
	for _, model := range catalog.Models {
		contextWindows[model.ID] = model.ContextWindow
	}
	encodedContextWindows, _ := json.Marshal(contextWindows)
	settings, _ := settingsFromStored(catalog.ID, catalog.ID, catalog.DisplayName, "", catalog.Protocol, false, encoded, encodedContextWindows, 0, 1, 4)
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
