package modelgateway

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"reflect"
	"sync"

	"github.com/google/uuid"
)

const MaximumTopK = 500

// SamplingSettings are tenant-global generation parameters. Version is
// assigned by the store and changes only when a value changes.
type SamplingSettings struct {
	Temperature     float64 `json:"temperature"`
	TopP            float64 `json:"topP"`
	TopK            int     `json:"topK"`
	ReasoningEffort string  `json:"reasoningEffort"`
	Version         int64   `json:"version"`
}

type SamplingSettingsStore interface {
	Get(context.Context, string) (SamplingSettings, bool, error)
	Put(context.Context, string, SamplingSettings) (SamplingSettings, error)
}

func DefaultSamplingSettings() SamplingSettings {
	return SamplingSettings{Temperature: 0, TopP: 1, TopK: 0, ReasoningEffort: "medium"}
}

func ValidateSamplingSettings(settings SamplingSettings) error {
	if settings.Version < 0 || math.IsNaN(settings.Temperature) || math.IsInf(settings.Temperature, 0) ||
		settings.Temperature < 0 || settings.Temperature > 2 || math.IsNaN(settings.TopP) || math.IsInf(settings.TopP, 0) ||
		settings.TopP < 0 || settings.TopP > 1 || settings.TopK < 0 || settings.TopK > MaximumTopK ||
		!validReasoningEffort(settings.ReasoningEffort) {
		return ErrInvalidRequest
	}
	return nil
}

func validReasoningEffort(value string) bool {
	switch value {
	case "", "none", "minimal", "low", "medium", "high", "xhigh":
		return true
	default:
		return false
	}
}

type MemorySamplingSettingsStore struct {
	mu       sync.Mutex
	settings map[string]SamplingSettings
}

func NewMemorySamplingSettingsStore() *MemorySamplingSettingsStore {
	return &MemorySamplingSettingsStore{settings: make(map[string]SamplingSettings)}
}

func (store *MemorySamplingSettingsStore) Get(_ context.Context, tenantID string) (SamplingSettings, bool, error) {
	if store == nil || tenantID == "" {
		return SamplingSettings{}, false, ErrInvalidRequest
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	settings, found := store.settings[tenantID]
	return settings, found, nil
}

func (store *MemorySamplingSettingsStore) Put(_ context.Context, tenantID string, settings SamplingSettings) (SamplingSettings, error) {
	settings.Version = 0
	if store == nil || tenantID == "" || ValidateSamplingSettings(settings) != nil {
		return SamplingSettings{}, ErrInvalidRequest
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	current, found := store.settings[tenantID]
	if found {
		candidate := settings
		candidate.Version = current.Version
		if reflect.DeepEqual(current, candidate) {
			return current, nil
		}
		settings.Version = current.Version + 1
	} else {
		settings.Version = 1
	}
	store.settings[tenantID] = settings
	return settings, nil
}

type PostgresSamplingSettingsStore struct {
	database *sql.DB
}

func NewPostgresSamplingSettingsStore(database *sql.DB) (*PostgresSamplingSettingsStore, error) {
	if database == nil {
		return nil, ErrInvalidRequest
	}
	return &PostgresSamplingSettingsStore{database: database}, nil
}

func (store *PostgresSamplingSettingsStore) Get(ctx context.Context, tenantID string) (SamplingSettings, bool, error) {
	tx, err := store.begin(ctx, tenantID, true)
	if err != nil {
		return SamplingSettings{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	var settings SamplingSettings
	err = tx.QueryRowContext(ctx, `
SELECT temperature, top_p, top_k, reasoning_effort, version
FROM tenant_model_sampling_settings
WHERE tenant_id = $1::uuid`, tenantID).Scan(
		&settings.Temperature, &settings.TopP, &settings.TopK, &settings.ReasoningEffort, &settings.Version,
	)
	if errors.Is(err, sql.ErrNoRows) {
		if err := tx.Commit(); err != nil {
			return SamplingSettings{}, false, err
		}
		return SamplingSettings{}, false, nil
	}
	if err != nil || ValidateSamplingSettings(settings) != nil || settings.Version < 1 {
		if err != nil {
			return SamplingSettings{}, false, err
		}
		return SamplingSettings{}, false, ErrInvalidRequest
	}
	if err := tx.Commit(); err != nil {
		return SamplingSettings{}, false, err
	}
	return settings, true, nil
}

func (store *PostgresSamplingSettingsStore) Put(ctx context.Context, tenantID string, settings SamplingSettings) (SamplingSettings, error) {
	settings.Version = 0
	if ValidateSamplingSettings(settings) != nil {
		return SamplingSettings{}, ErrInvalidRequest
	}
	tx, err := store.begin(ctx, tenantID, false)
	if err != nil {
		return SamplingSettings{}, err
	}
	defer func() { _ = tx.Rollback() }()
	err = tx.QueryRowContext(ctx, `
INSERT INTO tenant_model_sampling_settings (tenant_id, temperature, top_p, top_k, reasoning_effort, version)
VALUES ($1::uuid, $2, $3, $4, $5, 1)
ON CONFLICT (tenant_id) DO UPDATE
SET temperature = EXCLUDED.temperature,
    top_p = EXCLUDED.top_p,
    top_k = EXCLUDED.top_k,
    reasoning_effort = EXCLUDED.reasoning_effort,
    version = CASE
      WHEN tenant_model_sampling_settings.temperature = EXCLUDED.temperature
       AND tenant_model_sampling_settings.top_p = EXCLUDED.top_p
       AND tenant_model_sampling_settings.top_k = EXCLUDED.top_k
       AND tenant_model_sampling_settings.reasoning_effort = EXCLUDED.reasoning_effort
      THEN tenant_model_sampling_settings.version
      ELSE tenant_model_sampling_settings.version + 1
    END,
    updated_at = CASE
      WHEN tenant_model_sampling_settings.temperature = EXCLUDED.temperature
       AND tenant_model_sampling_settings.top_p = EXCLUDED.top_p
       AND tenant_model_sampling_settings.top_k = EXCLUDED.top_k
       AND tenant_model_sampling_settings.reasoning_effort = EXCLUDED.reasoning_effort
      THEN tenant_model_sampling_settings.updated_at
      ELSE transaction_timestamp()
    END
RETURNING temperature, top_p, top_k, reasoning_effort, version`,
		tenantID, settings.Temperature, settings.TopP, settings.TopK, settings.ReasoningEffort,
	).Scan(&settings.Temperature, &settings.TopP, &settings.TopK, &settings.ReasoningEffort, &settings.Version)
	if err != nil {
		return SamplingSettings{}, err
	}
	if err := tx.Commit(); err != nil {
		return SamplingSettings{}, err
	}
	return settings, nil
}

func (store *PostgresSamplingSettingsStore) begin(ctx context.Context, tenantID string, readOnly bool) (*sql.Tx, error) {
	if store == nil || store.database == nil || ctx == nil {
		return nil, ErrInvalidRequest
	}
	if _, err := uuid.Parse(tenantID); err != nil {
		return nil, ErrInvalidRequest
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

var _ SamplingSettingsStore = (*MemorySamplingSettingsStore)(nil)
var _ SamplingSettingsStore = (*PostgresSamplingSettingsStore)(nil)
