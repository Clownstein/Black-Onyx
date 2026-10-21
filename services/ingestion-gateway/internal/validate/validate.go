package validate

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	contracts "github.com/black-onyx/contracts"
)

var (
	ulidPattern          = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
	schemaVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+$`)
	eventTypePattern     = regexp.MustCompile(`^[a-z][a-z0-9_.-]*$`)
)

// Validator enforces envelope rules and temporal bounds.
type Validator struct {
	maxFutureSkew         time.Duration
	maxEventAge           time.Duration
	supportedMajorVersion int
}

func New(maxFutureSkew, maxEventAge time.Duration, supportedMajorVersion int) *Validator {
	return &Validator{
		maxFutureSkew:         maxFutureSkew,
		maxEventAge:           maxEventAge,
		supportedMajorVersion: supportedMajorVersion,
	}
}

type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string { return e.Message }

func (v *Validator) ValidateBytes(raw []byte) (*contracts.EventEnvelope, error) {
	var env contracts.EventEnvelope
	// Unknown modality fields (e.g. severity, message) are allowed alongside the envelope.
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, &ValidationError{Message: "invalid json envelope: " + err.Error()}
	}
	if err := v.Validate(&env); err != nil {
		return nil, err
	}
	return &env, nil
}

func (v *Validator) Validate(env *contracts.EventEnvelope) error {
	if env == nil {
		return &ValidationError{Message: "envelope is nil"}
	}
	if !schemaVersionPattern.MatchString(env.SchemaVersion) {
		return &ValidationError{Message: "schema_version must be major.minor"}
	}
	majorStr := strings.SplitN(env.SchemaVersion, ".", 2)[0]
	major, err := strconv.Atoi(majorStr)
	if err != nil || major != v.supportedMajorVersion {
		return &ValidationError{Message: fmt.Sprintf("unsupported major schema version: %s", env.SchemaVersion)}
	}
	if !ulidPattern.MatchString(env.EventID) {
		return &ValidationError{Message: "event_id must be a ULID"}
	}
	if !eventTypePattern.MatchString(env.EventType) {
		return &ValidationError{Message: "event_type format invalid"}
	}
	if strings.TrimSpace(env.TenantID) == "" {
		return &ValidationError{Message: "tenant_id is required"}
	}
	if strings.TrimSpace(env.Source.CollectorID) == "" || strings.TrimSpace(env.Source.SourceType) == "" {
		return &ValidationError{Message: "source.collector_id and source.source_type are required"}
	}
	if strings.TrimSpace(env.Asset.AssetID) == "" {
		return &ValidationError{Message: "asset.asset_id is required"}
	}
	if env.OccurredAt.IsZero() || env.IngestedAt.IsZero() {
		return &ValidationError{Message: "occurred_at and ingested_at are required"}
	}

	now := time.Now().UTC()
	if env.OccurredAt.After(now.Add(v.maxFutureSkew)) {
		return &ValidationError{Message: "occurred_at is too far in the future"}
	}
	if env.IngestedAt.After(now.Add(v.maxFutureSkew)) {
		return &ValidationError{Message: "ingested_at is too far in the future"}
	}
	if now.Sub(env.OccurredAt) > v.maxEventAge {
		return &ValidationError{Message: "occurred_at exceeds maximum event age"}
	}
	return nil
}

func IsValidationError(err error) bool {
	var ve *ValidationError
	return errors.As(err, &ve)
}
