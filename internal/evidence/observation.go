package evidence

import (
	"errors"
	"strings"
	"time"
)

// Observation records an individual observation supporting evidence.
type Observation struct {
	ID              string    `json:"id"`
	EvidenceID      string    `json:"evidence_id"`
	Source          string    `json:"source"`
	CollectionRunID string    `json:"collection_run_id,omitempty"`
	Stage           string    `json:"stage,omitempty"`
	ObservedAt      time.Time `json:"observed_at"`
	EventIDs        []string  `json:"event_ids"`
}

// Validate checks whether the observation is complete and consistent.
func (o Observation) Validate() error {
	if strings.TrimSpace(o.ID) == "" {
		return errors.New("observation ID is required")
	}

	if strings.TrimSpace(o.EvidenceID) == "" {
		return errors.New("observation evidence ID is required")
	}

	if strings.TrimSpace(o.Source) == "" {
		return errors.New("observation source is required")
	}

	if o.ObservedAt.IsZero() {
		return errors.New("observation timestamp is required")
	}

	if len(o.EventIDs) == 0 {
		return errors.New("observation must reference at least one event")
	}

	seen := make(map[string]struct{}, len(o.EventIDs))

	for _, id := range o.EventIDs {
		id = strings.TrimSpace(id)

		if id == "" {
			return errors.New("observation event ID is required")
		}

		if _, exists := seen[id]; exists {
			return errors.New("observation event IDs must be unique")
		}

		seen[id] = struct{}{}
	}

	return nil
}
