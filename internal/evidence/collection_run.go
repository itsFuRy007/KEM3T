package evidence

import (
	"fmt"
	"strings"
	"time"
)

type CollectionRunStatus string

const (
	CollectionRunRunning   CollectionRunStatus = "running"
	CollectionRunCompleted CollectionRunStatus = "completed"
	CollectionRunFailed    CollectionRunStatus = "failed"
)

type CollectionRun struct {
	ID           string              `json:"id"`
	Target       string              `json:"target"`
	StartedAt    time.Time           `json:"started_at"`
	FinishedAt   time.Time           `json:"finished_at,omitempty"`
	Status       CollectionRunStatus `json:"status"`
	EventCount   int                 `json:"event_count"`
	AddressCount int                 `json:"address_count"`
	ErrorMessage string              `json:"error_message,omitempty"`
}

func (r CollectionRun) Validate() error {
	if strings.TrimSpace(r.ID) == "" {
		return fmt.Errorf("collection run ID is required")
	}
	if strings.TrimSpace(r.Target) == "" {
		return fmt.Errorf("collection run target is required")
	}
	if r.StartedAt.IsZero() {
		return fmt.Errorf("collection run start time is required")
	}

	switch r.Status {
	case CollectionRunRunning:
		if !r.FinishedAt.IsZero() {
			return fmt.Errorf("running collection cannot have a finish time")
		}
	case CollectionRunCompleted, CollectionRunFailed:
		if r.FinishedAt.IsZero() {
			return fmt.Errorf("finished collection requires a finish time")
		}
		if r.FinishedAt.Before(r.StartedAt) {
			return fmt.Errorf("collection finish time precedes start time")
		}
	default:
		return fmt.Errorf("invalid collection run status %q", r.Status)
	}

	if r.EventCount < 0 || r.AddressCount < 0 {
		return fmt.Errorf("collection counts cannot be negative")
	}

	return nil
}
