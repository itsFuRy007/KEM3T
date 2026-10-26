package intelligence

import (
	"errors"
	"strings"

	"github.com/itsFuRy007/kem3t/internal/events"
)

// Priority represents the investigation priority of a finding.
type Priority string

const (
	PriorityLow      Priority = "LOW"
	PriorityInfo     Priority = "INFO"
	PriorityInterest Priority = "INTERESTING"
	PriorityHigh     Priority = "HIGH"
)

// Finding represents an evidence-backed interpretation of an event.
type Finding struct {
	Title                string
	Priority             Priority
	Fact                 string
	Observation          string
	PossibleSignificance string
	Evidence             []events.Event
	NextSteps            []string
}

// Validate checks whether the finding contains its required information.
func (f Finding) Validate() error {
	if strings.TrimSpace(f.Title) == "" {
		return errors.New("finding title is required")
	}

	switch f.Priority {
	case PriorityLow, PriorityInfo, PriorityInterest, PriorityHigh:
	default:
		return errors.New("finding priority is invalid")
	}

	if strings.TrimSpace(f.Fact) == "" {
		return errors.New("finding fact is required")
	}

	if len(f.Evidence) == 0 {
		return errors.New("finding must contain at least one evidence event")
	}

	for _, event := range f.Evidence {
		if err := event.Validate(); err != nil {
			return errors.New("finding contains invalid evidence: " + err.Error())
		}
	}

	return nil
}
