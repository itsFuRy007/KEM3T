package evidence

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
)

var (
	ErrEvidenceExists      = errors.New("evidence already exists")
	ErrEvidenceNotFound    = errors.New("evidence not found")
	ErrObservationExists   = errors.New("observation already exists")
	ErrObservationNotFound = errors.New("observation not found")
)

// Registry stores evidence and its observation history in memory.
type Registry struct {
	mu           sync.RWMutex
	evidence     map[string]Evidence
	observations map[string]Observation
	byEvidence   map[string][]string
}

// NewRegistry creates an empty evidence registry.
func NewRegistry() *Registry {
	return &Registry{
		evidence:     make(map[string]Evidence),
		observations: make(map[string]Observation),
		byEvidence:   make(map[string][]string),
	}
}

// AddEvidence validates, normalizes, and stores an evidence record.
func (r *Registry) AddEvidence(e Evidence) error {
	e.ID = strings.TrimSpace(e.ID)
	e.EntityID = strings.ToLower(strings.TrimSpace(e.EntityID))
	e.Value = strings.TrimSpace(e.Value)

	if e.Type == TypeDNSAddress {
		if ip := net.ParseIP(e.Value); ip != nil {
			e.Value = ip.String()
		}
	}

	if err := e.Validate(); err != nil {
		return fmt.Errorf("validate evidence: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.evidence[e.ID]; exists {
		return ErrEvidenceExists
	}

	r.evidence[e.ID] = e
	return nil
}

// GetEvidence returns evidence by ID.
func (r *Registry) GetEvidence(id string) (Evidence, error) {
	id = strings.TrimSpace(id)

	r.mu.RLock()
	defer r.mu.RUnlock()

	e, exists := r.evidence[id]
	if !exists {
		return Evidence{}, ErrEvidenceNotFound
	}

	return e, nil
}

// AddObservation validates and stores an observation.
func (r *Registry) AddObservation(o Observation) error {
	o.ID = strings.TrimSpace(o.ID)
	o.EvidenceID = strings.TrimSpace(o.EvidenceID)
	o.Source = strings.TrimSpace(o.Source)

	// Copy before normalization so the caller's slice is not modified.
	o.EventIDs = append([]string(nil), o.EventIDs...)
	for i, id := range o.EventIDs {
		o.EventIDs[i] = strings.TrimSpace(id)
	}

	if err := o.Validate(); err != nil {
		return fmt.Errorf("validate observation: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.observations[o.ID]; exists {
		return ErrObservationExists
	}

	if _, exists := r.evidence[o.EvidenceID]; !exists {
		return ErrEvidenceNotFound
	}

	r.observations[o.ID] = o
	r.byEvidence[o.EvidenceID] = append(
		r.byEvidence[o.EvidenceID],
		o.ID,
	)

	return nil
}

// GetObservation returns an observation by ID.
func (r *Registry) GetObservation(id string) (Observation, error) {
	id = strings.TrimSpace(id)

	r.mu.RLock()
	defer r.mu.RUnlock()

	o, exists := r.observations[id]
	if !exists {
		return Observation{}, ErrObservationNotFound
	}

	o.EventIDs = append([]string(nil), o.EventIDs...)
	return o, nil
}

// ObservationsForEvidence returns observations ordered by timestamp,
// then by ID.
func (r *Registry) ObservationsForEvidence(
	evidenceID string,
) ([]Observation, error) {
	evidenceID = strings.TrimSpace(evidenceID)

	r.mu.RLock()
	defer r.mu.RUnlock()

	if _, exists := r.evidence[evidenceID]; !exists {
		return nil, ErrEvidenceNotFound
	}

	ids := r.byEvidence[evidenceID]
	result := make([]Observation, 0, len(ids))

	for _, id := range ids {
		o := r.observations[id]
		o.EventIDs = append([]string(nil), o.EventIDs...)
		result = append(result, o)
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].ObservedAt.Equal(result[j].ObservedAt) {
			return result[i].ID < result[j].ID
		}

		return result[i].ObservedAt.Before(result[j].ObservedAt)
	})

	return result, nil
}
