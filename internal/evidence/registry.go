package evidence

import (
	"context"
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
	ErrRegistryClosed      = errors.New("evidence registry is closed")
)

// Registry stores evidence and its observation history.
// It can operate in memory or persist records in SQLite.
type Registry struct {
	mu             sync.RWMutex
	evidence       map[string]Evidence
	observations   map[string]Observation
	byEvidence     map[string][]string
	collectionRuns map[string]CollectionRun
	store          *SQLiteStore
	closed         bool
}

// NewRegistry creates an in-memory evidence registry.
func NewRegistry() *Registry {
	return &Registry{
		evidence:       make(map[string]Evidence),
		observations:   make(map[string]Observation),
		byEvidence:     make(map[string][]string),
		collectionRuns: make(map[string]CollectionRun),
	}
}

// OpenRegistry opens a persistent registry and restores its previous records.
func OpenRegistry(path string) (*Registry, error) {
	store, err := OpenSQLiteStore(path)
	if err != nil {
		return nil, fmt.Errorf("open evidence store: %w", err)
	}

	registry := NewRegistry()
	registry.store = store

	evidenceRecords, observations, err := store.LoadAll(context.Background())
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("restore evidence history: %w", err)
	}

	for _, e := range evidenceRecords {
		if err := e.Validate(); err != nil {
			_ = store.Close()
			return nil, fmt.Errorf("invalid stored evidence %q: %w", e.ID, err)
		}
		registry.evidence[e.ID] = e
	}

	for _, o := range observations {
		if err := o.Validate(); err != nil {
			_ = store.Close()
			return nil, fmt.Errorf("invalid stored observation %q: %w", o.ID, err)
		}
		if _, exists := registry.evidence[o.EvidenceID]; !exists {
			_ = store.Close()
			return nil, fmt.Errorf(
				"observation %q references missing evidence %q",
				o.ID,
				o.EvidenceID,
			)
		}

		registry.observations[o.ID] = cloneObservation(o)
		registry.byEvidence[o.EvidenceID] = append(
			registry.byEvidence[o.EvidenceID],
			o.ID,
		)
	}

	runs, err := store.LoadCollectionRuns(context.Background(), "")
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("restore collection run history: %w", err)
	}
	for _, run := range runs {
		registry.collectionRuns[run.ID] = run
	}

	return registry, nil
}

// Close closes the persistent store, if one is configured.
// The registry's in-memory records remain readable after closing.
func (r *Registry) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil
	}

	r.closed = true
	if r.store == nil {
		return nil
	}

	err := r.store.Close()
	r.store = nil
	return err
}

// AddEvidence validates, normalizes, and stores evidence.
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

	if r.closed {
		return ErrRegistryClosed
	}

	if _, exists := r.evidence[e.ID]; exists {
		return ErrEvidenceExists
	}

	if r.store != nil {
		if err := r.store.SaveEvidence(context.Background(), e); err != nil {
			return fmt.Errorf("persist evidence: %w", err)
		}
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
	o.EventIDs = append([]string(nil), o.EventIDs...)

	for i, id := range o.EventIDs {
		o.EventIDs[i] = strings.TrimSpace(id)
	}

	if err := o.Validate(); err != nil {
		return fmt.Errorf("validate observation: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return ErrRegistryClosed
	}

	if _, exists := r.observations[o.ID]; exists {
		return ErrObservationExists
	}

	if _, exists := r.evidence[o.EvidenceID]; !exists {
		return ErrEvidenceNotFound
	}

	if r.store != nil {
		if err := r.store.SaveObservation(context.Background(), o); err != nil {
			return fmt.Errorf("persist observation: %w", err)
		}
	}

	r.observations[o.ID] = cloneObservation(o)
	r.byEvidence[o.EvidenceID] = append(
		r.byEvidence[o.EvidenceID],
		o.ID,
	)

	return nil
}


 // AddBatch atomically adds evidence and observations to the registry. All
 // validation and duplicate/reference checks happen before any in-memory state
 // changes; persistent registries commit the SQLite transaction first.
 func (r *Registry) AddBatch(ctx context.Context, records []Evidence, observations []Observation) error {
	if ctx == nil { return errors.New("context is required") }
	if err := ctx.Err(); err != nil { return err }

	normalizedEvidence := make([]Evidence, len(records))
	batchEvidenceIDs := make(map[string]struct{}, len(records))
	for i, item := range records {
		item.ID = strings.TrimSpace(item.ID)
		item.EntityID = strings.ToLower(strings.TrimSpace(item.EntityID))
		item.Value = strings.TrimSpace(item.Value)
		if item.Type == TypeDNSAddress {
			if ip := net.ParseIP(item.Value); ip != nil { item.Value = ip.String() }
		}
		if err := item.Validate(); err != nil { return fmt.Errorf("validate evidence batch item %q: %w", item.ID, err) }
		if _, exists := batchEvidenceIDs[item.ID]; exists { return ErrEvidenceExists }
		batchEvidenceIDs[item.ID] = struct{}{}
		normalizedEvidence[i] = item
	}

	normalizedObservations := make([]Observation, len(observations))
	batchObservationIDs := make(map[string]struct{}, len(observations))
	for i, item := range observations {
		item.ID = strings.TrimSpace(item.ID)
		item.EvidenceID = strings.TrimSpace(item.EvidenceID)
		item.Source = strings.TrimSpace(item.Source)
		item.EventIDs = append([]string(nil), item.EventIDs...)
		for j, id := range item.EventIDs { item.EventIDs[j] = strings.TrimSpace(id) }
		if err := item.Validate(); err != nil { return fmt.Errorf("validate observation batch item %q: %w", item.ID, err) }
		if _, exists := batchObservationIDs[item.ID]; exists { return ErrObservationExists }
		batchObservationIDs[item.ID] = struct{}{}
		normalizedObservations[i] = item
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed { return ErrRegistryClosed }
	if err := ctx.Err(); err != nil { return err }

	for _, item := range normalizedEvidence {
		if _, exists := r.evidence[item.ID]; exists { return ErrEvidenceExists }
	}
	for _, item := range normalizedObservations {
		if _, exists := r.observations[item.ID]; exists { return ErrObservationExists }
		if _, exists := r.evidence[item.EvidenceID]; !exists {
			if _, inBatch := batchEvidenceIDs[item.EvidenceID]; !inBatch { return ErrEvidenceNotFound }
		}
	}

	if r.store != nil {
		if err := r.store.SaveBatch(ctx, normalizedEvidence, normalizedObservations); err != nil {
			return fmt.Errorf("persist evidence batch: %w", err)
		}
	}

	for _, item := range normalizedEvidence { r.evidence[item.ID] = item }
	for _, item := range normalizedObservations {
		r.observations[item.ID] = cloneObservation(item)
		r.byEvidence[item.EvidenceID] = append(r.byEvidence[item.EvidenceID], item.ID)
	}
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

	return cloneObservation(o), nil
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
		o, exists := r.observations[id]
		if !exists {
			continue
		}
		result = append(result, cloneObservation(o))
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].ObservedAt.Equal(result[j].ObservedAt) {
			return result[i].ID < result[j].ID
		}
		return result[i].ObservedAt.Before(result[j].ObservedAt)
	})

	return result, nil
}

// AllEvidence returns all evidence records ordered by ID.
func (r *Registry) AllEvidence() []Evidence {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Evidence, 0, len(r.evidence))
	for _, item := range r.evidence {
		result = append(result, item)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].ID < result[j].ID
	})

	return result
}

// AllObservations returns all observations ordered by ID.
func (r *Registry) AllObservations() []Observation {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Observation, 0, len(r.observations))
	for _, item := range r.observations {
		result = append(result, cloneObservation(item))
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].ID < result[j].ID
	})

	return result
}

// AddCollectionRun validates and stores a new collection run.
func (r *Registry) AddCollectionRun(run CollectionRun) error {
	run.ID = strings.TrimSpace(run.ID)
	run.Target = strings.ToLower(strings.TrimSpace(run.Target))
	run.ErrorMessage = strings.TrimSpace(run.ErrorMessage)

	if err := run.Validate(); err != nil {
		return fmt.Errorf("validate collection run: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return ErrRegistryClosed
	}

	if _, exists := r.collectionRuns[run.ID]; exists {
		return fmt.Errorf("collection run %q already exists", run.ID)
	}
	if r.store != nil {
		if err := r.store.SaveCollectionRun(context.Background(), run); err != nil {
			return fmt.Errorf("persist collection run: %w", err)
		}
	}
	r.collectionRuns[run.ID] = run
	return nil
}

// UpdateCollectionRun replaces an existing collection run.
func (r *Registry) UpdateCollectionRun(run CollectionRun) error {
	run.ID = strings.TrimSpace(run.ID)
	run.Target = strings.ToLower(strings.TrimSpace(run.Target))
	run.ErrorMessage = strings.TrimSpace(run.ErrorMessage)

	if err := run.Validate(); err != nil {
		return fmt.Errorf("validate collection run: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return ErrRegistryClosed
	}

	if _, exists := r.collectionRuns[run.ID]; !exists {
		return fmt.Errorf("collection run %q not found", run.ID)
	}
	if r.store != nil {
		if err := r.store.UpdateCollectionRun(context.Background(), run); err != nil {
			return fmt.Errorf("persist collection run update: %w", err)
		}
	}
	r.collectionRuns[run.ID] = run
	return nil
}

// GetCollectionRun returns one collection run by ID.
func (r *Registry) GetCollectionRun(id string) (CollectionRun, error) {
	id = strings.TrimSpace(id)

	r.mu.RLock()
	defer r.mu.RUnlock()

	run, exists := r.collectionRuns[id]
	if !exists {
		return CollectionRun{}, fmt.Errorf("collection run %q not found", id)
	}
	return run, nil
}

// CollectionRuns returns collection runs newest first.
// An empty target returns runs for all targets.
func (r *Registry) CollectionRuns(target string) ([]CollectionRun, error) {
	target = strings.ToLower(strings.TrimSpace(target))

	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.store != nil {
		return r.store.LoadCollectionRuns(context.Background(), target)
	}

	result := make([]CollectionRun, 0, len(r.collectionRuns))
	for _, run := range r.collectionRuns {
		if target == "" || run.Target == target {
			result = append(result, run)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].StartedAt.Equal(result[j].StartedAt) {
			return result[i].ID > result[j].ID
		}
		return result[i].StartedAt.After(result[j].StartedAt)
	})
	return result, nil
}

func cloneObservation(o Observation) Observation {
	o.EventIDs = append([]string(nil), o.EventIDs...)
	return o
}
