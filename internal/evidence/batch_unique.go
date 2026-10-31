package evidence

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strings"
)

// AddBatchUnique atomically adds records while treating exact duplicate IDs as
// already-known facts. Conflicting records that reuse an ID are rejected.
// This is useful for multi-record provider reports, where retries may include
// facts already persisted by an earlier successful collection.
func (r *Registry) AddBatchUnique(ctx context.Context, records []Evidence, observations []Observation) (int, int, error) {
	if ctx == nil {
		return 0, 0, errors.New("context is required")
	}
	if err := ctx.Err(); err != nil {
		return 0, 0, err
	}

	filteredEvidence := make([]Evidence, 0, len(records))
	filteredObservations := make([]Observation, 0, len(observations))
	if err := func() error {
		r.mu.RLock()
		defer r.mu.RUnlock()

		seenEvidence := make(map[string]Evidence, len(records))
		for _, item := range records {
			item.ID = strings.TrimSpace(item.ID)
			item.EntityID = strings.ToLower(strings.TrimSpace(item.EntityID))
			item.Value = strings.TrimSpace(item.Value)
			if item.Type == TypeDNSAddress {
				if ip := net.ParseIP(item.Value); ip != nil {
					item.Value = ip.String()
				}
			}
			if err := item.Validate(); err != nil {
				return err
			}
			if prior, ok := seenEvidence[item.ID]; ok {
				if !reflect.DeepEqual(prior, item) {
					return ErrEvidenceExists
				}
				continue
			}
			seenEvidence[item.ID] = item
			if prior, ok := r.evidence[item.ID]; ok {
				if !reflect.DeepEqual(prior, item) {
					return ErrEvidenceExists
				}
				continue
			}
			filteredEvidence = append(filteredEvidence, item)
		}

		seenObservations := make(map[string]Observation, len(observations))
		for _, item := range observations {
			item.ID = strings.TrimSpace(item.ID)
			item.EvidenceID = strings.TrimSpace(item.EvidenceID)
			item.Source = strings.TrimSpace(item.Source)
			item.EventIDs = append([]string(nil), item.EventIDs...)
			for i, id := range item.EventIDs {
				item.EventIDs[i] = strings.TrimSpace(id)
			}
			if err := item.Validate(); err != nil {
				return err
			}
			if prior, ok := seenObservations[item.ID]; ok {
				if !sameObservationFact(prior, item) {
					return ErrObservationExists
				}
				continue
			}
			seenObservations[item.ID] = item
			if prior, ok := r.observations[item.ID]; ok {
				if !sameObservationFact(prior, item) {
					return ErrObservationExists
				}
				continue
			}
			filteredObservations = append(filteredObservations, item)
		}
		return nil
	}(); err != nil {
		return 0, 0, err
	}

	if err := r.AddBatch(ctx, filteredEvidence, filteredObservations); err != nil {
		return 0, 0, err
	}
	return len(filteredEvidence), len(filteredObservations), nil
}

func sameObservationFact(a, b Observation) bool {
	a.CollectionRunID = ""
	a.Stage = ""
	b.CollectionRunID = ""
	b.Stage = ""
	return reflect.DeepEqual(a, b)
}
