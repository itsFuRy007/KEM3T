package externalintel

import (
	"context"

	"github.com/itsFuRy007/kem3t/internal/evidence"
)

func applyRegistrationProvenance(observation *evidence.Observation, provenance []evidence.ObservationProvenance) {
	if observation == nil || len(provenance) == 0 {
		return
	}
	if observation.CollectionRunID == "" {
		observation.CollectionRunID = provenance[0].CollectionRunID
	}
	if observation.Stage == "" {
		observation.Stage = provenance[0].Stage
	}
}

func registerEvidenceObservations(registry *evidence.Registry, records []evidence.Evidence, observations []evidence.Observation) (int, error) {
	_, addedObservations, err := registry.AddBatchUnique(context.Background(), records, observations)
	return addedObservations, err
}

func registerEvidenceObservation(registry *evidence.Registry, record evidence.Evidence, observation evidence.Observation) (bool, error) {
	_, added, err := registry.AddBatchUnique(context.Background(), []evidence.Evidence{record}, []evidence.Observation{observation})
	return added > 0, err
}
