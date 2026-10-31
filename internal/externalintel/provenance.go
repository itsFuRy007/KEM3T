package externalintel

import "github.com/itsFuRy007/kem3t/internal/evidence"

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
