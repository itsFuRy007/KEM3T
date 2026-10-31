package evidence

import "context"

type observationProvenanceContextKey struct{}

// WithObservationProvenance associates observations created within ctx with a
// specific collection run and stage. It is immutable and safe for concurrent
// collectors because provenance is carried by each stage context.
func WithObservationProvenance(ctx context.Context, runID, stage string) context.Context {
	if ctx == nil {
		return nil
	}
	return context.WithValue(ctx, observationProvenanceContextKey{}, ObservationProvenance{
		CollectionRunID: runID,
		Stage:           stage,
	})
}

type ObservationProvenance struct {
	CollectionRunID string
	Stage           string
}

func ObservationProvenanceFromContext(ctx context.Context) ObservationProvenance {
	if ctx == nil {
		return ObservationProvenance{}
	}
	provenance, _ := ctx.Value(observationProvenanceContextKey{}).(ObservationProvenance)
	return provenance
}

// ApplyObservationProvenance copies context provenance onto an observation.
// Existing explicit values are preserved.
func ApplyObservationProvenance(ctx context.Context, observation *Observation) {
	if ctx == nil || observation == nil {
		return
	}
	provenance, ok := ctx.Value(observationProvenanceContextKey{}).(ObservationProvenance)
	if !ok {
		return
	}
	if observation.CollectionRunID == "" {
		observation.CollectionRunID = provenance.CollectionRunID
	}
	if observation.Stage == "" {
		observation.Stage = provenance.Stage
	}
}
