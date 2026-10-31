package pipeline

import (
	"errors"
	"fmt"

	"github.com/itsFuRy007/kem3t/internal/evidence"
	"github.com/itsFuRy007/kem3t/internal/history"
)

// finalizeCollectionRun persists run status and its history snapshot. If either
// persistence step fails, it attempts to leave the database run marked failed.
func finalizeCollectionRun(
	snapshotDir string,
	registry *evidence.Registry,
	run *evidence.CollectionRun,
	observations []evidence.Observation,
	retErr *error,
) {
	if registry == nil || run == nil || retErr == nil {
		return
	}

	if err := registry.UpdateCollectionRun(*run); err != nil {
		updateErr := fmt.Errorf("finalize collection run: %w", err)
		*retErr = errors.Join(*retErr, updateErr)
		run.Status = evidence.CollectionRunFailed
		if run.ErrorMessage == "" {
			run.ErrorMessage = updateErr.Error()
		} else {
			run.ErrorMessage += "; " + updateErr.Error()
		}
		if retryErr := registry.UpdateCollectionRun(*run); retryErr != nil {
			*retErr = errors.Join(*retErr, fmt.Errorf("mark collection run failed after finalization error: %w", retryErr))
		}
		return
	}

	if *retErr != nil || run.Status != evidence.CollectionRunCompleted {
		return
	}
	if err := history.PersistRunSnapshot(snapshotDir, *run, registry, observations); err != nil {
		persistErr := fmt.Errorf("persist history snapshot: %w", err)
		*retErr = errors.Join(*retErr, persistErr)
		run.Status = evidence.CollectionRunFailed
		if run.ErrorMessage == "" {
			run.ErrorMessage = persistErr.Error()
		} else {
			run.ErrorMessage += "; " + persistErr.Error()
		}
		if updateErr := registry.UpdateCollectionRun(*run); updateErr != nil {
			*retErr = errors.Join(*retErr, fmt.Errorf("mark collection run failed after history persistence error: %w", updateErr))
		}
	}
}
