package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/itsFuRy007/kem3t/internal/evidence"
	"github.com/itsFuRy007/kem3t/internal/history"
)

type externalCollectionFunc func(
	context.Context,
	*evidence.Registry,
	string,
) error

// runExternalCollection gives standalone external-intelligence modes the same
// persisted run lifecycle and history guarantees as the collection pipelines.
func runExternalCollection(
	target string,
	snapshotDir string,
	runPrefix string,
	timeout time.Duration,
	collect externalCollectionFunc,
) (retErr error) {
	target = history.NormalizeTarget(target)
	snapshotDir = strings.TrimSpace(snapshotDir)
	runPrefix = strings.ToLower(strings.TrimSpace(runPrefix))

	if target == "" {
		return fmt.Errorf("target is required")
	}
	if snapshotDir == "" {
		return fmt.Errorf("snapshot directory is required")
	}
	if runPrefix == "" {
		return fmt.Errorf("collection run prefix is required")
	}
	if timeout <= 0 {
		return fmt.Errorf("collection timeout must be positive")
	}
	if collect == nil {
		return fmt.Errorf("external collection function is required")
	}

	if err := os.MkdirAll(snapshotDir, 0750); err != nil {
		return fmt.Errorf("create snapshot directory: %w", err)
	}

	registry, err := evidence.OpenRegistry(filepath.Join(snapshotDir, "evidence.db"))
	if err != nil {
		return fmt.Errorf("open evidence registry: %w", err)
	}
	defer func() {
		if err := registry.Close(); err != nil {
			closeErr := fmt.Errorf("close evidence registry: %w", err)
			if retErr == nil {
				retErr = closeErr
			} else {
				retErr = fmt.Errorf("%w; additionally, %v", retErr, closeErr)
			}
		}
	}()

	startedAt := time.Now().UTC()
	run := evidence.CollectionRun{
		ID:        fmt.Sprintf("%s-%d", runPrefix, startedAt.UnixNano()),
		Target:    target,
		StartedAt: startedAt,
		Status:    evidence.CollectionRunRunning,
	}
	if err := registry.AddCollectionRun(run); err != nil {
		return fmt.Errorf("start external collection run: %w", err)
	}

	previousEvidenceIDs := make(map[string]struct{})
	for _, item := range registry.AllEvidence() {
		previousEvidenceIDs[item.ID] = struct{}{}
	}

	previousObservationIDs := make(map[string]struct{})
	for _, observation := range registry.AllObservations() {
		previousObservationIDs[observation.ID] = struct{}{}
	}

	defer func() {
		run.FinishedAt = time.Now().UTC()

		if retErr != nil {
			run.Status = evidence.CollectionRunFailed
			run.ErrorMessage = retErr.Error()
		} else {
			run.Status = evidence.CollectionRunCompleted
		}

		runObservations := make([]evidence.Observation, 0)
		for _, observation := range registry.AllObservations() {
			if _, existed := previousObservationIDs[observation.ID]; !existed {
				runObservations = append(runObservations, observation)
			}
		}
		run.EventCount = len(runObservations)
		for _, item := range registry.AllEvidence() {
			if _, existed := previousEvidenceIDs[item.ID]; existed {
				continue
			}
			if item.Type == evidence.TypeDNSAddress {
				run.AddressCount++
			}
		}

		if err := registry.UpdateCollectionRun(run); err != nil {
			updateErr := fmt.Errorf("finalize external collection run: %w", err)
			retErr = errors.Join(retErr, updateErr)
			run.Status = evidence.CollectionRunFailed
			if run.ErrorMessage == "" {
				run.ErrorMessage = updateErr.Error()
			} else {
				run.ErrorMessage += "; " + updateErr.Error()
			}
			if retryErr := registry.UpdateCollectionRun(run); retryErr != nil {
				retErr = errors.Join(retErr, fmt.Errorf("mark external collection run failed after finalization error: %w", retryErr))
			}
			return
		}

		if retErr != nil || run.Status != evidence.CollectionRunCompleted {
			return
		}

		if err := history.PersistRunSnapshot(snapshotDir, run, registry, runObservations); err != nil {
			persistErr := fmt.Errorf("persist external collection history snapshot: %w", err)
			retErr = errors.Join(retErr, persistErr)
			run.Status = evidence.CollectionRunFailed
			if run.ErrorMessage == "" {
				run.ErrorMessage = persistErr.Error()
			} else {
				run.ErrorMessage += "; " + persistErr.Error()
			}
			if updateErr := registry.UpdateCollectionRun(run); updateErr != nil {
				retErr = errors.Join(retErr, fmt.Errorf("mark external collection run failed after history persistence error: %w", updateErr))
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	retErr = collect(ctx, registry, target)
	if retErr != nil {
		retErr = fmt.Errorf("%s collection: %w", runPrefix, retErr)
	}
	return retErr
}
