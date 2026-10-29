package pipeline

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/itsFuRy007/kem3t/internal/collectors"
	"github.com/itsFuRy007/kem3t/internal/events"
	"github.com/itsFuRy007/kem3t/internal/evidence"
	"github.com/itsFuRy007/kem3t/internal/graph"
	"github.com/itsFuRy007/kem3t/internal/observations"
)

type TLSResult struct {
	Event            *events.Event
	Evidence         evidence.Evidence
	Observation      evidence.Observation
	EvidenceRegistry *evidence.Registry
	Graph            graph.Graph
	Normalized       observations.Collection
}

func RunTLS(
	ctx context.Context,
	target string,
	port int,
	snapshotDir string,
) (result TLSResult, retErr error) {
	if ctx == nil {
		return TLSResult{}, fmt.Errorf("context is required")
	}
	if err := ctx.Err(); err != nil {
		return TLSResult{}, err
	}

	target = strings.TrimSpace(target)
	if target == "" {
		return TLSResult{}, fmt.Errorf("target is required")
	}
	if port == 0 {
		port = 443
	}
	if port < 1 || port > 65535 {
		return TLSResult{}, fmt.Errorf("port must be between 1 and 65535")
	}
	if strings.TrimSpace(snapshotDir) == "" {
		return TLSResult{}, fmt.Errorf("snapshot directory is required")
	}

	if err := os.MkdirAll(snapshotDir, 0750); err != nil {
		return TLSResult{}, fmt.Errorf("create snapshot directory: %w", err)
	}

	registry, err := evidence.OpenRegistry(
		filepath.Join(snapshotDir, "evidence.db"),
	)
	if err != nil {
		return TLSResult{}, fmt.Errorf("open evidence registry: %w", err)
	}
	result.EvidenceRegistry = registry
	defer func() {
		if err := registry.Close(); err != nil && retErr == nil {
			retErr = fmt.Errorf("close evidence registry: %w", err)
		}
	}()

	run := evidence.CollectionRun{
		ID:        fmt.Sprintf("tls-%d", time.Now().UnixNano()),
		Target:    target,
		StartedAt: time.Now().UTC(),
		Status:    evidence.CollectionRunRunning,
	}
	if err := registry.AddCollectionRun(run); err != nil {
		return TLSResult{}, fmt.Errorf("start collection run: %w", err)
	}

	defer func() {
		run.FinishedAt = time.Now().UTC()
		run.EventCount = 0
		run.AddressCount = 0

		if retErr != nil {
			run.Status = evidence.CollectionRunFailed
			run.ErrorMessage = retErr.Error()
		} else {
			run.Status = evidence.CollectionRunCompleted
		}

		if err := registry.UpdateCollectionRun(run); err != nil {
			updateErr := fmt.Errorf("finalize collection run: %w", err)
			if retErr == nil {
				retErr = updateErr
			} else {
				retErr = fmt.Errorf("%w; additionally, %v", retErr, updateErr)
			}
		}
	}()

	collector := &collectors.TLS{
		Target: target,
		Port:   port,
	}

	eventCh := make(chan events.Event, 1)
	collectorErrCh := make(chan error, 1)

	go func() {
		collectorErrCh <- collector.Run(ctx, eventCh)
		close(eventCh)
	}()

	for event := range eventCh {
		if event.Type != events.EventTLSCertificateFound {
			continue
		}

		item, observation, err := evidence.FromTLSEvent(event)
		if err != nil {
			return TLSResult{}, fmt.Errorf("convert TLS event to evidence: %w", err)
		}

		if err := registry.AddEvidence(item); err != nil &&
			!errors.Is(err, evidence.ErrEvidenceExists) {
			return TLSResult{}, fmt.Errorf("register TLS evidence: %w", err)
		}

		if err := registry.AddObservation(observation); err != nil &&
			!errors.Is(err, evidence.ErrObservationExists) {
			return TLSResult{}, fmt.Errorf("register TLS observation: %w", err)
		}

		result.Event = &event
		result.Evidence = item
		result.Observation = observation
	}

	if err := <-collectorErrCh; err != nil {
		return TLSResult{}, err
	}

	result.Normalized = observations.NormalizeEvents([]events.Event{*result.Event})
	observations.AttachEvidence(&result.Normalized, []evidence.Observation{result.Observation})
	if len(result.Normalized.Rejected) > 0 {
		return TLSResult{}, fmt.Errorf("normalize TLS event: %s", result.Normalized.Rejected[0].Reason)
	}
	builtGraph, err := graph.Build([]evidence.Evidence{result.Evidence}, []evidence.Observation{result.Observation})
	if err != nil {
		return TLSResult{}, fmt.Errorf("build infrastructure graph: %w", err)
	}

	result.Graph = builtGraph
	return result, nil
}
