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

type HTTPResult struct {
	Event            *events.Event
	Evidence         evidence.Evidence
	Observation      evidence.Observation
	EvidenceRegistry *evidence.Registry
	Graph            graph.Graph
	Normalized       observations.Collection
}

// RunHTTP performs one bounded HTTP(S) observation and persists its evidence
// and provenance in the same registry used by the other collection pipelines.
func RunHTTP(ctx context.Context, target, scheme string, port int, snapshotDir string) (result HTTPResult, retErr error) {
	if ctx == nil {
		return HTTPResult{}, fmt.Errorf("context is required")
	}
	if err := ctx.Err(); err != nil {
		return HTTPResult{}, err
	}
	if strings.TrimSpace(target) == "" {
		return HTTPResult{}, fmt.Errorf("target is required")
	}
	if port < 0 || port > 65535 {
		return HTTPResult{}, fmt.Errorf("HTTP port must be between 0 and 65535")
	}
	if strings.TrimSpace(snapshotDir) == "" {
		return HTTPResult{}, fmt.Errorf("snapshot directory is required")
	}
	if err := os.MkdirAll(snapshotDir, 0750); err != nil {
		return HTTPResult{}, fmt.Errorf("create snapshot directory: %w", err)
	}
	registry, err := evidence.OpenRegistry(filepath.Join(snapshotDir, "evidence.db"))
	if err != nil {
		return HTTPResult{}, fmt.Errorf("open evidence registry: %w", err)
	}
	result.EvidenceRegistry = registry
	defer func() {
		if err := registry.Close(); err != nil && retErr == nil {
			retErr = fmt.Errorf("close evidence registry: %w", err)
		}
	}()
	run := evidence.CollectionRun{
		ID:     fmt.Sprintf("http-%d", time.Now().UTC().UnixNano()),
		Target: strings.TrimSpace(target), StartedAt: time.Now().UTC(),
		Status: evidence.CollectionRunRunning,
	}
	if err := registry.AddCollectionRun(run); err != nil {
		return HTTPResult{}, fmt.Errorf("start collection run: %w", err)
	}
	defer func() {
		run.FinishedAt = time.Now().UTC()
		if retErr != nil {
			run.Status = evidence.CollectionRunFailed
			run.ErrorMessage = retErr.Error()
		} else {
			run.Status = evidence.CollectionRunCompleted
		}
		if result.Event != nil {
			run.EventCount = 1
		}
		finalizeCollectionRun(snapshotDir, registry, &run, []evidence.Observation{result.Observation}, &retErr)
	}()
	collector := &collectors.HTTP{Target: target, Scheme: scheme, Port: port}
	eventCh := make(chan events.Event, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- collector.Run(ctx, eventCh)
		close(eventCh)
	}()
	for event := range eventCh {
		if event.Type != events.EventHTTPObserved {
			continue
		}
		item, observation, err := evidence.FromHTTPEvent(event)
		if err != nil {
			return HTTPResult{}, fmt.Errorf("convert HTTP event to evidence: %w", err)
		}
		if err := registry.AddEvidence(item); err != nil && !errors.Is(err, evidence.ErrEvidenceExists) {
			return HTTPResult{}, fmt.Errorf("register HTTP evidence: %w", err)
		}
		if err := registry.AddObservation(observation); err != nil && !errors.Is(err, evidence.ErrObservationExists) {
			return HTTPResult{}, fmt.Errorf("register HTTP observation: %w", err)
		}
		result.Event = &event
		result.Evidence = item
		result.Observation = observation
	}
	if err := <-errCh; err != nil {
		return HTTPResult{}, err
	}
	if result.Event == nil {
		return HTTPResult{}, fmt.Errorf("HTTP collector returned no response event")
	}
	result.Normalized = observations.NormalizeEvents([]events.Event{*result.Event})
	observations.AttachEvidence(&result.Normalized, []evidence.Observation{result.Observation})
	if len(result.Normalized.Rejected) > 0 {
		return HTTPResult{}, fmt.Errorf("normalize HTTP event: %s", result.Normalized.Rejected[0].Reason)
	}
	builtGraph, err := graph.BuildFromRegistry(registry)
	if err != nil {
		return HTTPResult{}, fmt.Errorf("build infrastructure graph: %w", err)
	}
	builtGraph, err = graph.AttachServices(builtGraph, result.Normalized.Services)
	if err != nil {
		return HTTPResult{}, fmt.Errorf("attach normalized services to graph: %w", err)
	}
	result.Graph = builtGraph
	return result, nil
}
