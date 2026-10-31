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
	"github.com/itsFuRy007/kem3t/internal/intelligence"
	"github.com/itsFuRy007/kem3t/internal/observations"
)

type TCPResult struct {
	Events           []events.Event
	Findings         []intelligence.Finding
	Report           intelligence.IntelligenceReport
	Evidence         []evidence.Evidence
	Observations     []evidence.Observation
	EvidenceRegistry *evidence.Registry
	Graph            graph.Graph
	Normalized       observations.Collection
}

func RunTCP(ctx context.Context, target string, startPort, endPort int, snapshotDir string) (result TCPResult, retErr error) {
	if ctx == nil {
		return TCPResult{}, fmt.Errorf("context is required")
	}
	if err := ctx.Err(); err != nil {
		return TCPResult{}, err
	}
	target = strings.TrimSpace(target)
	if target == "" {
		return TCPResult{}, fmt.Errorf("target is required")
	}
	if startPort < 1 || endPort > 65535 || startPort > endPort {
		return TCPResult{}, fmt.Errorf("invalid TCP port range")
	}
	if strings.TrimSpace(snapshotDir) == "" {
		return TCPResult{}, fmt.Errorf("snapshot directory is required")
	}
	if err := os.MkdirAll(snapshotDir, 0750); err != nil {
		return TCPResult{}, fmt.Errorf("create snapshot directory: %w", err)
	}

	registry, err := evidence.OpenRegistry(filepath.Join(snapshotDir, "evidence.db"))
	if err != nil {
		return TCPResult{}, fmt.Errorf("open evidence registry: %w", err)
	}
	result.EvidenceRegistry = registry
	defer func() {
		if err := registry.Close(); err != nil && retErr == nil {
			retErr = fmt.Errorf("close evidence registry: %w", err)
		}
	}()

	run := evidence.CollectionRun{ID: fmt.Sprintf("tcp-%d", time.Now().UnixNano()), Target: target, StartedAt: time.Now().UTC(), Status: evidence.CollectionRunRunning}
	if err := registry.AddCollectionRun(run); err != nil {
		return TCPResult{}, fmt.Errorf("start collection run: %w", err)
	}
	defer func() {
		run.FinishedAt = time.Now().UTC()
		run.EventCount = len(result.Events)
		if retErr != nil {
			run.Status = evidence.CollectionRunFailed
			run.ErrorMessage = retErr.Error()
		} else {
			run.Status = evidence.CollectionRunCompleted
		}
		finalizeCollectionRun(snapshotDir, registry, &run, result.Observations, &retErr)
	}()

	collector := &collectors.TCP{Target: target, StartPort: startPort, EndPort: endPort}
	engine := &intelligence.Engine{}
	eventCh := make(chan events.Event)
	errCh := make(chan error, 1)
	go func() { errCh <- collector.Run(ctx, eventCh); close(eventCh) }()

	for event := range eventCh {
		if event.Type != events.EventPortDiscovered && event.Type != events.EventTCPPortStateObserved {
			continue
		}
		finding, err := engine.Analyze(event)
		if err != nil {
			return TCPResult{}, fmt.Errorf("analyze TCP event: %w", err)
		}
		if finding != nil {
			result.Findings = append(result.Findings, *finding)
		}
		result.Events = append(result.Events, event)
		item, observation, err := evidence.FromTCPEvent(event)
		if err != nil {
			return TCPResult{}, fmt.Errorf("convert TCP event to evidence: %w", err)
		}
		if err := registry.AddEvidence(item); err != nil && !errors.Is(err, evidence.ErrEvidenceExists) {
			return TCPResult{}, fmt.Errorf("register TCP evidence: %w", err)
		}
		if err := registry.AddObservation(observation); err != nil && !errors.Is(err, evidence.ErrObservationExists) {
			return TCPResult{}, fmt.Errorf("register TCP observation: %w", err)
		}
		result.Evidence = append(result.Evidence, item)
		result.Observations = append(result.Observations, observation)
	}
	if err := <-errCh; err != nil {
		return TCPResult{}, err
	}

	result.Normalized = observations.NormalizeEvents(result.Events)
	observations.AttachEvidence(&result.Normalized, result.Observations)
	if len(result.Normalized.Rejected) > 0 {
		return TCPResult{}, fmt.Errorf("normalize TCP events: %s", result.Normalized.Rejected[0].Reason)
	}

	builtGraph, err := graph.Build(result.Evidence, result.Observations)
	if err != nil {
		return TCPResult{}, fmt.Errorf("build infrastructure graph: %w", err)
	}
	builtGraph, err = graph.AttachServices(builtGraph, result.Normalized.Services)
	if err != nil {
		return TCPResult{}, fmt.Errorf("attach normalized services to graph: %w", err)
	}
	result.Graph = builtGraph

	result.Report, err = (&intelligence.ReportEngine{}).Build(target, result.Findings, registry)
	if err != nil {
		return TCPResult{}, fmt.Errorf("build TCP intelligence report: %w", err)
	}
	return result, nil
}
