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
	"github.com/itsFuRy007/kem3t/internal/history"
	"github.com/itsFuRy007/kem3t/internal/intelligence"
	"github.com/itsFuRy007/kem3t/internal/observations"
)

type TCPResult struct {
	Events           []events.Event
	Evidence         []evidence.Evidence
	Observations     []evidence.Observation
	Findings         []intelligence.Finding
	Report           intelligence.IntelligenceReport
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

	run := evidence.CollectionRun{
		ID:     fmt.Sprintf("tcp-%d", time.Now().UnixNano()),
		Target: target, StartedAt: time.Now().UTC(),
		Status: evidence.CollectionRunRunning,
	}
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
		if err := registry.UpdateCollectionRun(run); err != nil {
			updateErr := fmt.Errorf("finalize collection run: %w", err)
			if retErr == nil {
				retErr = updateErr
			} else {
				retErr = fmt.Errorf("%w; additionally, %v", retErr, updateErr)
			}
		}
		if retErr == nil && run.Status == evidence.CollectionRunCompleted {
			if err := history.PersistRunSnapshot(snapshotDir, run, registry, result.Observations); err != nil {
				retErr = fmt.Errorf("persist history snapshot: %w", err)
			}
		}
	}()

	collector := &collectors.TCP{
		Target: target, StartPort: startPort, EndPort: endPort,
	}
	eventCh := make(chan events.Event)
	errCh := make(chan error, 1)
	go func() {
		errCh <- collector.Run(ctx, eventCh)
		close(eventCh)
	}()

	for event := range eventCh {
		if event.Type != events.EventPortDiscovered {
			continue
		}
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
		result.Events = append(result.Events, event)
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

	intelligenceEngine := &intelligence.Engine{}
	findings := make([]intelligence.Finding, 0, len(result.Events))
	for _, event := range result.Events {
		finding, err := intelligenceEngine.Analyze(event)
		if err != nil {
			return TCPResult{}, fmt.Errorf("analyze TCP event %q: %w", event.ID, err)
		}
		if finding != nil {
			findings = append(findings, *finding)
		}
	}

	reportEngine := &intelligence.ReportEngine{}
	report, err := reportEngine.BuildWithInvestigationFeedback(
		target,
		findings,
		registry,
		nil,
		nil,
		nil,
	)
	if err != nil {
		return TCPResult{}, fmt.Errorf("build intelligence report: %w", err)
	}

	builtGraph, err := graph.Build(result.Evidence, result.Observations)
	if err != nil {
		return TCPResult{}, fmt.Errorf("build infrastructure graph: %w", err)
	}
	builtGraph, err = graph.AttachServices(builtGraph, result.Normalized.Services)
	if err != nil {
		return TCPResult{}, fmt.Errorf("attach normalized services to graph: %w", err)
	}
	result.Findings = findings
	result.Report = report
	result.Graph = builtGraph
	return result, nil
}
