package pipeline

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/itsFuRy007/kem3t/internal/changes"
	"github.com/itsFuRy007/kem3t/internal/collectors"
	"github.com/itsFuRy007/kem3t/internal/events"
	"github.com/itsFuRy007/kem3t/internal/evidence"
	"github.com/itsFuRy007/kem3t/internal/history"
	"github.com/itsFuRy007/kem3t/internal/graph"
	"github.com/itsFuRy007/kem3t/internal/intelligence"
	"github.com/itsFuRy007/kem3t/internal/observations"
	"github.com/itsFuRy007/kem3t/internal/snapshots"
)

type eventCollector interface {
	Run(context.Context, chan<- events.Event) error
}

type DNSResult struct {
	Findings         []intelligence.Finding
	Report           intelligence.IntelligenceReport
	CurrentSnapshot  snapshots.Snapshot
	PreviousSnapshot *snapshots.Snapshot
	Changes          []changes.Change
	History          *intelligence.DNSHistoryComparison
	BaselineCreated  bool
	EvidenceRegistry *evidence.Registry
	Graph            graph.Graph
	Normalized       observations.Collection
}

func RunDNS(
	ctx context.Context,
	target string,
	snapshotDir string,
) (DNSResult, error) {
	return runDNSWithCollector(
		ctx,
		target,
		snapshotDir,
		&collectors.DNS{Target: target},
	)
}

func runDNSWithCollector(
	ctx context.Context,
	target string,
	snapshotDir string,
	collector eventCollector,
) (result DNSResult, retErr error) {
	if ctx == nil {
		return DNSResult{}, fmt.Errorf("context is required")
	}
	if err := ctx.Err(); err != nil {
		return DNSResult{}, err
	}

	target = strings.ToLower(strings.TrimSpace(target))
	if target == "" {
		return DNSResult{}, fmt.Errorf("target is required")
	}
	if strings.TrimSpace(snapshotDir) == "" {
		return DNSResult{}, fmt.Errorf("snapshot directory is required")
	}
	if collector == nil {
		return DNSResult{}, fmt.Errorf("collector is required")
	}

	snapshotStore, err := snapshots.NewStore(snapshotDir)
	if err != nil {
		return DNSResult{}, err
	}

	if err := os.MkdirAll(snapshotDir, 0750); err != nil {
		return DNSResult{}, fmt.Errorf("create snapshot directory: %w", err)
	}

	registry, err := evidence.OpenRegistry(
		filepath.Join(snapshotDir, "evidence.db"),
	)
	if err != nil {
		return DNSResult{}, fmt.Errorf("open evidence registry: %w", err)
	}
	defer registry.Close()

	run := evidence.CollectionRun{
		ID:        fmt.Sprintf("dns-%d", time.Now().UnixNano()),
		Target:    target,
		StartedAt: time.Now().UTC(),
		Status:    evidence.CollectionRunRunning,
	}
	if err := registry.AddCollectionRun(run); err != nil {
		return DNSResult{}, fmt.Errorf("start collection run: %w", err)
	}

	eventCount := 0
	normalizedEvents := make([]events.Event, 0)
	observedAddresses := make(map[string]struct{})

	defer func() {
		run.FinishedAt = time.Now().UTC()
		run.EventCount = eventCount
		run.AddressCount = len(observedAddresses)

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
			if err := history.PersistRunSnapshot(snapshotDir, run, registry); err != nil {
				retErr = fmt.Errorf("persist history snapshot: %w", err)
			}
		}
}()

	aggregator := intelligence.NewAggregator()
	eventCh := make(chan events.Event)
	collectorDone := make(chan error, 1)
	collectorCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		collectorDone <- collector.Run(collectorCtx, eventCh)
		close(eventCh)
	}()

	var aggregationErr error

	for event := range eventCh {
		eventCount++
		normalizedEvents = append(normalizedEvents, event)

		if event.Type == events.EventDNSRecordFound {
			if item, _, err := evidence.FromDNSEvent(event); err == nil {
				observedAddresses[item.Value] = struct{}{}
			}
		}

		if err := aggregator.Add(event); err != nil {
			aggregationErr = fmt.Errorf("aggregate event: %w", err)
			cancel()
			break
		}

		if event.Type != events.EventDNSRecordFound {
			continue
		}

		item, observation, err := evidence.FromDNSEvent(event)
		if err != nil {
			continue
		}

		if err := registry.AddEvidence(item); err != nil &&
			!errors.Is(err, evidence.ErrEvidenceExists) {
			aggregationErr = fmt.Errorf("register evidence: %w", err)
			cancel()
			break
		}

		if err := registry.AddObservation(observation); err != nil {
			if errors.Is(err, evidence.ErrObservationExists) {
				continue
			}
			aggregationErr = fmt.Errorf("register observation: %w", err)
			cancel()
			break
		}
	}

	collectorErr := <-collectorDone

	if aggregationErr != nil {
		return DNSResult{}, aggregationErr
	}
	if err := ctx.Err(); err != nil {
		return DNSResult{}, err
	}
	if collectorErr != nil {
		return DNSResult{}, fmt.Errorf("DNS collector: %w", collectorErr)
	}

	findings := aggregator.Findings()

	dnsGraph, err := graph.BuildFromRegistry(registry)
	if err != nil {
		return DNSResult{}, fmt.Errorf("build DNS graph: %w", err)
	}

	reportEngine := &intelligence.ReportEngine{}
	report, err := reportEngine.Build(target, findings, registry)
	if err != nil {
		return DNSResult{}, fmt.Errorf("build intelligence report: %w", err)
	}

	var addresses []string
	for _, finding := range findings {
		for _, item := range finding.Evidence {
			if item.Data == nil {
				continue
			}
			if value := strings.TrimSpace(item.Data["value"]); value != "" {
				addresses = append(addresses, value)
			}
		}
	}

	currentSnapshot, err := snapshots.New(target, addresses)
	if err != nil {
		return DNSResult{}, fmt.Errorf("create current snapshot: %w", err)
	}

	normalized := observations.NormalizeEvents(normalizedEvents)
	observations.AttachEvidence(&normalized, registry.AllObservations())
	if len(normalized.Rejected) > 0 {
		return DNSResult{}, fmt.Errorf("normalize DNS events: %s", normalized.Rejected[0].Reason)
	}

	result = DNSResult{
		Normalized:       normalized,
		Findings:         findings,
		Report:           report,
		CurrentSnapshot:  currentSnapshot,
		EvidenceRegistry: registry,
		Graph:            dnsGraph,
	}

	previousSnapshot, err := snapshotStore.Load(target)
	if err != nil {
		if !errors.Is(err, snapshots.ErrNotFound) {
			return DNSResult{}, fmt.Errorf("load previous snapshot: %w", err)
		}

		if err := snapshotStore.Save(currentSnapshot); err != nil {
			return DNSResult{}, fmt.Errorf("save baseline snapshot: %w", err)
		}

		result.BaselineCreated = true
		return result, nil
	}

	result.PreviousSnapshot = &previousSnapshot

	detector := changes.NewDetector()
	detectedChanges, err := detector.Compare(
		changes.Snapshot{
			Target:    previousSnapshot.Target,
			Addresses: previousSnapshot.Addresses,
		},
		changes.Snapshot{
			Target:    currentSnapshot.Target,
			Addresses: currentSnapshot.Addresses,
		},
	)
	if err != nil {
		return DNSResult{}, fmt.Errorf("compare snapshots: %w", err)
	}
	result.Changes = detectedChanges

	history, err := intelligence.CompareDNSHistory(
		target,
		previousSnapshot.Addresses,
		currentSnapshot.Addresses,
	)
	if err != nil {
		return DNSResult{}, fmt.Errorf("compare DNS history: %w", err)
	}
	result.History = &history

	if err := snapshotStore.Save(currentSnapshot); err != nil {
		return DNSResult{}, fmt.Errorf("save current snapshot: %w", err)
	}

	return result, nil
}
