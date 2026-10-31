package pipeline

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/itsFuRy007/kem3t/internal/changes"
	"github.com/itsFuRy007/kem3t/internal/collectors"
	"github.com/itsFuRy007/kem3t/internal/events"
	"github.com/itsFuRy007/kem3t/internal/evidence"
	"github.com/itsFuRy007/kem3t/internal/graph"
	"github.com/itsFuRy007/kem3t/internal/intelligence"
	"github.com/itsFuRy007/kem3t/internal/investigation"
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

func RunDNS(ctx context.Context, target, snapshotDir string) (DNSResult, error) {
	return RunDNSWithPlanFeedback(ctx, target, snapshotDir, nil, nil)
}

// RunDNSWithPlanFeedback runs DNS collection and adapts the resulting plan using
// investigator feedback from the previous plan revision.
func RunDNSWithPlanFeedback(ctx context.Context, target, snapshotDir string, previousPlan *intelligence.InvestigationPlan, feedback []intelligence.InvestigationFeedback) (DNSResult, error) {
	return runDNSWithCollectorAndPlan(ctx, target, snapshotDir, &collectors.DNS{Target: target}, previousPlan, feedback)
}

func runDNSWithCollector(ctx context.Context, target, snapshotDir string, collector eventCollector) (DNSResult, error) {
	return runDNSWithCollectorAndPlan(ctx, target, snapshotDir, collector, nil, nil)
}

// runDNSWithCollectorAndPlan keeps DNS-specific baseline/change and feedback
// behavior, while delegating collection, evidence, provenance, run lifecycle,
// graph construction, and normalization to the shared investigation engine.
func runDNSWithCollectorAndPlan(ctx context.Context, target, snapshotDir string, collector eventCollector, previousPlan *intelligence.InvestigationPlan, feedback []intelligence.InvestigationFeedback) (result DNSResult, retErr error) {
	if ctx == nil {
		return DNSResult{}, fmt.Errorf("context is required")
	}
	if err := ctx.Err(); err != nil {
		return DNSResult{}, err
	}
	target = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(target)), ".")
	if target == "" {
		return DNSResult{}, fmt.Errorf("target is required")
	}
	if collector == nil {
		return DNSResult{}, fmt.Errorf("collector is required")
	}
	snapshotStore, err := snapshots.NewStore(snapshotDir)
	if err != nil {
		return DNSResult{}, err
	}

	stage := &investigation.CollectorStage{
		StageName: "dns",
		Collector: collector,
		Accept: func(event events.Event) bool {
			return event.Type == events.EventDNSRecordFound
		},
		Convert: evidence.FromDNSEvent,
	}
	unified, registry, runErr := runUnifiedStage(ctx, target, snapshotDir, stage)
	if registry != nil {
		result.EvidenceRegistry = registry
		defer func() {
			if closeErr := registry.Close(); closeErr != nil {
				retErr = errors.Join(retErr, fmt.Errorf("close shared evidence registry: %w", closeErr))
			}
		}()
	}
	if len(unified.Stages) > 0 {
		stageResult := unified.Stages[0].Result
		aggregator := intelligence.NewAggregator()
		for _, event := range stageResult.CollectedEvents {
			if err := aggregator.Add(event); err != nil {
				return result, fmt.Errorf("aggregate DNS event: %w", err)
			}
		}
		result.Findings = aggregator.Findings()
	}
	result.Graph = unified.Graph
	result.Normalized = unified.Normalized
	if runErr != nil {
		return result, runErr
	}
	if registry == nil {
		return result, fmt.Errorf("shared evidence registry is unavailable")
	}

	report, err := (&intelligence.ReportEngine{}).BuildWithInvestigationFeedback(target, result.Findings, registry, nil, previousPlan, feedback)
	if err != nil {
		return result, fmt.Errorf("build DNS intelligence report: %w", err)
	}
	result.Report = report

	addresses := make([]string, 0)
	for _, outcome := range unified.Stages {
		for _, item := range outcome.Result.EvidenceRecords {
			if item.Type == evidence.TypeDNSAddress {
				addresses = append(addresses, item.Value)
			}
		}
	}
	currentSnapshot, err := snapshots.New(target, addresses)
	if err != nil {
		return result, fmt.Errorf("create current DNS snapshot: %w", err)
	}
	result.CurrentSnapshot = currentSnapshot

	previousSnapshot, err := snapshotStore.Load(target)
	if err != nil {
		if !errors.Is(err, snapshots.ErrNotFound) {
			return result, fmt.Errorf("load previous DNS snapshot: %w", err)
		}
		if err := snapshotStore.Save(currentSnapshot); err != nil {
			return result, fmt.Errorf("save DNS baseline snapshot: %w", err)
		}
		result.BaselineCreated = true
		return result, nil
	}
	result.PreviousSnapshot = &previousSnapshot

	detector := changes.NewDetector()
	detectedChanges, err := detector.Compare(
		changes.Snapshot{Target: previousSnapshot.Target, Addresses: previousSnapshot.Addresses},
		changes.Snapshot{Target: currentSnapshot.Target, Addresses: currentSnapshot.Addresses},
	)
	if err != nil {
		return result, fmt.Errorf("compare DNS snapshots: %w", err)
	}
	result.Changes = detectedChanges

	history, err := intelligence.CompareDNSHistory(target, previousSnapshot.Addresses, currentSnapshot.Addresses)
	if err != nil {
		return result, fmt.Errorf("compare DNS history: %w", err)
	}
	result.History = &history

	if err := snapshotStore.Save(currentSnapshot); err != nil {
		return result, fmt.Errorf("save current DNS snapshot: %w", err)
	}
	return result, nil
}
