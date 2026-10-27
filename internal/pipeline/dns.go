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
	"github.com/itsFuRy007/kem3t/internal/intelligence"
	"github.com/itsFuRy007/kem3t/internal/snapshots"
)

type DNSResult struct {
	Findings         []intelligence.Finding
	CurrentSnapshot  snapshots.Snapshot
	PreviousSnapshot *snapshots.Snapshot
	Changes          []changes.Change
	BaselineCreated  bool
	EvidenceRegistry *evidence.Registry
}

type EventCollector interface {
	Run(context.Context, chan<- events.Event) error
}

func RunDNS(ctx context.Context, target, snapshotDir string) (DNSResult, error) {
	return runDNSWithCollector(
		ctx,
		target,
		snapshotDir,
		&collectors.DNS{Target: target},
	)
}

func runDNSWithCollector(
	ctx context.Context,
	target, snapshotDir string,
	collector EventCollector,
) (DNSResult, error) {
	if ctx == nil {
		return DNSResult{}, fmt.Errorf("context is required")
	}

	target = strings.TrimSpace(target)
	if target == "" {
		return DNSResult{}, fmt.Errorf("target is required")
	}
	if collector == nil {
		return DNSResult{}, fmt.Errorf("collector is required")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	eventCh := make(chan events.Event)
	collectorErr := make(chan error, 1)

	go func() {
		defer close(eventCh)
		collectorErr <- collector.Run(ctx, eventCh)
	}()

	aggregator := intelligence.NewAggregator()
	registry := evidence.NewRegistry()

	for event := range eventCh {
		if err := aggregator.Add(event); err != nil {
			cancel()
			<-collectorErr
			return DNSResult{}, fmt.Errorf("aggregate event: %w", err)
		}

		if event.Type != events.EventDNSRecordFound {
			continue
		}

		e, observation, err := evidence.FromDNSEvent(event)
		if err != nil {
			// Events that are not supported by the evidence converter
			// remain available to the intelligence aggregator.
			continue
		}

		if err := registry.AddEvidence(e); err != nil &&
			!errors.Is(err, evidence.ErrEvidenceExists) {
			cancel()
			<-collectorErr
			return DNSResult{}, fmt.Errorf("register evidence: %w", err)
		}

		if err := registry.AddObservation(observation); err != nil {
			cancel()
			<-collectorErr
			return DNSResult{}, fmt.Errorf("register observation: %w", err)
		}
	}

	if err := <-collectorErr; err != nil {
		return DNSResult{}, fmt.Errorf("DNS collector failed: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return DNSResult{}, fmt.Errorf("DNS collection canceled: %w", err)
	}

	findings := aggregator.Findings()
	if len(findings) == 0 {
		return DNSResult{}, fmt.Errorf("DNS collector produced no findings")
	}

	addresses := make([]string, 0)
	for _, finding := range findings {
		for _, event := range finding.Evidence {
			address := strings.TrimSpace(event.Data["value"])
			if address != "" {
				addresses = append(addresses, address)
			}
		}
	}

	current, err := snapshots.New(target, addresses)
	if err != nil {
		return DNSResult{}, fmt.Errorf("create current snapshot: %w", err)
	}

	store, err := snapshots.NewStore(snapshotDir)
	if err != nil {
		return DNSResult{}, fmt.Errorf("initialize snapshot store: %w", err)
	}

	previous, err := store.Load(current.Target)
	if err != nil {
		if !errors.Is(err, snapshots.ErrNotFound) {
			return DNSResult{}, fmt.Errorf("load previous snapshot: %w", err)
		}

		if err := store.Save(current); err != nil {
			return DNSResult{}, fmt.Errorf("save initial snapshot: %w", err)
		}

		return DNSResult{
			Findings:         findings,
			CurrentSnapshot:  current,
			BaselineCreated:  true,
			EvidenceRegistry: registry,
		}, nil
	}

	detector := changes.NewDetector()
	detected, err := detector.Compare(
		changes.Snapshot{
			Target:    previous.Target,
			Addresses: previous.Addresses,
		},
		changes.Snapshot{
			Target:    current.Target,
			Addresses: current.Addresses,
		},
	)
	if err != nil {
		return DNSResult{}, fmt.Errorf("compare snapshots: %w", err)
	}

	if err := store.Save(current); err != nil {
		return DNSResult{}, fmt.Errorf("save current snapshot: %w", err)
	}

	return DNSResult{
		Findings:         findings,
		CurrentSnapshot:  current,
		PreviousSnapshot: &previous,
		Changes:          detected,
		EvidenceRegistry: registry,
	}, nil
}
