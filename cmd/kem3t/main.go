package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/itsFuRy007/kem3t/internal/changes"
	"github.com/itsFuRy007/kem3t/internal/collectors"
	"github.com/itsFuRy007/kem3t/internal/events"
	"github.com/itsFuRy007/kem3t/internal/intelligence"
	"github.com/itsFuRy007/kem3t/internal/snapshots"
)

type Collector interface {
	Run(context.Context, chan<- events.Event) error
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	flags := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flags.SetOutput(os.Stderr)

	mode := flags.String("mode", "demo", "Collector mode: demo or dns")
	target := flags.String("target", "", "Target hostname for DNS mode")
	snapshotDir := flags.String("snapshot-dir", ".kem3t/snapshots", "Directory for DNS snapshots")

	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}

	switch strings.ToLower(strings.TrimSpace(*mode)) {
	case "demo":
		return runDemo()
	case "dns":
		if strings.TrimSpace(*target) == "" {
			return fmt.Errorf("-target is required in DNS mode")
		}
		return runDNS(strings.TrimSpace(*target), *snapshotDir)
	default:
		return fmt.Errorf("unsupported mode %q", *mode)
	}
}

func runDemo() error {
	ctx := context.Background()
	collector := &collectors.Demo{}
	eventCh := make(chan events.Event)
	collectorErr := make(chan error, 1)

	go func() {
		defer close(eventCh)
		collectorErr <- collector.Run(ctx, eventCh)
	}()

	engine := &intelligence.Engine{}
	findingCh := make(chan intelligence.Finding)
	engineErr := make(chan error, 1)

	go func() {
		defer close(findingCh)
		engineErr <- engine.Run(ctx, eventCh, findingCh)
	}()

	for finding := range findingCh {
		printFinding(finding)
	}

	if err := <-engineErr; err != nil {
		return fmt.Errorf("intelligence engine failed: %w", err)
	}
	if err := <-collectorErr; err != nil {
		return fmt.Errorf("collector failed: %w", err)
	}

	return nil
}

func runDNS(target, snapshotDir string) error {
	ctx := context.Background()
	collector := &collectors.DNS{Target: target}
	eventCh := make(chan events.Event)
	collectorErr := make(chan error, 1)

	go func() {
		defer close(eventCh)
		collectorErr <- collector.Run(ctx, eventCh)
	}()

	aggregator := intelligence.NewAggregator()

	for event := range eventCh {
		if err := aggregator.Add(event); err != nil {
			return fmt.Errorf("aggregate event: %w", err)
		}
	}

	if err := <-collectorErr; err != nil {
		return fmt.Errorf("DNS collector failed: %w", err)
	}

	findings := aggregator.Findings()
	if len(findings) == 0 {
		return fmt.Errorf("DNS collector produced no findings")
	}

	for _, finding := range findings {
		printFinding(finding)
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
		return fmt.Errorf("create current snapshot: %w", err)
	}

	store, err := snapshots.NewStore(snapshotDir)
	if err != nil {
		return fmt.Errorf("initialize snapshot store: %w", err)
	}

	previous, err := store.Load(current.Target)
	if err != nil {
		if !errors.Is(err, snapshots.ErrNotFound) {
			return fmt.Errorf("load previous snapshot: %w", err)
		}

		if err := store.Save(current); err != nil {
			return fmt.Errorf("save initial snapshot: %w", err)
		}

		fmt.Println("\n[BASELINE CREATED]")
		fmt.Printf("Target: %s\n", current.Target)
		fmt.Printf("Unique addresses: %d\n", len(current.Addresses))
		fmt.Printf("Snapshot: %s\n", storePath(snapshotDir, current.Target))
		fmt.Println("Run the same command again to detect DNS changes.")
		return nil
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
		return fmt.Errorf("compare snapshots: %w", err)
	}

	fmt.Println("\n[DNS CHANGE REPORT]")
	fmt.Printf("Target: %s\n", current.Target)
	fmt.Printf("Previous collection: %s\n", previous.Collected.Format("2006-01-02 15:04:05 UTC"))

	if len(detected) == 0 {
		fmt.Println("No address changes detected.")
	} else {
		for _, change := range detected {
			fmt.Printf("[%s] %s\n", change.Type, change.Address)
		}
	}

	if err := store.Save(current); err != nil {
		return fmt.Errorf("save current snapshot: %w", err)
	}

	fmt.Printf("Updated snapshot: %s\n", storePath(snapshotDir, current.Target))
	return nil
}

func storePath(dir, target string) string {
	return strings.TrimRight(dir, "/") + "/" + strings.ToLower(strings.TrimSpace(target)) + ".json"
}

func printFinding(finding intelligence.Finding) {
	fmt.Printf("\n[%s] %s\n", finding.Priority, finding.Title)
	fmt.Printf("Fact: %s\n", finding.Fact)

	if finding.Observation != "" {
		fmt.Printf("Observation: %s\n", finding.Observation)
	}

	if finding.PossibleSignificance != "" {
		fmt.Printf("Possible significance: %s\n", finding.PossibleSignificance)
	}

	fmt.Println("Next steps:")
	for _, step := range finding.NextSteps {
		fmt.Printf("  - %s\n", step)
	}

	fmt.Printf("Evidence events: %d\n", len(finding.Evidence))
}
