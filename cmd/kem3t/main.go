package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/itsFuRy007/kem3t/internal/collectors"
	"github.com/itsFuRy007/kem3t/internal/events"
	"github.com/itsFuRy007/kem3t/internal/intelligence"
	"github.com/itsFuRy007/kem3t/internal/pipeline"
)

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
	result, err := pipeline.RunDNS(context.Background(), target, snapshotDir)
	if err != nil {
		return err
	}

	for _, finding := range result.Findings {
		printFinding(finding)
	}

	if result.BaselineCreated {
		fmt.Println("\n[BASELINE CREATED]")
		fmt.Printf("Target: %s\n", result.CurrentSnapshot.Target)
		fmt.Printf("Unique addresses: %d\n", len(result.CurrentSnapshot.Addresses))
		fmt.Printf("Snapshot: %s\n", storePath(snapshotDir, result.CurrentSnapshot.Target))
		fmt.Println("Run the same command again to detect DNS changes.")
		return nil
	}

	fmt.Println("\n[DNS CHANGE REPORT]")
	fmt.Printf("Target: %s\n", result.CurrentSnapshot.Target)

	if result.PreviousSnapshot != nil {
		fmt.Printf(
			"Previous collection: %s\n",
			result.PreviousSnapshot.Collected.Format("2006-01-02 15:04:05 UTC"),
		)
	}

	if len(result.Changes) == 0 {
		fmt.Println("No address changes detected.")
	} else {
		for _, change := range result.Changes {
			fmt.Printf("[%s] %s\n", change.Type, change.Address)
		}
	}

	fmt.Printf("Updated snapshot: %s\n", storePath(snapshotDir, result.CurrentSnapshot.Target))
	return nil
}

func storePath(dir, target string) string {
	dir = strings.TrimRight(dir, "/")
	if dir == "" {
		dir = "."
	}
	return dir + "/" + strings.ToLower(strings.TrimSpace(target)) + ".json"
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
