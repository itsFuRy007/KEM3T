package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/itsFuRy007/kem3t/internal/collectors"
	"github.com/itsFuRy007/kem3t/internal/events"
	"github.com/itsFuRy007/kem3t/internal/evidence"
	"github.com/itsFuRy007/kem3t/internal/intelligence"
	"github.com/itsFuRy007/kem3t/internal/pipeline"
)

func main() {
	if err := run(); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	flags := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flags.SetOutput(os.Stderr)

	mode := flags.String("mode", "demo", "Mode: demo, dns, or history")
	target := flags.String("target", "", "Target hostname for DNS mode")
	snapshotDir := flags.String(
		"snapshot-dir",
		".kem3t/snapshots",
		"Directory for DNS snapshots",
	)

	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}

	switch strings.ToLower(strings.TrimSpace(*mode)) {
	case "history":
		return runHistory(*target, *snapshotDir)
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
	result, err := pipeline.RunDNS(
		context.Background(),
		target,
		snapshotDir,
	)
	if err != nil {
		return err
	}

	for _, finding := range result.Findings {
		printFinding(finding)
	}

	printIntelligenceReport(result.Report)

	if result.BaselineCreated {
		fmt.Println("\n[BASELINE CREATED]")
		fmt.Printf("Target: %s\n", result.CurrentSnapshot.Target)
		fmt.Printf(
			"Unique addresses: %d\n",
			len(result.CurrentSnapshot.Addresses),
		)
		fmt.Printf(
			"Snapshot: %s\n",
			storePath(snapshotDir, result.CurrentSnapshot.Target),
		)
		fmt.Println("Run the same command again to detect DNS changes.")
		return nil
	}

	fmt.Println("\n[DNS CHANGE REPORT]")
	fmt.Printf("Target: %s\n", result.CurrentSnapshot.Target)

	if result.PreviousSnapshot != nil {
		fmt.Printf(
			"Previous collection: %s\n",
			result.PreviousSnapshot.Collected.Format(
				"2006-01-02 15:04:05 UTC",
			),
		)
	}

	if len(result.Changes) == 0 {
		fmt.Println("No address changes detected.")
	} else {
		for _, change := range result.Changes {
			fmt.Printf("[%s] %s\n", change.Type, change.Address)
		}
	}

	if result.History != nil {
		printDNSHistory(*result.History)
	}

	fmt.Printf(
		"Updated snapshot: %s\n",
		storePath(snapshotDir, result.CurrentSnapshot.Target),
	)

	return nil
}

func printIntelligenceReport(report intelligence.IntelligenceReport) {
	fmt.Println("\n[INTELLIGENCE REPORT]")
	fmt.Printf("Target: %s\n", report.Target)
	fmt.Printf("Findings: %d\n", len(report.Findings))
	fmt.Printf("Correlations: %d\n", len(report.Correlations))
	fmt.Printf("Hypotheses: %d\n", len(report.Hypotheses))
	fmt.Printf("Prioritized findings: %d\n", len(report.PrioritizedFindings))

	if len(report.PrioritizedFindings) > 0 {
		fmt.Println("\n[INVESTIGATION PRIORITIES]")
		for _, item := range report.PrioritizedFindings {
			fmt.Printf("[%s] %s\n", item.Priority, item.Finding.Title)
			fmt.Printf("  Reason: %s\n", item.Reason)
		}
	}

	if len(report.Correlations) > 0 {
		fmt.Println("\n[CORRELATIONS]")
		for _, item := range report.Correlations {
			fmt.Printf("[%s] %s\n", item.Type, item.ID)
			fmt.Printf("  Shared value: %s\n", item.SharedValue)
			fmt.Printf("  Entities: %s\n", strings.Join(item.Entities, ", "))
			fmt.Printf("  Evidence records: %d\n", len(item.EvidenceIDs))
			fmt.Printf("  Limitations: %s\n", item.Limitations)
		}
	}

	if len(report.Hypotheses) > 0 {
		fmt.Println("\n[HYPOTHESES]")
		for _, item := range report.Hypotheses {
			fmt.Printf("[%s] %s\n", item.Confidence, item.Title)
			fmt.Printf("  Statement: %s\n", item.Statement)
			fmt.Printf("  Alternative explanations: %s\n", item.Alternative)
			fmt.Printf("  Limitations: %s\n", item.Limitations)
			if len(item.Verification) > 0 {
				fmt.Println("  Verification steps:")
				for _, step := range item.Verification {
					fmt.Printf("    - %s\n", step)
				}
			}
		}
	}
}

func printDNSHistory(history intelligence.DNSHistoryComparison) {
	fmt.Println("\n[DNS HISTORY COMPARISON]")
	fmt.Printf("Target: %s\n", history.Target)
	fmt.Printf(
		"Previous unique addresses: %d\n",
		history.PreviousCount,
	)
	fmt.Printf(
		"Current unique addresses: %d\n",
		history.CurrentCount,
	)

	printAddressGroup("Added", history.Added)
	printAddressGroup("Removed", history.Removed)
	printAddressGroup("Unchanged", history.Unchanged)
}

func printAddressGroup(label string, addresses []string) {
	fmt.Printf("%s (%d):\n", label, len(addresses))

	if len(addresses) == 0 {
		fmt.Println("  None")
		return
	}

	for _, address := range addresses {
		fmt.Printf("  - %s\n", address)
	}
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

func runHistory(target, snapshotDir string) error {
	dbPath := strings.TrimRight(snapshotDir, "/")
	if dbPath == "" {
		dbPath = "."
	}
	dbPath += "/evidence.db"

	registry, err := evidence.OpenRegistry(dbPath)
	if err != nil {
		return fmt.Errorf("open collection history: %w", err)
	}
	defer registry.Close()

	runs, err := registry.CollectionRuns(strings.TrimSpace(target))
	if err != nil {
		return fmt.Errorf("load collection history: %w", err)
	}

	fmt.Println("[COLLECTION RUN HISTORY]")
	fmt.Printf("Database: %s\n", dbPath)

	if strings.TrimSpace(target) != "" {
		fmt.Printf("Target: %s\n", strings.TrimSpace(target))
	}

	if len(runs) == 0 {
		fmt.Println("No collection runs found.")
		return nil
	}

	fmt.Printf("Runs: %d\n\n", len(runs))

	for i, run := range runs {
		fmt.Printf("%d. [%s] %s\n", i+1, run.Status, run.Target)
		fmt.Printf("   Run ID: %s\n", run.ID)
		fmt.Printf("   Started: %s\n", run.StartedAt.Format(time.RFC3339))
		if !run.FinishedAt.IsZero() {
			fmt.Printf("   Finished: %s\n", run.FinishedAt.Format(time.RFC3339))
			fmt.Printf("   Duration: %s\n", run.FinishedAt.Sub(run.StartedAt).Round(time.Millisecond))
		}
		fmt.Printf("   Events: %d | Unique addresses: %d\n", run.EventCount, run.AddressCount)
		if run.ErrorMessage != "" {
			fmt.Printf("   Error: %s\n", run.ErrorMessage)
		}
		fmt.Println()
	}

	return nil
}
