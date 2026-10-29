package main

import (
	"context"
	"errors"
	"flag"
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
	"github.com/itsFuRy007/kem3t/internal/history"
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

	mode := flags.String("mode", "demo", "Mode: demo, dns, tls, tcp, http, or history")
	target := flags.String("target", "", "Target hostname or IP address")
	port := flags.Int("port", 443, "TCP port for TLS mode")
	httpScheme := flags.String("http-scheme", "auto", "HTTP scheme: auto, http, or https")
	httpPort := flags.Int("http-port", 0, "HTTP port override (0 uses scheme defaults)")
	startPort := flags.Int("start-port", 1, "First TCP port to scan")
	endPort := flags.Int("end-port", 1024, "Last TCP port to scan")
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
	case "tls":
		if strings.TrimSpace(*target) == "" {
			return fmt.Errorf("-target is required in TLS mode")
		}
		return runTLS(strings.TrimSpace(*target), *port, *snapshotDir)
	case "http":
		if strings.TrimSpace(*target) == "" {
			return fmt.Errorf("-target is required in HTTP mode")
		}
		return runHTTP(strings.TrimSpace(*target), *httpScheme, *httpPort, *snapshotDir)
	case "tcp":
		if strings.TrimSpace(*target) == "" {
			return fmt.Errorf("-target is required in TCP mode")
		}
		return runTCP(strings.TrimSpace(*target), *startPort, *endPort, *snapshotDir)
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

func runTCP(target string, startPort, endPort int, snapshotDir string) error {
	result, err := pipeline.RunTCP(
		context.Background(),
		target,
		startPort,
		endPort,
		snapshotDir,
	)
	if err != nil {
		return err
	}

	fmt.Printf("[TCP PORT SCAN] %s (%d-%d)\n", target, startPort, endPort)
	for _, event := range result.Events {
		fmt.Printf("[OPEN] %s/tcp\n", event.Data["port"])
	}
	fmt.Printf("Open ports: %d\n", len(result.Events))
	fmt.Printf("Evidence records: %d | Graph nodes: %d | Graph edges: %d\n",
		len(result.Evidence), len(result.Graph.Nodes), len(result.Graph.Edges))
	return nil
}

func runTLS(target string, port int, snapshotDir string) error {
	result, err := pipeline.RunTLS(
		context.Background(),
		target,
		port,
		snapshotDir,
	)
	if err != nil {
		return err
	}

	if result.Event != nil {
		fmt.Println("[TLS CERTIFICATE]")
		fmt.Printf("Target: %s\n", result.Event.Target)
		fmt.Printf("Port: %s\n", result.Event.Data["port"])
		fmt.Printf("Subject: %s\n", result.Event.Data["subject"])
		fmt.Printf("Issuer: %s\n", result.Event.Data["issuer"])
		fmt.Printf("TLS Version: %s\n", result.Event.Data["tls_version"])
		fmt.Printf("Verified: %s\n", result.Event.Data["verified"])
		fmt.Printf("SHA-256: %s\n", result.Event.Data["sha256_fingerprint"])
	}

	printInfrastructureGraph(result.Graph)
	return nil
}

func runHTTP(target, scheme string, port int, snapshotDir string) error {
	result, err := pipeline.RunHTTP(context.Background(), target, scheme, port, snapshotDir)
	if err != nil {
		return err
	}
	if result.Event != nil {
		fmt.Println("[HTTP SERVICE]")
		fmt.Printf("Target: %s\n", result.Event.Target)
		fmt.Printf("URL: %s\n", result.Event.Data["url"])
		fmt.Printf("Final URL: %s\n", result.Event.Data["final_url"])
		fmt.Printf("Status: %s\n", result.Event.Data["status_code"])
		fmt.Printf("Title: %s\n", result.Event.Data["title"])
		fmt.Printf("Server: %s\n", result.Event.Data["server"])
		fmt.Printf("Content-Type: %s\n", result.Event.Data["content_type"])
		fmt.Printf("Redirects: %s\n", result.Event.Data["redirect_count"])
		fmt.Printf("TLS verified: %s\n", result.Event.Data["tls_verified"])
		fmt.Printf("Body truncated: %s\n", result.Event.Data["body_truncated"])
	}
	printInfrastructureGraph(result.Graph)
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
	printInfrastructureGraph(result.Graph)

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
	dbPath := filepath.Join(snapshotDir, "evidence.db")
	registry, err := evidence.OpenRegistry(dbPath)
	if err != nil {
		return fmt.Errorf("open collection history: %w", err)
	}
	defer registry.Close()

	target = strings.TrimSpace(target)
	runs, err := registry.CollectionRuns("")
	if err != nil {
		return fmt.Errorf("load collection history: %w", err)
	}
	if target != "" {
		normalizedTarget := history.NormalizeTarget(target)
		filteredRuns := make([]evidence.CollectionRun, 0, len(runs))
		for _, run := range runs {
			if history.NormalizeTarget(run.Target) == normalizedTarget {
				filteredRuns = append(filteredRuns, run)
			}
		}
		runs = filteredRuns
	}
	allEvidence := registry.AllEvidence()
	allObservations := registry.AllObservations()

	historyStore, err := history.NewStore(filepath.Join(snapshotDir, "history"))
	if err != nil {
		return err
	}
	// Reconstruct one immutable, evidence-backed snapshot per completed run.
	// Saving by run ID makes repeated history queries idempotent.
	for _, run := range runs {
		if run.Status != evidence.CollectionRunCompleted {
			continue
		}
		snapshot, err := history.BuildSnapshot(run, allEvidence, allObservations)
		if err != nil {
			return fmt.Errorf("build snapshot for run %q: %w", run.ID, err)
		}
		if err := historyStore.Save(snapshot); err != nil {
			return fmt.Errorf("save snapshot for run %q: %w", run.ID, err)
		}
	}

	snapshots, err := historyStore.List()
	if err != nil {
		return fmt.Errorf("load generalized history snapshots: %w", err)
	}
	if target != "" {
		normalizedTarget := history.NormalizeTarget(target)
		filtered := make([]history.Snapshot, 0, len(snapshots))
		for _, snapshot := range snapshots {
			if history.NormalizeTarget(snapshot.Target) == normalizedTarget {
				filtered = append(filtered, snapshot)
			}
		}
		snapshots = filtered
	}
	timeline, err := history.BuildTimeline(snapshots)
	if err != nil {
		return fmt.Errorf("build investigation timeline: %w", err)
	}

	fmt.Println("[COLLECTION RUN HISTORY]")
	fmt.Printf("Database: %s\n", dbPath)
	fmt.Printf("Generalized snapshots: %s\n", filepath.Join(snapshotDir, "history"))
	if target != "" {
		fmt.Printf("Target: %s\n", target)
	}
	fmt.Printf("Runs: %d | Snapshots: %d | Changes: %d\n\n", len(runs), len(timeline.Snapshots), len(timeline.Changes))

	if len(runs) == 0 {
		fmt.Println("No collection runs found.")
		return nil
	}
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

	fmt.Println("[INFRASTRUCTURE TIMELINE]")
	if len(timeline.Snapshots) == 0 {
		fmt.Println("No completed collection snapshots are available.")
	} else {
		for _, snapshot := range timeline.Snapshots {
			fmt.Printf("[%s] %s | %s | records: %d\n", snapshot.CollectedAt.Format(time.RFC3339), snapshot.Collector, snapshot.Target, len(snapshot.Records))
			fmt.Printf("  Run: %s\n", snapshot.RunID)
		}
	}

	fmt.Println("\n[HISTORICAL CHANGES]")
	if len(timeline.Changes) == 0 {
		fmt.Println("No changes between comparable snapshots.")
	} else {
		for _, change := range timeline.Changes {
			fmt.Printf("[%s] %s | %s | %s\n", change.Type, change.Collector, change.Target, change.Key)
			fmt.Printf("  Runs: %s -> %s | evidence refs: %d | observation refs: %d\n", change.PreviousRunID, change.CurrentRunID, len(change.EvidenceIDs), len(change.ObservationIDs))
		}
	}

	fmt.Println("\n[ANOMALY REVIEW SIGNALS]")
	anomalies := history.DetectAnomalies(timeline)
	if len(anomalies) == 0 {
		fmt.Println("No high-change-volume signals detected.")
	} else {
		for _, anomaly := range anomalies {
			fmt.Printf("[%s] %s | %s | run %s\n", anomaly.Type, anomaly.Target, anomaly.Collector, anomaly.RunID)
			fmt.Printf("  %s\n", anomaly.Summary)
		}
	}
	fmt.Println("Anomaly signals are review prompts, not proof of compromise or malicious activity.")
	return nil
}

func printInfrastructureGraph(g graph.Graph) {
	fmt.Println("\n[INFRASTRUCTURE GRAPH]")
	fmt.Printf("Nodes: %d\n", len(g.Nodes))
	fmt.Printf("Relationships: %d\n", len(g.Edges))

	if len(g.Edges) == 0 {
		fmt.Println("No relationships available.")
		return
	}

	nodeValues := make(map[string]string, len(g.Nodes))
	for _, node := range g.Nodes {
		nodeValues[node.ID] = node.Value
	}

	for _, edge := range g.Edges {
		fmt.Printf(
			"[%s] %s -> %s\n",
			edge.Type,
			nodeValues[edge.Source],
			nodeValues[edge.Target],
		)
	}
}
