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

	"github.com/itsFuRy007/kem3t/internal/batch"
	"github.com/itsFuRy007/kem3t/internal/collectors"
	"github.com/itsFuRy007/kem3t/internal/events"
	"github.com/itsFuRy007/kem3t/internal/evidence"
	"github.com/itsFuRy007/kem3t/internal/externalintel"
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

	mode := flags.String("mode", "demo", "Mode: demo, dns, tls, tcp, http, history, batch-dns, ct, rdap, iprdap, asn, pdns, or threat")
	target := flags.String("target", "", "Target hostname or IP address")
	targetsFile := flags.String("targets-file", "", "File with one hostname/IP per line (batch-dns mode)")
	workers := flags.Int("workers", 4, "Maximum concurrent targets for batch-dns mode")
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
	case "batch-dns":
		if strings.TrimSpace(*targetsFile) == "" {
			return fmt.Errorf("-targets-file is required in batch-dns mode")
		}
		return runBatchDNS(*targetsFile, *snapshotDir, *workers)
	case "ct":
		if strings.TrimSpace(*target) == "" {
			return fmt.Errorf("-target is required in CT mode")
		}
		return runCT(strings.TrimSpace(*target), *snapshotDir)
	case "rdap":
		if strings.TrimSpace(*target) == "" {
			return fmt.Errorf("-target is required in RDAP mode")
		}
		return runRDAP(strings.TrimSpace(*target), *snapshotDir)
	case "iprdap":
		if strings.TrimSpace(*target)=="" { return fmt.Errorf("-target is required in IP RDAP mode") }
		return runIPRDAP(strings.TrimSpace(*target),*snapshotDir)
	case "asn":
		if strings.TrimSpace(*target) == "" { return fmt.Errorf("-target is required in ASN mode") }
		return runASN(strings.TrimSpace(*target), *snapshotDir)
	case "pdns":
		if strings.TrimSpace(*target) == "" { return fmt.Errorf("-target is required in passive-DNS mode") }
		return runPassiveDNS(strings.TrimSpace(*target), *snapshotDir)
	case "threat":
		if strings.TrimSpace(*target) == "" { return fmt.Errorf("-target is required in threat-intelligence mode") }
		return runThreatIntel(strings.TrimSpace(*target), *snapshotDir)
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
			fmt.Printf("  Confidence: %s (scope: %s)\n", item.Confidence, item.ConfidenceScope)
			fmt.Printf("  Evidence refs: %s\n", strings.Join(item.EvidenceIDs, ", "))
			fmt.Printf("  Observation refs: %s\n", strings.Join(item.ObservationIDs, ", "))
			fmt.Printf("  Limitations: %s\n", item.Limitations)
		}
	}

	if len(report.Hypotheses) > 0 {
		fmt.Println("\n[HYPOTHESES]")
		for _, item := range report.Hypotheses {
			fmt.Printf("[%s] %s\n", item.Confidence, item.Title)
			fmt.Printf("  Statement: %s\n", item.Statement)
			fmt.Printf("  Supporting evidence refs: %s\n", strings.Join(item.SupportingIDs, ", "))
			fmt.Printf("  Supporting facts: %s\n", strings.Join(item.SupportingFacts, " | "))
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
	// Backfill snapshots for completed runs recorded before generalized history
	// was introduced. Never overwrite a snapshot captured by its live pipeline.
	existingSnapshots, err := historyStore.List()
	if err != nil {
		return fmt.Errorf("load existing history snapshots: %w", err)
	}
	existingRunIDs := make(map[string]struct{}, len(existingSnapshots))
	for _, snapshot := range existingSnapshots {
		existingRunIDs[snapshot.RunID] = struct{}{}
	}
	for _, run := range runs {
		if run.Status != evidence.CollectionRunCompleted {
			continue
		}
		if _, exists := existingRunIDs[run.ID]; exists {
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

func runCT(target, snapshotDir string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	report, err := (&externalintel.CTClient{}).LookupDomain(ctx, target)
	if err != nil {
		return err
	}
	if strings.TrimSpace(snapshotDir) == "" {
		return fmt.Errorf("snapshot directory is required")
	}
	if err := os.MkdirAll(snapshotDir, 0750); err != nil {
		return fmt.Errorf("create snapshot directory: %w", err)
	}
	registry, err := evidence.OpenRegistry(filepath.Join(snapshotDir, "evidence.db"))
	if err != nil {
		return fmt.Errorf("open evidence registry: %w", err)
	}
	defer registry.Close()
	added, err := externalintel.RegisterCTReport(registry, report)
	if err != nil {
		return err
	}
	infrastructureGraph, err := graph.BuildFromRegistry(registry)
	if err != nil {
		return fmt.Errorf("build CT infrastructure graph: %w", err)
	}

	fmt.Println("[CERTIFICATE TRANSPARENCY INTELLIGENCE]")
	fmt.Printf("Target: %s\n", report.Target)
	fmt.Printf("Source: %s\n", report.Source)
	fmt.Printf("Retrieved: %s\n", report.RetrievedAt.Format(time.RFC3339))
	fmt.Printf("Certificate records: %d\n", report.CertificateRecords)
	fmt.Printf("Unique in-scope DNS names: %d\n", report.UniqueDNSNames)
	fmt.Printf("Distinct issuer labels: %d\n", report.UniqueIssuers)
	for _, name := range report.DNSNames {
		fmt.Printf("[CT NAME] %s\n", name)
	}
	fmt.Println("\n[INTERPRETATION LIMITS]")
	for _, limitation := range report.Limitations {
		fmt.Printf("- %s\n", limitation)
	}
	fmt.Printf("Evidence records added: %d\n", added)
	printInfrastructureGraph(infrastructureGraph)
	return nil
}

func runRDAP(target, snapshotDir string) error {
	ctx,cancel:=context.WithTimeout(context.Background(),25*time.Second)
	defer cancel()
	report,err:=(&externalintel.RDAPClient{}).LookupDomain(ctx,target)
	if err!=nil{return err}
	if strings.TrimSpace(snapshotDir)==""{return fmt.Errorf("snapshot directory is required")}
	if err:=os.MkdirAll(snapshotDir,0750);err!=nil{return fmt.Errorf("create snapshot directory: %w",err)}
	registry,err:=evidence.OpenRegistry(filepath.Join(snapshotDir,"evidence.db"))
	if err!=nil{return fmt.Errorf("open evidence registry: %w",err)}
	defer registry.Close()
	added,err:=externalintel.RegisterRDAPReport(registry,report)
	if err!=nil{return err}
	infrastructureGraph,err:=graph.BuildFromRegistry(registry)
	if err!=nil{return fmt.Errorf("build RDAP infrastructure graph: %w",err)}
	fmt.Println("[DOMAIN REGISTRATION INTELLIGENCE]")
	fmt.Printf("Target: %s\nSource: %s\nRetrieved: %s\n",report.Target,report.Source,report.RetrievedAt.Format(time.RFC3339))
	if report.Handle!=""{fmt.Printf("Registry handle: %s\n",report.Handle)}
	if report.Registrar!=""{fmt.Printf("Registrar label: %s\n",report.Registrar)}
	fmt.Printf("Status values: %s\n",strings.Join(report.Status,", "))
	for _,ns:=range report.NameServers{fmt.Printf("[NAMESERVER] %s\n",ns)}
	for _,event:=range report.Events{fmt.Printf("[REGISTRATION EVENT] %s: %s\n",event.Action,event.Date)}
	fmt.Println("\n[INTERPRETATION LIMITS]")
	for _,limitation:=range report.Limitations{fmt.Printf("- %s\n",limitation)}
	fmt.Printf("New observation: %t\n",added)
	printInfrastructureGraph(infrastructureGraph)
	return nil
}

func runASN(target,snapshotDir string)error{
 ctx,cancel:=context.WithTimeout(context.Background(),30*time.Second);defer cancel()
 report,err:=(&externalintel.ASNClient{}).LookupIP(ctx,target);if err!=nil{return err}
 if strings.TrimSpace(snapshotDir)==""{return fmt.Errorf("snapshot directory is required")}
 if err:=os.MkdirAll(snapshotDir,0750);err!=nil{return fmt.Errorf("create snapshot directory: %w",err)}
 registry,err:=evidence.OpenRegistry(filepath.Join(snapshotDir,"evidence.db"));if err!=nil{return fmt.Errorf("open evidence registry: %w",err)};defer registry.Close()
 added,err:=externalintel.RegisterASNReport(registry,report);if err!=nil{return err}
 infrastructureGraph,err:=graph.BuildFromRegistry(registry);if err!=nil{return fmt.Errorf("build ASN infrastructure graph: %w",err)}
 fmt.Println("[ORIGIN ASN INTELLIGENCE]")
 fmt.Printf("Target IP: %s\nRetrieved: %s\n",report.Target,report.RetrievedAt.Format(time.RFC3339))
 for _,record:=range report.Records{
  fmt.Printf("[ORIGIN] AS%d | Prefix: %s | Network label: %s | Country: %s | Registry: %s | Allocated: %s\n",record.ASN,record.Prefix,record.NetworkName,record.Country,record.Registry,record.Allocated)
  fmt.Printf("  Mapping source: %s\n  RDAP source: %s\n",record.MappingSource,record.RDAPSource)
 }
 fmt.Println("\n[INTERPRETATION LIMITS]")
 for _,limitation:=range report.Limitations{fmt.Printf("- %s\n",limitation)}
 fmt.Printf("New observation: %t\n",added)
 printInfrastructureGraph(infrastructureGraph)
 return nil
}

func runPassiveDNS(target,snapshotDir string)error{
 ctx,cancel:=context.WithTimeout(context.Background(),20*time.Second);defer cancel()
 client:=&externalintel.PassiveDNSClient{APIKey:strings.TrimSpace(os.Getenv("OTX_API_KEY"))}
 report,err:=client.LookupDomain(ctx,target);if err!=nil{return err}
 if strings.TrimSpace(snapshotDir)==""{return fmt.Errorf("snapshot directory is required")}
 if err:=os.MkdirAll(snapshotDir,0750);err!=nil{return fmt.Errorf("create snapshot directory: %w",err)}
 registry,err:=evidence.OpenRegistry(filepath.Join(snapshotDir,"evidence.db"));if err!=nil{return fmt.Errorf("open evidence registry: %w",err)};defer registry.Close()
 added,err:=externalintel.RegisterPassiveDNSReport(registry,report);if err!=nil{return err}
 infrastructureGraph,err:=graph.BuildFromRegistry(registry);if err!=nil{return fmt.Errorf("build passive-DNS infrastructure graph: %w",err)}
 fmt.Println("[PASSIVE DNS INTELLIGENCE]")
 fmt.Printf("Target: %s\nSource: %s\nRetrieved: %s\nProvider records: %d\nScoped unique observations: %d\n",report.Target,report.Source,report.RetrievedAt.Format(time.RFC3339),report.SourceRecordCount,len(report.Records))
 for _,record:=range report.Records{fmt.Printf("[HISTORICAL DNS] %s %s %s | first: %s | last: %s | ASN: %s\n",record.Hostname,record.RecordType,record.Address,record.FirstSeen,record.LastSeen,record.ASN)}
 if report.Truncated{fmt.Println("Warning: provider response may be truncated; treat this as a partial historical view.")}
 fmt.Println("\n[INTERPRETATION LIMITS]")
 for _,limitation:=range report.Limitations{fmt.Printf("- %s\n",limitation)}
 fmt.Printf("New observations: %d\n",added)
 printInfrastructureGraph(infrastructureGraph)
 return nil
}

func runThreatIntel(target,snapshotDir string)error{
 ctx,cancel:=context.WithTimeout(context.Background(),20*time.Second);defer cancel()
 client:=&externalintel.ThreatIntelClient{APIKey:strings.TrimSpace(os.Getenv("OTX_API_KEY"))}
 report,err:=client.Lookup(ctx,target);if err!=nil{return err}
 if strings.TrimSpace(snapshotDir)==""{return fmt.Errorf("snapshot directory is required")}
 if err:=os.MkdirAll(snapshotDir,0750);err!=nil{return fmt.Errorf("create snapshot directory: %w",err)}
 registry,err:=evidence.OpenRegistry(filepath.Join(snapshotDir,"evidence.db"));if err!=nil{return fmt.Errorf("open evidence registry: %w",err)};defer registry.Close()
 added,err:=externalintel.RegisterThreatIntelReport(registry,report);if err!=nil{return err}
 infrastructureGraph,err:=graph.BuildFromRegistry(registry);if err!=nil{return fmt.Errorf("build threat-intelligence graph: %w",err)}
 fmt.Println("[THREAT INTELLIGENCE CONTEXT]")
 fmt.Printf("Indicator: %s (%s)\nSource: %s\nRetrieved: %s\nCommunity pulse count: %d\nReturned pulse records: %d\n",report.Target,report.IndicatorType,report.Source,report.RetrievedAt.Format(time.RFC3339),report.PulseCount,len(report.Pulses))
 for _,pulse:=range report.Pulses{fmt.Printf("[COMMUNITY REPORT] %s | ID: %s | Tags: %s | Created: %s | Modified: %s\n",pulse.Name,pulse.ID,strings.Join(pulse.Tags,", "),pulse.Created,pulse.Modified)}
 if len(report.Pulses)==0{fmt.Println("No pulse records were returned; this is not proof that the indicator is benign.")}
 if report.Truncated{fmt.Println("Warning: provider reports more pulses than returned records; this is a partial view.")}
 fmt.Println("\n[INTERPRETATION LIMITS]")
 for _,limitation:=range report.Limitations{fmt.Printf("- %s\n",limitation)}
 fmt.Printf("New observation: %t\n",added)
 printInfrastructureGraph(infrastructureGraph)
 return nil
}

func runIPRDAP(target,snapshotDir string)error{
 ctx,cancel:=context.WithTimeout(context.Background(),25*time.Second);defer cancel()
 report,err:=(&externalintel.RDAPClient{}).LookupIP(ctx,target);if err!=nil{return err}
 if strings.TrimSpace(snapshotDir)==""{return fmt.Errorf("snapshot directory is required")}
 if err:=os.MkdirAll(snapshotDir,0750);err!=nil{return fmt.Errorf("create snapshot directory: %w",err)}
 registry,err:=evidence.OpenRegistry(filepath.Join(snapshotDir,"evidence.db"));if err!=nil{return fmt.Errorf("open evidence registry: %w",err)};defer registry.Close()
 added,err:=externalintel.RegisterIPRDAPReport(registry,report);if err!=nil{return err}
 infrastructureGraph,err:=graph.BuildFromRegistry(registry);if err!=nil{return fmt.Errorf("build IP RDAP graph: %w",err)}
 fmt.Println("[IP NETWORK REGISTRATION INTELLIGENCE]")
 fmt.Printf("Target IP: %s\nSource: %s\nRetrieved: %s\n",report.Target,report.Source,report.RetrievedAt.Format(time.RFC3339))
 fmt.Printf("Network handle: %s\nNetwork label: %s\nRange: %s - %s\nCountry label: %s\nNetwork type: %s\nStatus: %s\n",report.Handle,report.Name,report.StartAddress,report.EndAddress,report.Country,report.NetworkType,strings.Join(report.Status,", "))
 fmt.Println("\n[INTERPRETATION LIMITS]")
 for _,limitation:=range report.Limitations{fmt.Printf("- %s\n",limitation)}
 fmt.Printf("New observation: %t\n",added)
 printInfrastructureGraph(infrastructureGraph)
 return nil
}


func runBatchDNS(targetsFile, snapshotDir string, workers int) error {
	targets, err := batch.ReadTargetsFile(targetsFile)
	if err != nil {
		return err
	}
	results, err := batch.RunDNS(context.Background(), targets, workers, snapshotDir)
	if err != nil {
		return err
	}
	failures := 0
	fmt.Printf("[BATCH DNS INVESTIGATION] targets=%d workers=%d\n", len(results), workers)
	for _, result := range results {
		if result.Err != nil {
			failures++
			fmt.Printf("[FAILED] %s: %v\n", result.Target, result.Err)
			continue
		}
		state := "updated"
		if result.BaselineCreated {
			state = "baseline created"
		}
		fmt.Printf("[OK] %s | unique addresses=%d | changes=%d | %s\n", result.Target, result.AddressCount, result.ChangeCount, state)
	}
	fmt.Printf("Completed: %d | Failed: %d\n", len(results)-failures, failures)
	if failures > 0 {
		return fmt.Errorf("%d of %d target investigations failed; successful results were preserved", failures, len(results))
	}
	return nil
}
