package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/itsFuRy007/kem3t/internal/batch"
	"github.com/itsFuRy007/kem3t/internal/collectors"
	"github.com/itsFuRy007/kem3t/internal/events"
	"github.com/itsFuRy007/kem3t/internal/evidence"
	"github.com/itsFuRy007/kem3t/internal/externalintel"
	"github.com/itsFuRy007/kem3t/internal/graph"
	"github.com/itsFuRy007/kem3t/internal/history"
	"github.com/itsFuRy007/kem3t/internal/intelligence"
	"github.com/itsFuRy007/kem3t/internal/investigation"
	"github.com/itsFuRy007/kem3t/internal/pipeline"
)

var commandContext = context.Background()

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	commandContext = ctx
	if err := run(); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintf(os.Stderr, "Error: %s\n", sanitizeTerminalText(err.Error()))
		os.Exit(1)
	}
}

func run() error {
	flags := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flags.SetOutput(os.Stderr)

	mode := flags.String("mode", "demo", "Mode: demo, dns, plan-feedback, tls, tcp, http, investigate, history, batch-dns, ct, rdap, iprdap, asn, pdns, or threat")
	exportJSON := flags.String("export-json", "", "Write the target-scoped DNS intelligence report as versioned JSON (DNS mode only)")
	exportMarkdown := flags.String("export-markdown", "", "Write a researcher-oriented Markdown intelligence dossier (investigate mode only)")
	planStatePath := flags.String("plan-state", "", "Load and update adaptive investigation feedback state (DNS and plan-feedback modes)")
	planFeedbackItem := flags.String("plan-feedback-item", "", "Saved plan task ID to update (plan-feedback mode)")
	planFeedbackOutcome := flags.String("plan-feedback-outcome", "", "Feedback outcome: COMPLETED, INCONCLUSIVE, BLOCKED, or NOT_APPLICABLE")
	planFeedbackEvidence := flags.String("plan-feedback-evidence-ids", "", "Comma-separated evidence IDs supporting COMPLETED feedback")
	planFeedbackNote := flags.String("plan-feedback-note", "", "Required explanation for INCONCLUSIVE, BLOCKED, or NOT_APPLICABLE feedback")
	target := flags.String("target", "", "Target hostname or IP address")
	targetsFile := flags.String("targets-file", "", "File with one hostname/IP per line (batch-dns mode)")
	workers := flags.Int("workers", 4, "Maximum concurrent targets for batch-dns mode (hard cap 64)")
	port := flags.Int("port", 443, "TCP port for TLS mode")
	httpScheme := flags.String("http-scheme", "auto", "HTTP scheme: auto, http, or https")
	httpPort := flags.Int("http-port", 0, "HTTP port override (0 uses scheme defaults)")
	startPort := flags.Int("start-port", 1, "First TCP port to scan")
	endPort := flags.Int("end-port", 1024, "Last TCP port to scan")
	enableActive := flags.Bool("enable-active", false, "In investigate mode, explicitly enable bounded TCP/TLS/HTTP checks against the supplied target")
	snapshotDir := flags.String(
		"snapshot-dir",
		".kem3t/snapshots",
		"Directory for DNS snapshots",
	)

	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}

	selectedMode := strings.ToLower(strings.TrimSpace(*mode))
	if strings.TrimSpace(*exportJSON) != "" && selectedMode != "dns" {
		return fmt.Errorf("-export-json is supported only in DNS mode")
	}
	if strings.TrimSpace(*exportMarkdown) != "" && selectedMode != "investigate" {
		return fmt.Errorf("-export-markdown is supported only in investigate mode")
	}
	if strings.TrimSpace(*planStatePath) != "" && selectedMode != "dns" && selectedMode != "plan-feedback" {
		return fmt.Errorf("-plan-state is supported only in DNS and plan-feedback modes")
	}
	if selectedMode != "plan-feedback" && (strings.TrimSpace(*planFeedbackItem) != "" || strings.TrimSpace(*planFeedbackOutcome) != "" || strings.TrimSpace(*planFeedbackEvidence) != "" || strings.TrimSpace(*planFeedbackNote) != "") {
		return fmt.Errorf("plan feedback flags are supported only in plan-feedback mode")
	}

	switch selectedMode {
	case "plan-feedback":
		return runPlanFeedback(*planStatePath, *planFeedbackItem, *planFeedbackOutcome, *planFeedbackEvidence, *planFeedbackNote)
	case "investigate":
		if strings.TrimSpace(*target) == "" {
			return fmt.Errorf("-target is required in investigate mode")
		}
		return runInvestigation(strings.TrimSpace(*target), *snapshotDir, *enableActive, *startPort, *endPort, *port, *httpScheme, *httpPort, *exportMarkdown)
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
		if strings.TrimSpace(*target) == "" {
			return fmt.Errorf("-target is required in IP RDAP mode")
		}
		return runIPRDAP(strings.TrimSpace(*target), *snapshotDir)
	case "asn":
		if strings.TrimSpace(*target) == "" {
			return fmt.Errorf("-target is required in ASN mode")
		}
		return runASN(strings.TrimSpace(*target), *snapshotDir)
	case "pdns":
		if strings.TrimSpace(*target) == "" {
			return fmt.Errorf("-target is required in passive-DNS mode")
		}
		return runPassiveDNS(strings.TrimSpace(*target), *snapshotDir)
	case "threat":
		if strings.TrimSpace(*target) == "" {
			return fmt.Errorf("-target is required in threat-intelligence mode")
		}
		return runThreatIntel(strings.TrimSpace(*target), *snapshotDir)
	case "demo":
		return runDemo()
	case "dns":
		if strings.TrimSpace(*target) == "" {
			return fmt.Errorf("-target is required in DNS mode")
		}
		return runDNSWithPlanState(strings.TrimSpace(*target), *snapshotDir, *exportJSON, *planStatePath)
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

func runInvestigation(target, snapshotDir string, enableActive bool, startPort, endPort, tlsPort int, httpScheme string, httpPort int, exportMarkdown string) (retErr error) {
	if strings.TrimSpace(snapshotDir) == "" {
		return fmt.Errorf("snapshot directory is required")
	}
	if enableActive && (startPort < 1 || endPort > 65535 || startPort > endPort) {
		return fmt.Errorf("invalid authorized TCP port range %d-%d", startPort, endPort)
	}
	if enableActive && (tlsPort < 1 || tlsPort > 65535) {
		return fmt.Errorf("TLS port must be between 1 and 65535")
	}
	registry, err := evidence.OpenRegistry(filepath.Join(snapshotDir, "evidence.db"))
	if err != nil {
		return fmt.Errorf("open shared evidence registry: %w", err)
	}
	defer func() {
		if closeErr := registry.Close(); closeErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close shared evidence registry: %w", closeErr))
		}
	}()

	var stages []investigation.Stage
	if net.ParseIP(target) != nil {
		stages = append(stages, investigation.NewIPRDAPStage(), investigation.NewASNStage())
	} else {
		stages = append(stages, investigation.NewDNSStage(target), investigation.NewCTStage(), investigation.NewRDAPDomainStage())
	}
	if apiKey := strings.TrimSpace(os.Getenv("OTX_API_KEY")); apiKey != "" {
		stages = append(stages,
			investigation.NewPassiveDNSStageWithClient(&externalintel.PassiveDNSClient{APIKey: apiKey}),
			investigation.NewThreatIntelStageWithClient(&externalintel.ThreatIntelClient{APIKey: apiKey}),
		)
	}
	if enableActive {
		stages = append(stages,
			investigation.NewTCPStage(target, startPort, endPort),
			investigation.NewTLSStage(target, tlsPort),
			investigation.NewHTTPStage(target, httpScheme, httpPort),
		)
	}
	engine := investigation.Engine{Registry: registry, Stages: stages, Planner: investigation.NewCTSubdomainDNSPlanner(8), SnapshotDir: snapshotDir}
	result, runErr := engine.Run(commandContext, target)
	if runErr != nil {
		if strings.TrimSpace(result.RunID) == "" {
			return fmt.Errorf("investigation: %w", runErr)
		}
		retErr = errors.Join(retErr, fmt.Errorf("investigation: %w", runErr))
	}
	if runErr == nil && result.Partial {
		for _, outcome := range result.Stages {
			if outcome.Error != "" {
				retErr = errors.Join(retErr, fmt.Errorf("investigation partially failed at %s: %s", outcome.Name, outcome.Error))
			}
		}
		if retErr == nil {
			retErr = errors.New("investigation completed partially")
		}
	}

	fmt.Println("[UNIFIED INVESTIGATION]")
	safePrintf("Target: %s\nRun ID: %s\nPartial: %t\n", result.Target, result.RunID, result.Partial)
	if path := strings.TrimSpace(exportMarkdown); path != "" {
		if strings.TrimSpace(result.Report.Target) == "" {
			retErr = errors.Join(retErr, fmt.Errorf("cannot render Markdown intelligence dossier: investigation report is unavailable"))
		} else {
			markdown, renderErr := intelligence.RenderMarkdownReport(result.Report)
			if renderErr != nil {
				retErr = errors.Join(retErr, fmt.Errorf("render Markdown intelligence dossier: %w", renderErr))
			} else if writeErr := writeFileAtomic(path, []byte(markdown)); writeErr != nil {
				retErr = errors.Join(retErr, fmt.Errorf("write Markdown intelligence dossier: %w", writeErr))
			} else {
				safePrintf("[MARKDOWN DOSSIER] %s\n", path)
			}
		}
	}
	for _, stage := range result.Stages {
		state := "completed"
		if stage.Error != "" {
			state = "failed/partial"
		}
		safePrintf("[%s] %s — events: %d, evidence: %d, observations: %d\n", state, stage.Name, stage.Result.Events, stage.Result.Evidence, stage.Result.Observations)
		if stage.Error != "" {
			safePrintf("  Error: %s\n", stage.Error)
		}
		for _, limitation := range stage.Result.Limitations {
			safePrintf("  Limitation: %s\n", limitation)
		}
	}
	evidenceCount, observationCount := 0, 0
	for _, stage := range result.Stages {
		evidenceCount += stage.Result.Evidence
		observationCount += stage.Result.Observations
	}
	safePrintf("\nNew evidence records: %d | New observations: %d\n", evidenceCount, observationCount)
	if strings.TrimSpace(result.Report.Target) != "" {
		printIntelligenceReport(result.Report)
		printInvestigationPlan(result.Report.InvestigationPlan)
	} else {
		fmt.Println("\n[REPORT UNAVAILABLE] The investigation did not produce a valid intelligence report.")
	}
	printInfrastructureGraph(result.Graph)
	if result.HistoryPersisted {
		safePrintf("\n[HISTORY] Unified investigation snapshot saved under %s/history\n", snapshotDir)
	} else {
		safePrintf("\n[HISTORY] No completed snapshot was persisted under %s/history\n", snapshotDir)
	}
	return retErr
}

func runDemo() error {
	ctx := commandContext
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
		commandContext,
		target,
		startPort,
		endPort,
		snapshotDir,
	)
	if err != nil {
		return err
	}

	counts, err := countTCPStates(result.Events)
	if err != nil {
		return err
	}
	for _, event := range result.Events {
		state := strings.ToLower(strings.TrimSpace(event.Data["state"]))
		reason := strings.TrimSpace(event.Data["reason"])
		if reason != "" {
			safePrintf("[%s] %s/tcp — %s\n", strings.ToUpper(state), event.Data["port"], reason)
		} else {
			safePrintf("[%s] %s/tcp\n", strings.ToUpper(state), event.Data["port"])
		}
	}
	safePrintf("TCP states: OPEN=%d | CLOSED=%d | UNKNOWN=%d | TOTAL=%d\n",
		counts["open"], counts["closed"], counts["unknown"], len(result.Events))
	safePrintf("Evidence records: %d | Graph nodes: %d | Graph edges: %d\n",
		len(result.Evidence), len(result.Graph.Nodes), len(result.Graph.Edges))
	for _, finding := range result.Findings {
		printFinding(finding)
	}
	printIntelligenceReport(result.Report)
	printInvestigationPlan(result.Report.InvestigationPlan)
	printInfrastructureGraph(result.Graph)
	return nil
}
func countTCPStates(eventsIn []events.Event) (map[string]int, error) {
	counts := map[string]int{"open": 0, "closed": 0, "unknown": 0}
	for _, event := range eventsIn {
		state := strings.ToLower(strings.TrimSpace(event.Data["state"]))
		if _, ok := counts[state]; !ok {
			return nil, fmt.Errorf("unsupported TCP state %q for port %s", state, event.Data["port"])
		}
		counts[state]++
	}
	return counts, nil
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
		safePrintf("Target: %s\n", result.Event.Target)
		safePrintf("Port: %s\n", result.Event.Data["port"])
		safePrintf("Subject: %s\n", result.Event.Data["subject"])
		safePrintf("Issuer: %s\n", result.Event.Data["issuer"])
		safePrintf("TLS Version: %s\n", result.Event.Data["tls_version"])
		safePrintf("Verified: %s\n", result.Event.Data["verified"])
		if reason := strings.TrimSpace(result.Event.Data["verification_error"]); reason != "" {
			safePrintf("Verification error: %s\n", reason)
		}
		safePrintf("SHA-256: %s\n", result.Event.Data["sha256_fingerprint"])
	}

	printInfrastructureGraph(result.Graph)
	return nil
}

func runHTTP(target, scheme string, port int, snapshotDir string) error {
	result, err := pipeline.RunHTTP(commandContext, target, scheme, port, snapshotDir)
	if err != nil {
		return err
	}
	if result.Event != nil {
		fmt.Println("[HTTP SERVICE]")
		safePrintf("Target: %s\n", result.Event.Target)
		safePrintf("URL: %s\n", result.Event.Data["url"])
		safePrintf("Final URL: %s\n", result.Event.Data["final_url"])
		safePrintf("Status: %s\n", result.Event.Data["status_code"])
		safePrintf("Title: %s\n", result.Event.Data["title"])
		safePrintf("Server: %s\n", result.Event.Data["server"])
		safePrintf("Content-Type: %s\n", result.Event.Data["content_type"])
		safePrintf("Redirects: %s\n", result.Event.Data["redirect_count"])
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(result.Event.Data["url"])), "https://") {
			safePrintf("TLS verified: %s\n", result.Event.Data["tls_verified"])
		} else {
			fmt.Println("TLS verification: not applicable (plain HTTP)")
		}
		safePrintf("Body truncated: %s\n", result.Event.Data["body_truncated"])
	}
	printInfrastructureGraph(result.Graph)
	return nil
}

func runDNS(target, snapshotDir, exportJSON string) error {
	return runDNSWithPlanState(target, snapshotDir, exportJSON, "")
}

func runPlanFeedback(statePath, itemID, outcome, evidenceList, note string) error {
	statePath = strings.TrimSpace(statePath)
	if statePath == "" {
		return fmt.Errorf("-plan-state is required in plan-feedback mode")
	}
	itemID = strings.TrimSpace(itemID)
	outcome = strings.ToUpper(strings.TrimSpace(outcome))
	if itemID == "" || outcome == "" {
		return fmt.Errorf("-plan-feedback-item and -plan-feedback-outcome are required")
	}
	data, err := os.ReadFile(statePath)
	if err != nil {
		return fmt.Errorf("read investigation plan state: %w", err)
	}
	var state intelligence.InvestigationPlanState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("decode investigation plan state: %w", err)
	}
	if err := state.Validate(); err != nil {
		return fmt.Errorf("validate investigation plan state: %w", err)
	}
	if state.PreviousPlan == nil {
		return fmt.Errorf("no saved investigation plan; run DNS mode with -plan-state first")
	}
	evidenceIDs := make([]string, 0)
	for _, raw := range strings.Split(evidenceList, ",") {
		if id := strings.TrimSpace(raw); id != "" {
			evidenceIDs = append(evidenceIDs, id)
		}
	}
	feedback := intelligence.InvestigationFeedback{
		ItemID: itemID, Outcome: outcome, EvidenceIDs: evidenceIDs, Note: strings.TrimSpace(note),
	}
	state.Feedback = append(state.Feedback, feedback)
	if err := state.Validate(); err != nil {
		return fmt.Errorf("invalid plan feedback: %w", err)
	}
	updated, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode investigation plan state: %w", err)
	}
	if err := writeFileAtomic(statePath, updated); err != nil {
		return fmt.Errorf("save plan feedback: %w", err)
	}
	safePrintf("[PLAN FEEDBACK QUEUED] %s -> %s\n", itemID, outcome)
	fmt.Println("Feedback will be applied to the plan during the next DNS investigation using this -plan-state file.")
	return nil
}

func runDNSWithPlanState(target, snapshotDir, exportJSON, planStatePath string) error {
	if strings.TrimSpace(planStatePath) != "" && filepath.Clean(planStatePath) == filepath.Clean(exportJSON) && strings.TrimSpace(exportJSON) != "" {
		return fmt.Errorf("-plan-state and -export-json must use different paths")
	}
	state := intelligence.InvestigationPlanState{Feedback: []intelligence.InvestigationFeedback{}}
	if strings.TrimSpace(planStatePath) != "" {
		data, err := os.ReadFile(planStatePath)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("read investigation plan state: %w", err)
		}
		if err == nil {
			if err := json.Unmarshal(data, &state); err != nil {
				return fmt.Errorf("decode investigation plan state: %w", err)
			}
			if err := state.Validate(); err != nil {
				return fmt.Errorf("validate investigation plan state: %w", err)
			}
		}
	}
	result, err := pipeline.RunDNSWithPlanFeedback(
		context.Background(),
		target,
		snapshotDir,
		state.PreviousPlan,
		state.Feedback,
	)
	if err != nil {
		return err
	}

	for _, finding := range result.Findings {
		printFinding(finding)
	}

	printIntelligenceReport(result.Report)
	printInvestigationPlan(result.Report.InvestigationPlan)
	if strings.TrimSpace(exportJSON) != "" {
		if err := writeInvestigationExport(exportJSON, intelligence.NewDNSInvestigationExport(target, &result.Report, result.CurrentSnapshot, result.PreviousSnapshot, result.Changes, result.History, result.BaselineCreated)); err != nil {
			return fmt.Errorf("write investigation export: %w", err)
		}
		safePrintf("[INVESTIGATION EXPORT] %s\n", exportJSON)
	}
	if strings.TrimSpace(planStatePath) != "" {
		state.PreviousPlan = &result.Report.InvestigationPlan
		state.Feedback = []intelligence.InvestigationFeedback{}
		stateData, err := json.MarshalIndent(state, "", "  ")
		if err != nil {
			return fmt.Errorf("encode investigation plan state: %w", err)
		}
		if err := writeFileAtomic(planStatePath, stateData); err != nil {
			return fmt.Errorf("write investigation plan state: %w", err)
		}
		safePrintf("[ADAPTIVE PLAN STATE] %s\n", planStatePath)
	}
	printInfrastructureGraph(result.Graph)

	if result.BaselineCreated {
		fmt.Println("\n[BASELINE CREATED]")
		safePrintf("Target: %s\n", result.CurrentSnapshot.Target)
		safePrintf(
			"Unique addresses: %d\n",
			len(result.CurrentSnapshot.Addresses),
		)
		safePrintf(
			"Snapshot: %s\n",
			storePath(snapshotDir, result.CurrentSnapshot.Target),
		)
		fmt.Println("Run the same command again to detect DNS changes.")
		return nil
	}

	fmt.Println("\n[DNS CHANGE REPORT]")
	safePrintf("Target: %s\n", result.CurrentSnapshot.Target)

	if result.PreviousSnapshot != nil {
		safePrintf(
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
			safePrintf("[%s] %s\n", change.Type, change.Address)
		}
	}

	if result.History != nil {
		printDNSHistory(*result.History)
	}

	safePrintf(
		"Updated snapshot: %s\n",
		storePath(snapshotDir, result.CurrentSnapshot.Target),
	)

	return nil
}

func writeInvestigationExport(path string, export intelligence.InvestigationExport) error {
	data, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return fmt.Errorf("encode scoped report: %w", err)
	}
	return writeFileAtomic(path, data)
}

func writeFileAtomic(path string, data []byte) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("output path is required")
	}
	data = append([]byte(nil), data...)
	if len(data) == 0 || data[len(data)-1] != '\n' {
		data = append(data, '\n')
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	file, err := os.CreateTemp(dir, ".kem3t-export-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary output: %w", err)
	}
	tempPath := file.Name()
	defer os.Remove(tempPath)
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return fmt.Errorf("restrict output permissions: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return fmt.Errorf("write output: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("sync output: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close output: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("atomically replace output: %w", err)
	}
	return nil
}

func printInvestigationPlan(plan intelligence.InvestigationPlan) {
	fmt.Println("\n[ADAPTIVE INVESTIGATION PLAN]")
	safePrintf("Target: %s | Revision: %s\n", plan.Target, plan.Revision)
	safePrintln(plan.Summary)
	for _, item := range plan.Items {
		safePrintf("[%s | %s | %s] %s\n", item.Status, item.PriorityLabel, item.ID, item.Action)
		safePrintf("  Why: %s\n", item.Rationale)
		safePrintf("  References: %s\n", strings.Join(item.References, ", "))
		if len(item.EvidenceIDs) > 0 {
			safePrintf("  Outcome evidence: %s\n", strings.Join(item.EvidenceIDs, ", "))
		}
	}
}

func correlationTypeStrings(values []intelligence.CorrelationType) []string {
	result := make([]string, len(values))
	for i, value := range values {
		result[i] = string(value)
	}
	return result
}

func printIntelligenceReport(report intelligence.IntelligenceReport) {
	fmt.Println("\n[INTELLIGENCE REPORT]")
	safePrintf("Target: %s\n", report.Target)
	safePrintf("Findings: %d\n", len(report.Findings))
	safePrintf("Service surfaces: %d\n", len(report.ServiceSurfaces))
	safePrintf("Correlations: %d\n", len(report.Correlations))
	safePrintf("Discoveries: %d | Multi-hop paths: %d | Recurring pivots: %d\n", len(report.Discoveries), len(report.DiscoveryPaths), len(report.DiscoveryPivots))
	safePrintf("Hypotheses: %d | Verification assessments: %d\n", len(report.Hypotheses), len(report.VerificationAssessments))
	safePrintf("Intelligence gaps: %d\n", len(report.IntelligenceGaps))
	safePrintf("Prioritized findings: %d\n", len(report.PrioritizedFindings))

	correlationsByID := make(map[string]intelligence.Correlation, len(report.Correlations))
	for _, correlation := range report.Correlations {
		correlationsByID[correlation.ID] = correlation
	}
	pathsByID := make(map[string]intelligence.DiscoveryPath, len(report.DiscoveryPaths))
	for _, path := range report.DiscoveryPaths {
		pathsByID[path.ID] = path
	}

	if len(report.Findings) > 0 {
		fmt.Println("\n[FINDINGS]")
		for _, finding := range report.Findings {
			printFinding(finding)
		}
	}

	if len(report.ServiceSurfaces) > 0 {
		fmt.Println("\n[SERVICE SURFACES]")
		for _, surface := range report.ServiceSurfaces {
			safePrintf("%s\n", surface.Summary)
			safePrintf("  Protocols: %s | Evidence: %s\n", strings.Join(surface.Protocols, ", "), strings.Join(surface.EvidenceIDs, ", "))
			if len(surface.TCPStates) > 0 {
				safePrintf("  TCP states: %s\n", strings.Join(surface.TCPStates, ", "))
			}
			for _, http := range surface.HTTP {
				safePrintf("  HTTP: %s status=%d title=%q server=%q final_url=%s\n", strings.ToUpper(http.Scheme), http.StatusCode, http.Title, http.Server, http.FinalURL)
			}
			for _, tls := range surface.TLS {
				safePrintf("  TLS: %s verified=%t fingerprint=%s expires=%s\n", tls.TLSVersion, tls.Verified, tls.Fingerprint, tls.NotAfter.UTC().Format(time.RFC3339))
			}
			safePrintf("  Evidence refs: %s\n", strings.Join(surface.EvidenceIDs, ", "))
			safePrintf("  Observation refs: %s\n", strings.Join(surface.ObservationIDs, ", "))
			for _, limitation := range surface.Limitations {
				safePrintf("  Limitation: %s\n", limitation)
			}
			for _, step := range surface.NextSteps {
				safePrintf("  Research next step: %s\n", step)
			}
		}
	}

	if len(report.PrioritizedFindings) > 0 {
		fmt.Println("\n[INVESTIGATION PRIORITIES]")
		for _, item := range report.PrioritizedFindings {
			safePrintf("[%s] %s\n", item.Priority, item.Finding.Title)
			safePrintf("  Reason: %s\n", item.Reason)
		}
	}

	if strings.TrimSpace(report.Narrative.Summary) != "" {
		fmt.Println("\n[RESEARCH SUMMARY]")
		safePrintln(report.Narrative.Summary)
	}

	if len(report.IntelligenceGaps) > 0 {
		fmt.Println("\n[INTELLIGENCE GAPS]")
		for _, gap := range report.IntelligenceGaps {
			safePrintf("[%s] %s — %s\n", gap.Priority, gap.Subject, gap.Unknown)
			safePrintf("  Why it matters: %s\n", gap.WhyItMatters)
			safePrintf("  Required evidence: %s\n", strings.Join(gap.RequiredEvidence, "; "))
			safePrintf("  Suggested action: %s\n", gap.SuggestedAction)
			safePrintf("  Evidence references: %s\n", strings.Join(gap.References, ", "))
		}
	}

	if len(report.Correlations) > 0 {
		fmt.Println("\n[CORRELATIONS]")
		for _, item := range report.Correlations {
			safePrintf("[%s] %s\n", item.Type, item.ID)
			safePrintf("  Shared value: %s\n", item.SharedValue)
			safePrintf("  Entities: %s\n", strings.Join(item.Entities, ", "))
			safePrintf("  Evidence records: %d\n", len(item.EvidenceIDs))
			safePrintf("  Confidence: %s (scope: %s)\n", item.Confidence, item.ConfidenceScope)
			safePrintf("  Evidence refs: %s\n", strings.Join(item.EvidenceIDs, ", "))
			safePrintf("  Observation refs: %s\n", strings.Join(item.ObservationIDs, ", "))
			safePrintf("  Limitations: %s\n", item.Limitations)
		}
	}

	if len(report.Discoveries) > 0 {
		fmt.Println("\n[HIGHER-ORDER DISCOVERIES]")
		for _, discovery := range report.Discoveries {
			safePrintf("[%s] %s\n", discovery.Confidence, discovery.ID)
			safePrintf("  Entities: %s\n", strings.Join(discovery.Entities, " -> "))
			safePrintf("  Statement: %s\n", discovery.Statement)
			safePrintf("  Signal types: %s | diversity: %d\n", strings.Join(correlationTypeStrings(discovery.SignalTypes), ", "), discovery.SignalDiversity)
			safePrintf("  Shared values: %s\n", strings.Join(discovery.SharedValues, ", "))
			safePrintf("  Correlation refs: %s\n", strings.Join(discovery.CorrelationIDs, ", "))
			safePrintf("  Why it matters: %s\n", discovery.WhyItMatters)
			safePrintf("  Alternative explanations: %s\n", discovery.AlternativeExplanations)
			for _, correlationID := range discovery.CorrelationIDs {
				if correlation, ok := correlationsByID[correlationID]; ok {
					safePrintf("  Evidence for %s: %s\n", correlationID, strings.Join(correlation.EvidenceIDs, ", "))
					safePrintf("  Observations for %s: %s\n", correlationID, strings.Join(correlation.ObservationIDs, ", "))
				}
			}
			for _, step := range discovery.Verification {
				safePrintf("  Verify: %s\n", step)
			}
		}
	}

	if len(report.DiscoveryPaths) > 0 {
		fmt.Println("\n[MULTI-HOP DISCOVERY PATHS]")
		for _, path := range report.DiscoveryPaths {
			safePrintf("[%s] %s\n", path.Confidence, path.ID)
			safePrintf("  Route: %s\n", strings.Join(path.Entities, " -> "))
			safePrintf("  Statement: %s\n", path.Statement)
			safePrintf("  Correlation refs: %s\n", strings.Join(path.CorrelationIDs, ", "))
			safePrintf("  Signal types: %s\n", strings.Join(correlationTypeStrings(path.SignalTypes), ", "))
			safePrintf("  Why it matters: %s\n", path.WhyItMatters)
			safePrintf("  Alternative explanations: %s\n", path.AlternativeExplanations)
			for _, correlationID := range path.CorrelationIDs {
				if correlation, ok := correlationsByID[correlationID]; ok {
					safePrintf("  Evidence for %s: %s\n", correlationID, strings.Join(correlation.EvidenceIDs, ", "))
					safePrintf("  Observations for %s: %s\n", correlationID, strings.Join(correlation.ObservationIDs, ", "))
				}
			}
			for _, step := range path.Verification {
				safePrintf("  Verify: %s\n", step)
			}
		}
	}

	if len(report.DiscoveryPivots) > 0 {
		fmt.Println("\n[RECURRING INVESTIGATION PIVOTS]")
		for _, pivot := range report.DiscoveryPivots {
			safePrintf("[%s] %s — %s\n", pivot.Confidence, pivot.Pivot, pivot.ID)
			safePrintf("  Connected entities: %s\n", strings.Join(pivot.ConnectedEntities, ", "))
			safePrintf("  Supporting paths: %s\n", strings.Join(pivot.PathIDs, ", "))
			safePrintf("  Signal types: %s | diversity: %d\n", strings.Join(correlationTypeStrings(pivot.SignalTypes), ", "), pivot.SignalDiversity)
			safePrintf("  Statement: %s\n", pivot.Statement)
			safePrintf("  Why it matters: %s\n", pivot.WhyItMatters)
			safePrintf("  Alternative explanations: %s\n", pivot.AlternativeExplanations)
			for _, pathID := range pivot.PathIDs {
				if path, ok := pathsByID[pathID]; ok {
					safePrintf("  Path %s: %s\n", pathID, strings.Join(path.Entities, " -> "))
				}
			}
			for _, step := range pivot.Verification {
				safePrintf("  Verify: %s\n", step)
			}
		}
	}

	if len(report.Hypotheses) > 0 {
		fmt.Println("\n[HYPOTHESES]")
		for _, item := range report.Hypotheses {
			safePrintf("[%s] %s\n", item.Confidence, item.Title)
			safePrintf("  Statement: %s\n", item.Statement)
			safePrintf("  Supporting evidence refs: %s\n", strings.Join(item.SupportingIDs, ", "))
			safePrintf("  Supporting facts: %s\n", strings.Join(item.SupportingFacts, " | "))
			safePrintf("  Alternative explanations: %s\n", item.Alternative)
			safePrintf("  Limitations: %s\n", item.Limitations)
			if len(item.Verification) > 0 {
				fmt.Println("  Verification steps:")
				for _, step := range item.Verification {
					safePrintf("    - %s\n", step)
				}
			}
		}
	}
	if len(report.VerificationAssessments) > 0 {
		fmt.Println("\n[VERIFICATION ASSESSMENTS]")
		for _, assessment := range report.VerificationAssessments {
			safePrintf("[%s] %s\n", assessment.Status, assessment.HypothesisID)
			safePrintf("  Assessment: %s\n", assessment.Explanation)
			if len(assessment.SupportingEvidenceIDs) > 0 {
				safePrintf("  Supporting evidence: %s\n", strings.Join(assessment.SupportingEvidenceIDs, ", "))
				for _, fact := range assessment.SupportingFacts {
					safePrintf("    Supports: %s\n", fact)
				}
			}
			if len(assessment.ContradictingEvidenceIDs) > 0 {
				safePrintf("  Contradicting evidence: %s\n", strings.Join(assessment.ContradictingEvidenceIDs, ", "))
				for _, fact := range assessment.ContradictingFacts {
					safePrintf("    Contradicts: %s\n", fact)
				}
			}
			if len(assessment.ExcludedEvidenceIDs) > 0 {
				safePrintf("  Excluded/reused evidence: %s\n", strings.Join(assessment.ExcludedEvidenceIDs, ", "))
			}
			safePrintf("  Limitations: %s\n", assessment.Limitations)
		}
	}

	if len(report.Narrative.Signals) > 0 {
		fmt.Println("\n[RESEARCH NARRATIVE SIGNALS]")
		for _, signal := range report.Narrative.Signals {
			safePrintf("[%s | %s] %s\n", signal.Kind, signal.Confidence, signal.ID)
			safePrintf("  %s\n", signal.Summary)
			if signal.AlternativeExplanations != "" {
				safePrintf("  Alternatives/limitations: %s\n", signal.AlternativeExplanations)
			}
			safePrintf("  References: %s\n", strings.Join(signal.References, ", "))
		}
	}

	if len(report.Narrative.NextSteps) > 0 {
		fmt.Println("\n[RESEARCHER NEXT STEPS]")
		for _, step := range report.Narrative.NextSteps {
			safePrintf("%s: %s\n", step.ID, step.Action)
			safePrintf("  Reason: %s\n", step.Reason)
			safePrintf("  References: %s\n", strings.Join(step.References, ", "))
		}
	}

	if len(report.Narrative.Limitations) > 0 {
		fmt.Println("\n[REPORT LIMITATIONS]")
		for _, limitation := range report.Narrative.Limitations {
			safePrintf("- %s\n", limitation)
		}
	}

}

func printDNSHistory(history intelligence.DNSHistoryComparison) {
	fmt.Println("\n[DNS HISTORY COMPARISON]")
	safePrintf("Target: %s\n", history.Target)
	safePrintf(
		"Previous unique addresses: %d\n",
		history.PreviousCount,
	)
	safePrintf(
		"Current unique addresses: %d\n",
		history.CurrentCount,
	)

	printAddressGroup("Added", history.Added)
	printAddressGroup("Removed", history.Removed)
	printAddressGroup("Unchanged", history.Unchanged)
}

func printAddressGroup(label string, addresses []string) {
	safePrintf("%s (%d):\n", label, len(addresses))

	if len(addresses) == 0 {
		fmt.Println("  None")
		return
	}

	for _, address := range addresses {
		safePrintf("  - %s\n", address)
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
	safePrintf("\n[%s] %s\n", finding.Priority, finding.Title)
	safePrintf("Fact: %s\n", finding.Fact)

	if finding.Observation != "" {
		safePrintf("Observation: %s\n", finding.Observation)
	}

	if finding.PossibleSignificance != "" {
		safePrintf("Possible significance: %s\n", finding.PossibleSignificance)
	}

	fmt.Println("Next steps:")
	for _, step := range finding.NextSteps {
		safePrintf("  - %s\n", step)
	}

	safePrintf("Evidence events: %d\n", len(finding.Evidence))
	for _, event := range finding.Evidence {
		safePrintf("  Event ref: %s | %s | target=%s | source=%s | observed=%s\n",
			event.ID, event.Type, event.Target, event.Source, event.Timestamp.UTC().Format(time.RFC3339))
	}
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
	safePrintf("Database: %s\n", dbPath)
	safePrintf("Generalized snapshots: %s\n", filepath.Join(snapshotDir, "history"))
	if target != "" {
		safePrintf("Target: %s\n", target)
	}
	safePrintf("Runs: %d | Snapshots: %d | Changes: %d\n\n", len(runs), len(timeline.Snapshots), len(timeline.Changes))

	if len(runs) == 0 {
		fmt.Println("No collection runs found.")
		return nil
	}
	for i, run := range runs {
		safePrintf("%d. [%s] %s\n", i+1, run.Status, run.Target)
		safePrintf("   Run ID: %s\n", run.ID)
		safePrintf("   Started: %s\n", run.StartedAt.Format(time.RFC3339))
		if !run.FinishedAt.IsZero() {
			safePrintf("   Finished: %s\n", run.FinishedAt.Format(time.RFC3339))
			safePrintf("   Duration: %s\n", run.FinishedAt.Sub(run.StartedAt).Round(time.Millisecond))
		}
		safePrintf("   Events: %d | Unique addresses: %d\n", run.EventCount, run.AddressCount)
		if run.ErrorMessage != "" {
			safePrintf("   Error: %s\n", run.ErrorMessage)
		}
		fmt.Println()
	}

	fmt.Println("[INFRASTRUCTURE TIMELINE]")
	if len(timeline.Snapshots) == 0 {
		fmt.Println("No completed collection snapshots are available.")
	} else {
		for _, snapshot := range timeline.Snapshots {
			safePrintf("[%s] %s | %s | records: %d\n", snapshot.CollectedAt.Format(time.RFC3339), snapshot.Collector, snapshot.Target, len(snapshot.Records))
			safePrintf("  Run: %s\n", snapshot.RunID)
		}
	}

	fmt.Println("\n[HISTORICAL CHANGES]")
	if len(timeline.Changes) == 0 {
		fmt.Println("No changes between comparable snapshots.")
	} else {
		for _, change := range timeline.Changes {
			safePrintf("[%s] %s | %s | %s\n", change.Type, change.Collector, change.Target, change.Key)
			safePrintf("  Runs: %s -> %s | evidence refs: %d | observation refs: %d\n", change.PreviousRunID, change.CurrentRunID, len(change.EvidenceIDs), len(change.ObservationIDs))
		}
	}

	fmt.Println("\n[ANOMALY REVIEW SIGNALS]")
	anomalies := history.DetectAnomalies(timeline)
	if len(anomalies) == 0 {
		fmt.Println("No high-change-volume signals detected.")
	} else {
		for _, anomaly := range anomalies {
			safePrintf("[%s] %s | %s | run %s\n", anomaly.Type, anomaly.Target, anomaly.Collector, anomaly.RunID)
			safePrintf("  %s\n", anomaly.Summary)
		}
	}
	fmt.Println("Anomaly signals are review prompts, not proof of compromise or malicious activity.")
	return nil
}

func printInfrastructureGraph(g graph.Graph) {
	fmt.Println("\n[INFRASTRUCTURE GRAPH]")
	safePrintf("Nodes: %d\n", len(g.Nodes))
	safePrintf("Relationships: %d\n", len(g.Edges))

	if len(g.Edges) == 0 {
		fmt.Println("No relationships available.")
		return
	}

	nodeValues := make(map[string]string, len(g.Nodes))
	for _, node := range g.Nodes {
		nodeValues[node.ID] = node.Value
	}

	for _, edge := range g.Edges {
		safePrintf(
			"[%s] %s -> %s\n",
			edge.Type,
			nodeValues[edge.Source],
			nodeValues[edge.Target],
		)
		if edge.State != "" {
			safePrintf("  TCP state: %s\n", edge.State)
		}
		if len(edge.EvidenceIDs) > 0 {
			safePrintf("  Evidence refs: %s\n", strings.Join(edge.EvidenceIDs, ", "))
		}
		if len(edge.ObservationIDs) > 0 {
			safePrintf("  Observation refs: %s\n", strings.Join(edge.ObservationIDs, ", "))
		}
	}
}

func runCT(target, snapshotDir string) error {
	return runExternalCollection(target, snapshotDir, "ct", 20*time.Second,
		func(ctx context.Context, registry *evidence.Registry, target string) error {
			report, err := (&externalintel.CTClient{}).LookupDomain(ctx, target)
			if err != nil {
				return err
			}
			added, err := externalintel.RegisterCTReport(registry, report, evidence.ObservationProvenanceFromContext(ctx))
			if err != nil {
				return err
			}
			infrastructureGraph, err := graph.BuildFromRegistryForTarget(registry, target)
			if err != nil {
				return fmt.Errorf("build CT infrastructure graph: %w", err)
			}

			fmt.Println("[CERTIFICATE TRANSPARENCY INTELLIGENCE]")
			safePrintf("Target: %s\n", report.Target)
			safePrintf("Source: %s\n", report.Source)
			safePrintf("Retrieved: %s\n", report.RetrievedAt.Format(time.RFC3339))
			safePrintf("Certificate records: %d\n", report.CertificateRecords)
			safePrintf("Unique in-scope DNS names: %d\n", report.UniqueDNSNames)
			safePrintf("Distinct issuer labels: %d\n", report.UniqueIssuers)
			for _, name := range report.DNSNames {
				safePrintf("[CT NAME] %s\n", name)
			}
			fmt.Println("\n[INTERPRETATION LIMITS]")
			for _, limitation := range report.Limitations {
				safePrintf("- %s\n", limitation)
			}
			safePrintf("New observations: %d\n", added)
			printInfrastructureGraph(infrastructureGraph)
			return nil
		})
}

func runRDAP(target, snapshotDir string) error {
	return runExternalCollection(target, snapshotDir, "rdap", 25*time.Second,
		func(ctx context.Context, registry *evidence.Registry, target string) error {
			report, err := (&externalintel.RDAPClient{}).LookupDomain(ctx, target)
			if err != nil {
				return err
			}
			added, err := externalintel.RegisterRDAPReport(registry, report, evidence.ObservationProvenanceFromContext(ctx))
			if err != nil {
				return err
			}
			infrastructureGraph, err := graph.BuildFromRegistryForTarget(registry, target)
			if err != nil {
				return fmt.Errorf("build RDAP infrastructure graph: %w", err)
			}
			fmt.Println("[DOMAIN REGISTRATION INTELLIGENCE]")
			safePrintf("Target: %s\nSource: %s\nRetrieved: %s\n", report.Target, report.Source, report.RetrievedAt.Format(time.RFC3339))
			if report.Handle != "" {
				safePrintf("Registry handle: %s\n", report.Handle)
			}
			if report.Registrar != "" {
				safePrintf("Registrar label: %s\n", report.Registrar)
			}
			safePrintf("Status values: %s\n", strings.Join(report.Status, ", "))
			for _, ns := range report.NameServers {
				safePrintf("[NAMESERVER] %s\n", ns)
			}
			for _, event := range report.Events {
				safePrintf("[REGISTRATION EVENT] %s: %s\n", event.Action, event.Date)
			}
			fmt.Println("\n[INTERPRETATION LIMITS]")
			for _, limitation := range report.Limitations {
				safePrintf("- %s\n", limitation)
			}
			safePrintf("New observation: %t\n", added)
			printInfrastructureGraph(infrastructureGraph)
			return nil
		})
}

func runASN(target, snapshotDir string) error {
	return runExternalCollection(target, snapshotDir, "asn", 30*time.Second,
		func(ctx context.Context, registry *evidence.Registry, target string) error {
			report, err := (&externalintel.ASNClient{}).LookupIP(ctx, target)
			if err != nil {
				return err
			}
			added, err := externalintel.RegisterASNReport(registry, report, evidence.ObservationProvenanceFromContext(ctx))
			if err != nil {
				return err
			}
			infrastructureGraph, err := graph.BuildFromRegistryForTarget(registry, target)
			if err != nil {
				return fmt.Errorf("build ASN infrastructure graph: %w", err)
			}
			fmt.Println("[ORIGIN ASN INTELLIGENCE]")
			safePrintf("Target IP: %s\nRetrieved: %s\n", report.Target, report.RetrievedAt.Format(time.RFC3339))
			for _, record := range report.Records {
				safePrintf("[ORIGIN] AS%d | Prefix: %s | Network label: %s | Country: %s | Registry: %s | Allocated: %s\n", record.ASN, record.Prefix, record.NetworkName, record.Country, record.Registry, record.Allocated)
				safePrintf("  Mapping source: %s\n  RDAP source: %s\n", record.MappingSource, record.RDAPSource)
			}
			fmt.Println("\n[INTERPRETATION LIMITS]")
			for _, limitation := range report.Limitations {
				safePrintf("- %s\n", limitation)
			}
			safePrintf("New observation: %t\n", added)
			printInfrastructureGraph(infrastructureGraph)
			return nil
		})
}

func runPassiveDNS(target, snapshotDir string) error {
	return runExternalCollection(target, snapshotDir, "pdns", 20*time.Second,
		func(ctx context.Context, registry *evidence.Registry, target string) error {
			client := &externalintel.PassiveDNSClient{APIKey: strings.TrimSpace(os.Getenv("OTX_API_KEY"))}
			report, err := client.LookupDomain(ctx, target)
			if err != nil {
				return err
			}
			added, err := externalintel.RegisterPassiveDNSReport(registry, report, evidence.ObservationProvenanceFromContext(ctx))
			if err != nil {
				return err
			}
			infrastructureGraph, err := graph.BuildFromRegistryForTarget(registry, target)
			if err != nil {
				return fmt.Errorf("build passive-DNS infrastructure graph: %w", err)
			}
			fmt.Println("[PASSIVE DNS INTELLIGENCE]")
			safePrintf("Target: %s\nSource: %s\nRetrieved: %s\nProvider records: %d\nScoped unique observations: %d\n", report.Target, report.Source, report.RetrievedAt.Format(time.RFC3339), report.SourceRecordCount, len(report.Records))
			for _, record := range report.Records {
				safePrintf("[HISTORICAL DNS] %s %s %s | first: %s | last: %s | ASN: %s\n", record.Hostname, record.RecordType, record.Address, record.FirstSeen, record.LastSeen, record.ASN)
			}
			if report.Truncated {
				fmt.Println("Warning: provider response may be truncated; treat this as a partial historical view.")
			}
			fmt.Println("\n[INTERPRETATION LIMITS]")
			for _, limitation := range report.Limitations {
				safePrintf("- %s\n", limitation)
			}
			safePrintf("New observations: %d\n", added)
			printInfrastructureGraph(infrastructureGraph)
			return nil
		})
}

func runThreatIntel(target, snapshotDir string) error {
	return runExternalCollection(target, snapshotDir, "threat", 20*time.Second,
		func(ctx context.Context, registry *evidence.Registry, target string) error {
			client := &externalintel.ThreatIntelClient{APIKey: strings.TrimSpace(os.Getenv("OTX_API_KEY"))}
			report, err := client.Lookup(ctx, target)
			if err != nil {
				return err
			}
			added, err := externalintel.RegisterThreatIntelReport(registry, report, evidence.ObservationProvenanceFromContext(ctx))
			if err != nil {
				return err
			}
			infrastructureGraph, err := graph.BuildFromRegistryForTarget(registry, target)
			if err != nil {
				return fmt.Errorf("build threat-intelligence graph: %w", err)
			}
			fmt.Println("[THREAT INTELLIGENCE CONTEXT]")
			safePrintf("Indicator: %s (%s)\nSource: %s\nRetrieved: %s\nCommunity pulse count: %d\nReturned pulse records: %d\n", report.Target, report.IndicatorType, report.Source, report.RetrievedAt.Format(time.RFC3339), report.PulseCount, len(report.Pulses))
			for _, pulse := range report.Pulses {
				safePrintf("[COMMUNITY REPORT] %s | ID: %s | Tags: %s | Created: %s | Modified: %s\n", pulse.Name, pulse.ID, strings.Join(pulse.Tags, ", "), pulse.Created, pulse.Modified)
			}
			if len(report.Pulses) == 0 {
				fmt.Println("No pulse records were returned; this is not proof that the indicator is benign.")
			}
			if report.Truncated {
				fmt.Println("Warning: provider reports more pulses than returned records; this is a partial view.")
			}
			fmt.Println("\n[INTERPRETATION LIMITS]")
			for _, limitation := range report.Limitations {
				safePrintf("- %s\n", limitation)
			}
			safePrintf("New observation: %t\n", added)
			printInfrastructureGraph(infrastructureGraph)
			return nil
		})
}

func runIPRDAP(target, snapshotDir string) error {
	return runExternalCollection(target, snapshotDir, "rdap", 25*time.Second,
		func(ctx context.Context, registry *evidence.Registry, target string) error {
			report, err := (&externalintel.RDAPClient{}).LookupIP(ctx, target)
			if err != nil {
				return err
			}
			added, err := externalintel.RegisterIPRDAPReport(registry, report, evidence.ObservationProvenanceFromContext(ctx))
			if err != nil {
				return err
			}
			infrastructureGraph, err := graph.BuildFromRegistryForTarget(registry, target)
			if err != nil {
				return fmt.Errorf("build IP RDAP graph: %w", err)
			}
			fmt.Println("[IP NETWORK REGISTRATION INTELLIGENCE]")
			safePrintf("Target IP: %s\nSource: %s\nRetrieved: %s\n", report.Target, report.Source, report.RetrievedAt.Format(time.RFC3339))
			safePrintf("Network handle: %s\nNetwork label: %s\nRange: %s - %s\nCountry label: %s\nNetwork type: %s\nStatus: %s\n", report.Handle, report.Name, report.StartAddress, report.EndAddress, report.Country, report.NetworkType, strings.Join(report.Status, ", "))
			fmt.Println("\n[INTERPRETATION LIMITS]")
			for _, limitation := range report.Limitations {
				safePrintf("- %s\n", limitation)
			}
			safePrintf("New observation: %t\n", added)
			printInfrastructureGraph(infrastructureGraph)
			return nil
		})
}

func runBatchDNS(targetsFile, snapshotDir string, workers int) error {
	targets, err := batch.ReadTargetsFile(targetsFile)
	if err != nil {
		return err
	}
	results, err := batch.RunDNS(commandContext, targets, workers, snapshotDir)
	if err != nil {
		return err
	}
	failures := 0
	safePrintf("[BATCH DNS INVESTIGATION] targets=%d workers=%d\n", len(results), workers)
	for _, result := range results {
		if result.Err != nil {
			failures++
			safePrintf("[FAILED] %s: %v\n", result.Target, result.Err)
			continue
		}
		state := "updated"
		if result.BaselineCreated {
			state = "baseline created"
		}
		safePrintf("[OK] %s | unique addresses=%d | changes=%d | %s\n", result.Target, result.AddressCount, result.ChangeCount, state)
	}
	safePrintf("Completed: %d | Failed: %d\n", len(results)-failures, failures)
	report := batch.BuildDNSBatchReport(results, time.Now().UTC())
	for _, shared := range report.SharedAddresses {
		targets := make([]string, 0, len(shared.Observations))
		for _, observation := range shared.Observations {
			targets = append(targets, observation.Target)
		}
		safePrintf("[SHARED DNS ADDRESS] %s | targets=%s | investigate as a lead, not proof of common ownership\n", shared.Address, strings.Join(targets, ", "))
	}
	safePrintf("Batch report: %s\n", filepath.Join(snapshotDir, "batch-dns", "report.json"))
	if failures > 0 {
		return fmt.Errorf("%d of %d target investigations failed; successful results were preserved", failures, len(results))
	}
	return nil
}

// sanitizeTerminalText removes control and formatting characters from
// untrusted strings before they are written to an interactive terminal.
func sanitizeTerminalText(value string) string {
	cleaned := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ' '
		}
		return r
	}, value)
	return strings.Join(strings.Fields(cleaned), " ")
}

func sanitizeTerminalArgs(args []any) []any {
	safe := make([]any, len(args))
	for i, arg := range args {
		switch value := arg.(type) {
		case string:
			safe[i] = sanitizeTerminalText(value)
		case []string:
			items := make([]string, len(value))
			for j := range value {
				items[j] = sanitizeTerminalText(value[j])
			}
			safe[i] = items
		case []byte:
			safe[i] = sanitizeTerminalText(string(value))
		case error:
			safe[i] = sanitizeTerminalText(value.Error())
		case fmt.Stringer:
			safe[i] = sanitizeTerminalText(value.String())
		default:
			safe[i] = arg
		}
	}
	return safe
}

func safePrintf(format string, args ...any) {
	fmt.Printf(format, sanitizeTerminalArgs(args)...)
}

func safePrintln(args ...any) {
	fmt.Println(sanitizeTerminalArgs(args)...)
}
