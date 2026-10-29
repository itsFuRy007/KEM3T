// Package batch coordinates bounded investigations over explicit target lists.
package batch

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/itsFuRy007/kem3t/internal/pipeline"
	"github.com/itsFuRy007/kem3t/internal/scale"
)

const MaxTargets = 10000

type DNSOutcome struct {
	Target          string    `json:"target"`
	AddressCount    int       `json:"address_count"`
	ChangeCount     int       `json:"change_count"`
	BaselineCreated bool      `json:"baseline_created"`
	Addresses       []string  `json:"addresses,omitempty"`
	CollectedAt     time.Time `json:"collected_at,omitempty"`
	EvidenceStore   string    `json:"evidence_store,omitempty"`
	Error           string    `json:"error,omitempty"`
	Err             error     `json:"-"`
}

type DNSObservationRef struct {
	Target        string    `json:"target"`
	CollectedAt   time.Time `json:"collected_at"`
	EvidenceStore string    `json:"evidence_store"`
}

type SharedAddressCorrelation struct {
	Address       string              `json:"address"`
	TargetCount   int                 `json:"target_count"`
	Observations  []DNSObservationRef `json:"observations"`
	Interpretation string             `json:"interpretation"`
}

type DNSBatchReport struct {
	GeneratedAt     time.Time                 `json:"generated_at"`
	TargetCount     int                       `json:"target_count"`
	CompletedCount  int                       `json:"completed_count"`
	FailedCount     int                       `json:"failed_count"`
	GraphFile       string                    `json:"graph_file,omitempty"`
	Outcomes        []DNSOutcome              `json:"outcomes"`
	SharedAddresses []SharedAddressCorrelation `json:"shared_addresses"`
	Limitations     []string                  `json:"limitations"`
}

type dnsInvestigator func(context.Context, string, string) (DNSOutcome, error)

func ReadTargetsFile(path string) ([]string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("target file path is required")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open target file: %w", err)
	}
	defer file.Close()
	targets, err := ParseTargets(file, MaxTargets)
	if err != nil {
		return nil, fmt.Errorf("parse target file: %w", err)
	}
	return targets, nil
}

// ParseTargets reads one hostname/IP per line, strips comments and blank lines,
// canonicalizes targets, removes duplicates, and rejects URLs and host:port values.
func ParseTargets(reader io.Reader, maxTargets int) ([]string, error) {
	if reader == nil {
		return nil, fmt.Errorf("target reader is required")
	}
	if maxTargets < 1 {
		return nil, fmt.Errorf("maximum target count must be positive")
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	targets := make([]string, 0)
	seen := make(map[string]struct{})
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line, _, _ := strings.Cut(scanner.Text(), "#")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		target, err := NormalizeTarget(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber, err)
		}
		if _, exists := seen[target]; exists {
			continue
		}
		if len(targets) >= maxTargets {
			return nil, fmt.Errorf("target count exceeds limit of %d", maxTargets)
		}
		seen[target] = struct{}{}
		targets = append(targets, target)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read target list: %w", err)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("target file contains no valid targets")
	}
	return targets, nil
}

func NormalizeTarget(raw string) (string, error) {
	target := strings.ToLower(strings.TrimSpace(raw))
	if target == "" {
		return "", fmt.Errorf("target is empty")
	}
	if strings.Contains(target, "://") || strings.ContainsAny(target, "/\\@?#") {
		return "", fmt.Errorf("target must be a hostname or IP address, not a URL or path")
	}
	if ip := net.ParseIP(target); ip != nil {
		return ip.String(), nil
	}
	target = strings.TrimSuffix(target, ".")
	if len(target) == 0 || len(target) > 253 {
		return "", fmt.Errorf("hostname length is invalid")
	}
	for _, label := range strings.Split(target, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid hostname label %q", label)
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z') && !(ch >= '0' && ch <= '9') && ch != '-' {
				return "", fmt.Errorf("hostname contains unsupported character %q", ch)
			}
		}
	}
	return target, nil
}

// RunDNS executes independent DNS investigations with bounded concurrency. Each
// target has an isolated evidence database/history directory. A JSON report and
// a portable graph export preserve cross-target pivots and per-observation provenance.
func RunDNS(ctx context.Context, targets []string, workers int, snapshotDir string) ([]DNSOutcome, error) {
	outcomes, err := runDNS(ctx, targets, workers, snapshotDir, func(ctx context.Context, target, dir string) (DNSOutcome, error) {
		result, err := pipeline.RunDNS(ctx, target, dir)
		if err != nil {
			return DNSOutcome{}, err
		}
		return DNSOutcome{
			Target: target,
			AddressCount: len(result.CurrentSnapshot.Addresses),
			ChangeCount: len(result.Changes),
			BaselineCreated: result.BaselineCreated,
			Addresses: append([]string(nil), result.CurrentSnapshot.Addresses...),
			CollectedAt: result.CurrentSnapshot.Collected,
			EvidenceStore: filepath.Join(dir, "evidence.db"),
		}, nil
	})
	if err != nil {
		return outcomes, err
	}
	if err := PersistDNSBatchReport(snapshotDir, outcomes); err != nil {
		return outcomes, fmt.Errorf("persist batch DNS report: %w", err)
	}
	return outcomes, nil
}

func runDNS(ctx context.Context, targets []string, workers int, snapshotDir string, investigate dnsInvestigator) ([]DNSOutcome, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}
	if workers < 1 {
		return nil, fmt.Errorf("worker count must be at least one")
	}
	if investigate == nil {
		return nil, fmt.Errorf("DNS investigator is required")
	}
	snapshotDir = strings.TrimSpace(snapshotDir)
	if snapshotDir == "" {
		return nil, fmt.Errorf("snapshot directory is required")
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("at least one target is required")
	}
	canonical := make([]string, 0, len(targets))
	seen := make(map[string]struct{}, len(targets))
	for _, raw := range targets {
		target, err := NormalizeTarget(raw)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[target]; exists {
			continue
		}
		seen[target] = struct{}{}
		canonical = append(canonical, target)
	}
	if len(canonical) == 0 {
		return nil, fmt.Errorf("at least one unique target is required")
	}
	if err := os.MkdirAll(filepath.Join(snapshotDir, "batch-dns"), 0750); err != nil {
		return nil, fmt.Errorf("create batch DNS directory: %w", err)
	}
	results, err := scale.Run(ctx, canonical, workers, func(ctx context.Context, target string) (DNSOutcome, error) {
		sum := sha256.Sum256([]byte(target))
		targetDir := filepath.Join(snapshotDir, "batch-dns", hex.EncodeToString(sum[:12]))
		outcome, itemErr := investigate(ctx, target, targetDir)
		outcome.Target = target
		if itemErr != nil {
			outcome.Err = itemErr
			outcome.Error = itemErr.Error()
		}
		return outcome, nil
	})
	if err != nil {
		return nil, err
	}
	outcomes := make([]DNSOutcome, len(results))
	for i, result := range results {
		outcomes[i] = result.Value
		if result.Err != nil {
			outcomes[i] = DNSOutcome{Target: result.Input, Err: result.Err, Error: result.Err.Error()}
		}
	}
	return outcomes, nil
}

// BuildDNSBatchReport correlates addresses observed for multiple target scopes.
// It intentionally records references and limitations rather than inferring
// common ownership or treating shared hosting as proof of a relationship.
func BuildDNSBatchReport(outcomes []DNSOutcome, generatedAt time.Time) DNSBatchReport {
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	} else {
		generatedAt = generatedAt.UTC()
	}
	report := DNSBatchReport{
		GeneratedAt: generatedAt,
		TargetCount: len(outcomes),
		Outcomes: append([]DNSOutcome(nil), outcomes...),
		SharedAddresses: make([]SharedAddressCorrelation, 0),
		Limitations: []string{
			"DNS addresses are observations collected at the per-target timestamps, not guarantees of current resolution.",
			"Shared IP addresses can result from CDNs, shared hosting, reverse proxies, cloud platforms, or unrelated tenants; they do not prove common ownership or control.",
			"Each target's evidence database is isolated. EvidenceStore paths identify where the underlying observations can be reviewed.",
			"Only successful target outcomes participate in shared-address correlations; failed targets are not treated as negative evidence.",
		},
	}
	byAddress := make(map[string][]DNSObservationRef)
	for _, outcome := range outcomes {
		if outcome.Err != nil || outcome.Error != "" {
			report.FailedCount++
			continue
		}
		report.CompletedCount++
		seenForTarget := make(map[string]struct{})
		for _, raw := range outcome.Addresses {
			ip := net.ParseIP(strings.TrimSpace(raw))
			if ip == nil {
				continue
			}
			address := ip.String()
			if _, duplicate := seenForTarget[address]; duplicate {
				continue
			}
			seenForTarget[address] = struct{}{}
			byAddress[address] = append(byAddress[address], DNSObservationRef{
				Target: outcome.Target, CollectedAt: outcome.CollectedAt, EvidenceStore: outcome.EvidenceStore,
			})
		}
	}
	for address, observations := range byAddress {
		if len(observations) < 2 {
			continue
		}
		report.SharedAddresses = append(report.SharedAddresses, SharedAddressCorrelation{
			Address: address, TargetCount: len(observations), Observations: observations,
			Interpretation: "Same address observed for multiple target scopes; investigate as a lead, not proof of shared ownership.",
		})
	}
	sort.Slice(report.SharedAddresses, func(i, j int) bool { return report.SharedAddresses[i].Address < report.SharedAddresses[j].Address })
	return report
}

// PersistDNSBatchReport atomically writes the latest batch summary and its
// portable graph export beside the per-target evidence stores.
func PersistDNSBatchReport(snapshotDir string, outcomes []DNSOutcome) error {
	snapshotDir = strings.TrimSpace(snapshotDir)
	if snapshotDir == "" {
		return fmt.Errorf("snapshot directory is required")
	}
	dir := filepath.Join(snapshotDir, "batch-dns")
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("create batch report directory: %w", err)
	}
	report := BuildDNSBatchReport(outcomes, time.Now().UTC())
	report.GraphFile = "investigation-graph.json"
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("encode batch DNS report: %w", err)
	}
	data = append(data, byte(10))
')
	if err := writeAtomicFile(dir, "report.json", data, ".report-*.tmp"); err != nil {
		return fmt.Errorf("persist batch DNS report: %w", err)
	}
	if err := PersistDNSInvestigationGraph(snapshotDir, outcomes, report.GeneratedAt); err != nil {
		return fmt.Errorf("persist batch DNS investigation graph: %w", err)
	}
	return nil
}
