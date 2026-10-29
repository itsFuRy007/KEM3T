// Package batch coordinates bounded investigations over explicit target lists.
package batch

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/itsFuRy007/kem3t/internal/pipeline"
	"github.com/itsFuRy007/kem3t/internal/scale"
)

const MaxTargets = 10000

type DNSOutcome struct {
	Target string
	AddressCount int
	ChangeCount int
	BaselineCreated bool
	Err error
}

type dnsInvestigator func(context.Context, string, string) (int, int, bool, error)

func ReadTargetsFile(path string) ([]string, error) {
	path = strings.TrimSpace(path)
	if path == "" { return nil, fmt.Errorf("target file path is required") }
	file, err := os.Open(path)
	if err != nil { return nil, fmt.Errorf("open target file: %w", err) }
	defer file.Close()
	targets, err := ParseTargets(file, MaxTargets)
	if err != nil { return nil, fmt.Errorf("parse target file: %w", err) }
	return targets, nil
}

// ParseTargets reads one hostname/IP per line, strips comments and blank lines,
// canonicalizes targets, removes duplicates, and rejects URLs and host:port values.
func ParseTargets(reader io.Reader, maxTargets int) ([]string, error) {
	if reader == nil { return nil, fmt.Errorf("target reader is required") }
	if maxTargets < 1 { return nil, fmt.Errorf("maximum target count must be positive") }
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	targets := make([]string, 0)
	seen := make(map[string]struct{})
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line, _, _ := strings.Cut(scanner.Text(), "#")
		line = strings.TrimSpace(line)
		if line == "" { continue }
		target, err := NormalizeTarget(line)
		if err != nil { return nil, fmt.Errorf("line %d: %w", lineNumber, err) }
		if _, exists := seen[target]; exists { continue }
		if len(targets) >= maxTargets { return nil, fmt.Errorf("target count exceeds limit of %d", maxTargets) }
		seen[target] = struct{}{}
		targets = append(targets, target)
	}
	if err := scanner.Err(); err != nil { return nil, fmt.Errorf("read target list: %w", err) }
	if len(targets) == 0 { return nil, fmt.Errorf("target file contains no valid targets") }
	return targets, nil
}

func NormalizeTarget(raw string) (string, error) {
	target := strings.ToLower(strings.TrimSpace(raw))
	if target == "" { return "", fmt.Errorf("target is empty") }
	if strings.Contains(target, "://") || strings.ContainsAny(target, "/\\@?#") {
		return "", fmt.Errorf("target must be a hostname or IP address, not a URL or path")
	}
	if ip := net.ParseIP(target); ip != nil { return ip.String(), nil }
	target = strings.TrimSuffix(target, ".")
	if len(target) == 0 || len(target) > 253 { return "", fmt.Errorf("hostname length is invalid") }
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
// target receives its own evidence database/history directory, preventing shared
// SQLite write contention. Results remain in input order; item failures are isolated.
func RunDNS(ctx context.Context, targets []string, workers int, snapshotDir string) ([]DNSOutcome, error) {
	return runDNS(ctx, targets, workers, snapshotDir, func(ctx context.Context, target, dir string) (int, int, bool, error) {
		result, err := pipeline.RunDNS(ctx, target, dir)
		if err != nil { return 0, 0, false, err }
		return len(result.CurrentSnapshot.Addresses), len(result.Changes), result.BaselineCreated, nil
	})
}

func runDNS(ctx context.Context, targets []string, workers int, snapshotDir string, investigate dnsInvestigator) ([]DNSOutcome, error) {
	if ctx == nil { return nil, fmt.Errorf("context is required") }
	if workers < 1 { return nil, fmt.Errorf("worker count must be at least one") }
	if investigate == nil { return nil, fmt.Errorf("DNS investigator is required") }
	snapshotDir = strings.TrimSpace(snapshotDir)
	if snapshotDir == "" { return nil, fmt.Errorf("snapshot directory is required") }
	if len(targets) == 0 { return nil, fmt.Errorf("at least one target is required") }
	canonical := make([]string, 0, len(targets))
	seen := make(map[string]struct{}, len(targets))
	for _, raw := range targets {
		target, err := NormalizeTarget(raw)
		if err != nil { return nil, err }
		if _, exists := seen[target]; exists { continue }
		seen[target] = struct{}{}
		canonical = append(canonical, target)
	}
	if len(canonical) == 0 { return nil, fmt.Errorf("at least one unique target is required") }
	if err := os.MkdirAll(filepath.Join(snapshotDir, "batch-dns"), 0750); err != nil {
		return nil, fmt.Errorf("create batch DNS directory: %w", err)
	}
	results, err := scale.Run(ctx, canonical, workers, func(ctx context.Context, target string) (DNSOutcome, error) {
		sum := sha256.Sum256([]byte(target))
		targetDir := filepath.Join(snapshotDir, "batch-dns", hex.EncodeToString(sum[:12]))
		addresses, changes, baseline, itemErr := investigate(ctx, target, targetDir)
		return DNSOutcome{Target:target, AddressCount:addresses, ChangeCount:changes, BaselineCreated:baseline, Err:itemErr}, nil
	})
	if err != nil { return nil, err }
	outcomes := make([]DNSOutcome, len(results))
	for i, result := range results {
		outcomes[i] = result.Value
		if result.Err != nil { outcomes[i] = DNSOutcome{Target:result.Input, Err:result.Err} }
	}
	return outcomes, nil
}
