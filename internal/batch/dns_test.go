package batch

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseTargetsCanonicalizesCommentsAndDuplicates(t *testing.T) {
	input := strings.NewReader(" # authorized assets\nExample.COM.\nexample.com # duplicate\n192.0.2.1\n2001:0db8::1\n")
	got, err := ParseTargets(input, 10)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"example.com", "192.0.2.1", "2001:db8::1"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseTargetsRejectsInvalidAndOversizedLists(t *testing.T) {
	for _, input := range []string{"https://example.com", "example.com:443", "bad..example", "-bad.example", "bad_name.example"} {
		if _, err := ParseTargets(strings.NewReader(input), 10); err == nil {
			t.Errorf("expected %q to be rejected", input)
		}
	}
	if _, err := ParseTargets(strings.NewReader("a.example\nb.example\nc.example\n"), 2); err == nil {
		t.Fatal("expected target cap error")
	}
	if _, err := ParseTargets(strings.NewReader("# no targets\n\n"), 10); err == nil {
		t.Fatal("expected empty target-list error")
	}
}

func TestRunDNSBoundsConcurrencyAndPreservesPerTargetFailures(t *testing.T) {
	targets := []string{"first.example", "second.example", "third.example", "fourth.example"}
	var active, peak atomic.Int32
	wantErr := errors.New("simulated resolver failure")
	outcomes, err := runDNS(context.Background(), targets, 2, t.TempDir(), func(_ context.Context, target, dir string) (DNSOutcome, error) {
		if dir == "" {
			t.Error("expected isolated target directory")
		}
		now := active.Add(1)
		for {
			old := peak.Load()
			if now <= old || peak.CompareAndSwap(old, now) {
				break
			}
		}
		time.Sleep(time.Millisecond)
		active.Add(-1)
		if target == "third.example" {
			return DNSOutcome{}, wantErr
		}
		return DNSOutcome{AddressCount: 2, ChangeCount: 1, BaselineCreated: true, Addresses: []string{"192.0.2.1", "192.0.2.2"}, CollectedAt: time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC), EvidenceStore: filepath.Join(dir, "evidence.db")}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if peak.Load() > 2 || peak.Load() != 2 {
		t.Fatalf("peak concurrency=%d, want 2", peak.Load())
	}
	if len(outcomes) != len(targets) {
		t.Fatalf("got %d outcomes, want %d", len(outcomes), len(targets))
	}
	for i, outcome := range outcomes {
		if outcome.Target != targets[i] {
			t.Fatalf("outcome order changed at %d: %+v", i, outcome)
		}
		if targets[i] == "third.example" {
			if !errors.Is(outcome.Err, wantErr) || outcome.Error == "" {
				t.Fatalf("expected isolated target error, got %+v", outcome)
			}
		} else if outcome.Err != nil || outcome.AddressCount != 2 || outcome.ChangeCount != 1 || !outcome.BaselineCreated {
			t.Fatalf("unexpected successful outcome: %+v", outcome)
		}
	}
}

func TestRunDNSRejectsInvalidConfiguration(t *testing.T) {
	fn := func(context.Context, string, string) (DNSOutcome, error) { return DNSOutcome{}, nil }
	if _, err := runDNS(nil, []string{"example.com"}, 1, t.TempDir(), fn); err == nil {
		t.Fatal("expected nil-context error")
	}
	if _, err := runDNS(context.Background(), []string{"example.com"}, 0, t.TempDir(), fn); err == nil {
		t.Fatal("expected worker-count error")
	}
}

func TestBuildDNSBatchReportFindsSharedAddressesWithoutInferringOwnership(t *testing.T) {
	when := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	outcomes := []DNSOutcome{
		{Target: "a.example", Addresses: []string{"192.0.2.10", "192.0.2.10", "2001:db8::1"}, CollectedAt: when, EvidenceStore: "a.db"},
		{Target: "b.example", Addresses: []string{"192.0.2.10"}, CollectedAt: when.Add(time.Minute), EvidenceStore: "b.db"},
		{Target: "c.example", Error: "resolver failed", Err: errors.New("resolver failed"), Addresses: []string{"192.0.2.10"}},
		{Target: "d.example", Addresses: []string{"198.51.100.1"}, CollectedAt: when, EvidenceStore: "d.db"},
	}
	report := BuildDNSBatchReport(outcomes, when)
	if report.TargetCount != 4 || report.CompletedCount != 3 || report.FailedCount != 1 {
		t.Fatalf("unexpected counts: %+v", report)
	}
	if len(report.SharedAddresses) != 1 {
		t.Fatalf("got %d correlations, want 1", len(report.SharedAddresses))
	}
	correlation := report.SharedAddresses[0]
	if correlation.Address != "192.0.2.10" || correlation.TargetCount != 2 || len(correlation.Observations) != 2 {
		t.Fatalf("unexpected correlation: %+v", correlation)
	}
	if correlation.Observations[0].EvidenceStore != "a.db" || correlation.Observations[1].EvidenceStore != "b.db" {
		t.Fatalf("evidence provenance missing: %+v", correlation.Observations)
	}
	if !strings.Contains(correlation.Interpretation, "not proof") {
		t.Fatalf("missing caveat: %s", correlation.Interpretation)
	}
}

func TestPersistDNSBatchReportIsValidJSONAndPreservesFailedTargets(t *testing.T) {
	dir := t.TempDir()
	outcomes := []DNSOutcome{{Target: "a.example", Addresses: []string{"192.0.2.1"}}, {Target: "b.example", Error: "timeout", Err: errors.New("timeout")}}
	if err := PersistDNSBatchReport(dir, outcomes); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "batch-dns", "report.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "\"target\": \"a.example\"") || !strings.Contains(string(data), "\"error\": \"timeout\"") {
		t.Fatalf("report is missing outcomes: %s", data)
	}
	if strings.Contains(string(data), "\"Err\"") {
		t.Fatalf("internal error field should not leak into JSON: %s", data)
	}
}
