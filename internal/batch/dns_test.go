package batch

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseTargetsCanonicalizesCommentsAndDuplicates(t *testing.T) {
	input := strings.NewReader(" # authorized assets\nExample.COM.\nexample.com # duplicate\n192.0.2.1\n2001:0db8::1\n")
	got, err := ParseTargets(input, 10)
	if err != nil { t.Fatal(err) }
	want := []string{"example.com", "192.0.2.1", "2001:db8::1"}
	if fmt.Sprint(got) != fmt.Sprint(want) { t.Fatalf("got %v, want %v", got, want) }
}

func TestParseTargetsRejectsInvalidAndOversizedLists(t *testing.T) {
	for _, input := range []string{"https://example.com", "example.com:443", "bad..example", "-bad.example", "bad_name.example"} {
		if _, err := ParseTargets(strings.NewReader(input), 10); err == nil { t.Errorf("expected %q to be rejected", input) }
	}
	if _, err := ParseTargets(strings.NewReader("a.example\nb.example\nc.example\n"), 2); err == nil { t.Fatal("expected target cap error") }
	if _, err := ParseTargets(strings.NewReader("# no targets\n\n"), 10); err == nil { t.Fatal("expected empty target-list error") }
}

func TestRunDNSBoundsConcurrencyAndPreservesPerTargetFailures(t *testing.T) {
	targets := []string{"first.example", "second.example", "third.example", "fourth.example"}
	var active, peak atomic.Int32
	wantErr := errors.New("simulated resolver failure")
	outcomes, err := runDNS(context.Background(), targets, 2, t.TempDir(), func(_ context.Context, target, dir string) (int, int, bool, error) {
		if dir == "" { t.Error("expected isolated target directory") }
		now := active.Add(1)
		for { old := peak.Load(); if now <= old || peak.CompareAndSwap(old, now) { break } }
		time.Sleep(time.Millisecond)
		active.Add(-1)
		if target == "third.example" { return 0, 0, false, wantErr }
		return 2, 1, true, nil
	})
	if err != nil { t.Fatal(err) }
	if peak.Load() > 2 || peak.Load() != 2 { t.Fatalf("peak concurrency=%d, want 2", peak.Load()) }
	if len(outcomes) != len(targets) { t.Fatalf("got %d outcomes, want %d", len(outcomes), len(targets)) }
	for i, outcome := range outcomes {
		if outcome.Target != targets[i] { t.Fatalf("outcome order changed at %d: %+v", i, outcome) }
		if targets[i] == "third.example" {
			if !errors.Is(outcome.Err, wantErr) { t.Fatalf("expected isolated target error, got %v", outcome.Err) }
		} else if outcome.Err != nil || outcome.AddressCount != 2 || outcome.ChangeCount != 1 || !outcome.BaselineCreated {
			t.Fatalf("unexpected successful outcome: %+v", outcome)
		}
	}
}

func TestRunDNSRejectsInvalidConfiguration(t *testing.T) {
	fn := func(context.Context, string, string) (int, int, bool, error) { return 0, 0, false, nil }
	if _, err := runDNS(nil, []string{"example.com"}, 1, t.TempDir(), fn); err == nil { t.Fatal("expected nil-context error") }
	if _, err := runDNS(context.Background(), []string{"example.com"}, 0, t.TempDir(), fn); err == nil { t.Fatal("expected worker-count error") }
}
