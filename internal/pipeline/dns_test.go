package pipeline

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/itsFuRy007/kem3t/internal/changes"
	"github.com/itsFuRy007/kem3t/internal/events"
	"github.com/itsFuRy007/kem3t/internal/evidence"
	"github.com/itsFuRy007/kem3t/internal/intelligence"
)

type fakeCollector struct {
	events []events.Event
	err    error
}

func (f *fakeCollector) Run(ctx context.Context, out chan<- events.Event) error {
	for _, event := range f.events {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case out <- event:
		}
	}
	return f.err
}
func dnsEvents(addresses ...string) []events.Event {
	result := make([]events.Event, 0, len(addresses))
	for _, address := range addresses {
		result = append(result, events.Event{
			ID:        "dns-test-" + address,
			Type:      events.EventDNSRecordFound,
			Timestamp: time.Now().UTC(),
			Target:    "example.com",
			Source:    "test",
			Data: map[string]string{
				"record_type": "IP_ADDRESS",
				"value":       address,
			},
		})
	}
	return result
}
func TestRunDNSCreatesBaselineAndDetectsChanges(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	first := &fakeCollector{
		events: dnsEvents("192.0.2.10", "192.0.2.11"),
	}
	result, err := runDNSWithCollector(ctx, "example.com", dir, first)
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	if !result.BaselineCreated {
		t.Fatal("expected first run to create baseline")
	}
	if result.PreviousSnapshot != nil {
		t.Fatal("expected no previous snapshot on first run")
	}
	second := &fakeCollector{
		events: dnsEvents("192.0.2.10", "192.0.2.25"),
	}
	result, err = runDNSWithCollector(ctx, "example.com", dir, second)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if result.BaselineCreated {
		t.Fatal("expected second run to compare against existing baseline")
	}
	if result.PreviousSnapshot == nil {
		t.Fatal("expected previous snapshot on second run")
	}
	if len(result.Changes) != 2 {
		t.Fatalf("expected 2 changes, got %d", len(result.Changes))
	}
	expected := map[changes.ChangeType]string{
		changes.AddressAdded:   "192.0.2.25",
		changes.AddressRemoved: "192.0.2.11",
	}
	for _, change := range result.Changes {
		address, ok := expected[change.Type]
		if !ok {
			t.Fatalf("unexpected change type: %s", change.Type)
		}
		if change.Address != address {
			t.Errorf("unexpected address for %s: got %s, want %s",
				change.Type, change.Address, address)
		}
	}
}
func TestRunDNSCancelsCollectorWhenAggregationFails(t *testing.T) {
	invalidEvent := dnsEvents("192.0.2.10")[0]
	invalidEvent.ID = ""
	collector := &fakeCollector{
		events: []events.Event{
			invalidEvent,
			dnsEvents("192.0.2.11")[0],
		},
	}
	done := make(chan error, 1)
	go func() {
		_, err := runDNSWithCollector(
			context.Background(),
			"example.com",
			t.TempDir(),
			collector,
		)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected aggregation error for invalid event")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pipeline hung instead of stopping the collector")
	}
}
func TestRunDNSRegistersEvidenceAndObservations(t *testing.T) {
	collected := dnsEvents("192.0.2.10", "192.0.2.11")
	repeated := collected[0]
	repeated.ID = "dns-repeat"
	repeated.Timestamp = repeated.Timestamp.Add(time.Minute)
	collected = append(collected, repeated)
	result, err := runDNSWithCollector(
		context.Background(),
		"example.com",
		t.TempDir(),
		&fakeCollector{events: collected},
	)
	if err != nil {
		t.Fatalf("runDNSWithCollector() error = %v", err)
	}
	if result.EvidenceRegistry == nil {
		t.Fatal("expected evidence registry in DNS result")
	}
	evidenceID := "dns-address:example.com:192.0.2.10"
	gotEvidence, err := result.EvidenceRegistry.GetEvidence(evidenceID)
	if err != nil {
		t.Fatalf("GetEvidence() error = %v", err)
	}
	if gotEvidence.Value != "192.0.2.10" {
		t.Fatalf("evidence value = %q", gotEvidence.Value)
	}
	history, err := result.EvidenceRegistry.ObservationsForEvidence(evidenceID)
	if err != nil {
		t.Fatalf("ObservationsForEvidence() error = %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("observation count = %d, want 2", len(history))
	}
	eventIDs := make(map[string]bool)
	for _, observation := range history {
		for _, eventID := range observation.EventIDs {
			eventIDs[eventID] = true
		}
	}
	if !eventIDs[collected[0].ID] || !eventIDs["dns-repeat"] {
		t.Fatalf("expected both event IDs in history, got %v", eventIDs)
	}
	secondHistory, err := result.EvidenceRegistry.ObservationsForEvidence(
		"dns-address:example.com:192.0.2.11",
	)
	if err != nil {
		t.Fatalf("history for second IP: %v", err)
	}
	if len(secondHistory) != 1 {
		t.Fatalf("second IP observation count = %d, want 1", len(secondHistory))
	}
}

func TestRunDNSIncludesHistoryComparison(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	first, err := runDNSWithCollector(
		ctx,
		"example.com",
		dir,
		&fakeCollector{
			events: dnsEvents(
				"192.0.2.10",
				"192.0.2.11",
				"192.0.2.12",
			),
		},
	)
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	if !first.BaselineCreated {
		t.Fatal("expected baseline on first run")
	}
	if first.History != nil {
		t.Fatal("expected no history comparison on first run")
	}

	second, err := runDNSWithCollector(
		ctx,
		"example.com",
		dir,
		&fakeCollector{
			events: dnsEvents(
				"192.0.2.11",
				"192.0.2.12",
				"192.0.2.25",
			),
		},
	)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}

	if second.History == nil {
		t.Fatal("expected history comparison on second run")
	}

	history := second.History

	if history.Target != "example.com" {
		t.Errorf("target = %q, want example.com", history.Target)
	}
	if history.PreviousCount != 3 || history.CurrentCount != 3 {
		t.Errorf(
			"counts = %d/%d, want 3/3",
			history.PreviousCount,
			history.CurrentCount,
		)
	}

	if len(history.Added) != 1 || history.Added[0] != "192.0.2.25" {
		t.Errorf("added = %v, want [192.0.2.25]", history.Added)
	}
	if len(history.Removed) != 1 || history.Removed[0] != "192.0.2.10" {
		t.Errorf("removed = %v, want [192.0.2.10]", history.Removed)
	}

	wantUnchanged := []string{"192.0.2.11", "192.0.2.12"}
	if len(history.Unchanged) != len(wantUnchanged) {
		t.Fatalf(
			"unchanged = %v, want %v",
			history.Unchanged,
			wantUnchanged,
		)
	}
	for i, address := range wantUnchanged {
		if history.Unchanged[i] != address {
			t.Errorf(
				"unchanged[%d] = %q, want %q",
				i,
				history.Unchanged[i],
				address,
			)
		}
	}
}

func TestRunDNSPersistsObservationsAcrossRuns(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	firstEvents := dnsEvents("192.0.2.10")
	first, err := runDNSWithCollector(
		ctx,
		"example.com",
		dir,
		&fakeCollector{events: firstEvents},
	)
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	if err := first.EvidenceRegistry.Close(); err != nil {
		t.Fatalf("close first registry: %v", err)
	}

	secondEvents := dnsEvents("192.0.2.10")
	secondEvents[0].ID = "dns-second-run"
	secondEvents[0].Timestamp = secondEvents[0].Timestamp.Add(time.Minute)

	second, err := runDNSWithCollector(
		ctx,
		"example.com",
		dir,
		&fakeCollector{events: secondEvents},
	)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	defer second.EvidenceRegistry.Close()

	history, err := second.EvidenceRegistry.ObservationsForEvidence(
		"dns-address:example.com:192.0.2.10",
	)
	if err != nil {
		t.Fatalf("load observation history: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("observation history has %d records, want 2", len(history))
	}

	eventIDs := make(map[string]bool)
	for _, observation := range history {
		for _, id := range observation.EventIDs {
			eventIDs[id] = true
		}
	}
	if !eventIDs[firstEvents[0].ID] || !eventIDs["dns-second-run"] {
		t.Fatalf("history does not contain both runs: %v", eventIDs)
	}
}

func TestRunDNSRecordsCompletedCollectionRuns(t *testing.T) {
	dir := t.TempDir()

	result, err := runDNSWithCollector(
		context.Background(),
		"example.com",
		dir,
		&fakeCollector{
			events: func() []events.Event {
				collected := dnsEvents("192.0.2.10", "192.0.2.11", "192.0.2.10")
				collected[2].ID = "dns-test-192.0.2.10-repeat"
				return collected
			}(),
		},
	)
	if err != nil {
		t.Fatalf("runDNSWithCollector() error = %v", err)
	}

	if result.EvidenceRegistry == nil {
		t.Fatal("expected evidence registry")
	}

	runs, err := result.EvidenceRegistry.CollectionRuns("example.com")
	if err != nil {
		t.Fatalf("CollectionRuns() error = %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("collection run count = %d, want 1", len(runs))
	}

	run := runs[0]
	if run.Status != "completed" {
		t.Errorf("status = %q, want completed", run.Status)
	}
	if run.EventCount != 3 {
		t.Errorf("event count = %d, want 3", run.EventCount)
	}
	if run.AddressCount != 2 {
		t.Errorf("address count = %d, want 2", run.AddressCount)
	}
	if run.FinishedAt.IsZero() {
		t.Error("expected finished_at to be set")
	}
	if run.ErrorMessage != "" {
		t.Errorf("unexpected error message: %q", run.ErrorMessage)
	}
}

func TestRunDNSRecordsFailedCollectionRun(t *testing.T) {
	dir := t.TempDir()

	invalidEvent := dnsEvents("192.0.2.10")[0]
	invalidEvent.ID = ""

	_, err := runDNSWithCollector(
		context.Background(),
		"example.com",
		dir,
		&fakeCollector{
			events: []events.Event{invalidEvent},
		},
	)
	if err == nil {
		t.Fatal("expected aggregation error")
	}

	registry, openErr := evidence.OpenRegistry(filepath.Join(dir, "evidence.db"))
	if openErr != nil {
		t.Fatalf("OpenRegistry() error = %v", openErr)
	}
	defer registry.Close()

	runs, err := registry.CollectionRuns("example.com")
	if err != nil {
		t.Fatalf("CollectionRuns() error = %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("collection run count = %d, want 1", len(runs))
	}

	run := runs[0]
	if run.Status != "failed" {
		t.Errorf("status = %q, want failed", run.Status)
	}
	if run.FinishedAt.IsZero() {
		t.Error("expected failed run to have finished_at")
	}
	if run.ErrorMessage == "" {
		t.Error("expected failed run to preserve its error")
	}
}

func TestRunDNSBuildsIntelligenceReport(t *testing.T) {
	result, err := runDNSWithCollector(
		context.Background(),
		"example.com",
		t.TempDir(),
		&fakeCollector{
			events: dnsEvents("192.0.2.10", "192.0.2.11"),
		},
	)
	if err != nil {
		t.Fatalf("runDNSWithCollector() error = %v", err)
	}

	report := result.Report

	if report.Target != "example.com" {
		t.Fatalf("report target = %q, want example.com", report.Target)
	}

	if len(report.Findings) != 1 {
		t.Fatalf("report findings = %d, want 1", len(report.Findings))
	}

	if len(report.PrioritizedFindings) != 1 {
		t.Fatalf(
			"prioritized findings = %d, want 1",
			len(report.PrioritizedFindings),
		)
	}

	finding := report.Findings[0]
	if finding.Title != "DNS addresses summarized" {
		t.Errorf("finding title = %q", finding.Title)
	}
	if finding.Priority != intelligence.PriorityInfo {
		t.Errorf(
			"finding priority = %q, want %q",
			finding.Priority,
			intelligence.PriorityInfo,
		)
	}

	prioritized := report.PrioritizedFindings[0]
	if prioritized.Finding.Title != finding.Title {
		t.Errorf(
			"prioritized finding title = %q, want %q",
			prioritized.Finding.Title,
			finding.Title,
		)
	}
	if prioritized.Priority != intelligence.PriorityInfo {
		t.Errorf(
			"prioritized priority = %q, want %q",
			prioritized.Priority,
			intelligence.PriorityInfo,
		)
	}
	if prioritized.Reason == "" {
		t.Error("expected a prioritization reason")
	}

	if report.Correlations == nil {
		t.Error("expected correlations to be initialized")
	}
	if report.Hypotheses == nil {
		t.Error("expected hypotheses to be initialized")
	}
}
