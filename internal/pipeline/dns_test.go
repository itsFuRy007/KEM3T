package pipeline

import (
	"context"
	"testing"
	"time"

	"github.com/itsFuRy007/kem3t/internal/changes"
	"github.com/itsFuRy007/kem3t/internal/events"
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
