package investigation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/itsFuRy007/kem3t/internal/events"
	"github.com/itsFuRy007/kem3t/internal/evidence"
)

type sliceCollector struct{ events []events.Event }

func (c sliceCollector) Run(ctx context.Context, out chan<- events.Event) error {
	for _, event := range c.events {
		select {
		case out <- event:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func dnsEvent(id, target, ip string) events.Event {
	return events.Event{ID: id, Type: events.EventDNSRecordFound, Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Target: target, Source: "test", Data: map[string]string{"record_type": "IP_ADDRESS", "value": ip}}
}

func TestCollectorStageRegistersNormalizedEvidenceInSharedRegistry(t *testing.T) {
	registry := evidence.NewRegistry()
	stage := CollectorStage{
		StageName: "dns-test",
		Collector: sliceCollector{events: []events.Event{dnsEvent("event-1", "example.com", "203.0.113.10")}},
		Accept:    func(e events.Event) bool { return e.Type == events.EventDNSRecordFound },
		Convert:   evidence.FromDNSEvent,
	}
	stageCtx := evidence.WithObservationProvenance(context.Background(), "investigation-test-run", "dns-test")
	result, err := stage.Run(stageCtx, "example.com", registry)
	if err != nil {
		t.Fatal(err)
	}
	if result.Events != 1 || result.Evidence != 1 || result.Observations != 1 {
		t.Fatalf("unexpected stage result: %+v", result)
	}
	if len(registry.AllEvidence()) != 1 || len(registry.AllObservations()) != 1 {
		t.Fatal("collector output was not registered")
	}
	observation := registry.AllObservations()[0]
	if observation.CollectionRunID != "investigation-test-run" || observation.Stage != "dns-test" {
		t.Fatalf("stage provenance was not attached to observation: %+v", observation)
	}
}

func TestCollectorStageDeduplicatesWithoutInflatingCounts(t *testing.T) {
	registry := evidence.NewRegistry()
	item, observation, err := evidence.FromDNSEvent(dnsEvent("event-1", "example.com", "203.0.113.10"))
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.AddEvidence(item); err != nil {
		t.Fatal(err)
	}
	if err := registry.AddObservation(observation); err != nil {
		t.Fatal(err)
	}
	stage := CollectorStage{StageName: "dns-test", Collector: sliceCollector{events: []events.Event{dnsEvent("event-1", "example.com", "203.0.113.10")}}, Convert: evidence.FromDNSEvent}
	result, err := stage.Run(context.Background(), "example.com", registry)
	if err != nil {
		t.Fatal(err)
	}
	if result.Events != 1 || result.Evidence != 0 || result.Observations != 0 {
		t.Fatalf("duplicate registration inflated counts: %+v", result)
	}
}

func TestCollectorStageRejectsOutOfScopeEventsAndCancelsCollector(t *testing.T) {
	registry := evidence.NewRegistry()
	stage := CollectorStage{StageName: "dns-test", Collector: sliceCollector{events: []events.Event{dnsEvent("event-1", "other.example", "203.0.113.10")}}, Convert: evidence.FromDNSEvent}
	_, err := stage.Run(context.Background(), "example.com", registry)
	if err == nil {
		t.Fatal("expected out-of-scope event to be rejected")
	}
	if len(registry.AllEvidence()) != 0 {
		t.Fatal("out-of-scope evidence was registered")
	}
	if errors.Is(err, context.Canceled) {
		t.Fatalf("expected scope validation error, got %v", err)
	}
}

func TestEventTargetScopeAllowsSubdomainsButNotSiblingDomains(t *testing.T) {
	if !eventTargetInScope("api.example.com.", "example.com") {
		t.Fatal("in-scope subdomain was rejected")
	}
	if eventTargetInScope("example.com.attacker.test", "example.com") {
		t.Fatal("suffix-confusion target was accepted")
	}
	if eventTargetInScope("other-example.com", "example.com") {
		t.Fatal("sibling domain was accepted")
	}
	if eventTargetInScope("203.0.113.5", "203.0.113.4") {
		t.Fatal("different IP was accepted")
	}
}

type failingCollector struct {
	event events.Event
	err   error
}

func (c failingCollector) Run(ctx context.Context, out chan<- events.Event) error {
	select {
	case out <- c.event:
	case <-ctx.Done():
		return ctx.Err()
	}
	return c.err
}

func TestCollectorStageDoesNotCommitPartialOutputOnCollectorFailure(t *testing.T) {
	registry := evidence.NewRegistry()
	stage := CollectorStage{
		StageName: "dns-failing",
		Collector: failingCollector{event: dnsEvent("event-partial", "example.com", "203.0.113.20"), err: errors.New("simulated collector failure")},
		Convert:   evidence.FromDNSEvent,
	}
	result, err := stage.Run(context.Background(), "example.com", registry)
	if err == nil {
		t.Fatal("expected collector failure")
	}
	if len(registry.AllEvidence()) != 0 || len(registry.AllObservations()) != 0 {
		t.Fatalf("failed stage left partial registry state: evidence=%d observations=%d", len(registry.AllEvidence()), len(registry.AllObservations()))
	}
	if len(result.Findings) != 0 {
		t.Fatalf("failed stage returned uncommitted findings: %+v", result.Findings)
	}
}
