package intelligence

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/itsFuRy007/kem3t/internal/events"
)

func makeDNSEvent(id, target, ip string) events.Event {
	return events.Event{
		ID:        id,
		Type:      events.EventDNSRecordFound,
		Timestamp: time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC),
		Target:    target,
		Source:    "dns-collector",
		Data: map[string]string{
			"record_type": "IP_ADDRESS",
			"value":       ip,
		},
	}
}

func TestAggregatorGroupsDNSAddresses(t *testing.T) {
	aggregator := NewAggregator()

	input := []events.Event{
		makeDNSEvent("dns-001", "example.test", "192.0.2.10"),
		makeDNSEvent("dns-002", "example.test", "192.0.2.11"),
		makeDNSEvent("dns-003", "example.test", "192.0.2.10"),
	}
	for _, event := range input {
		if err := aggregator.Add(event); err != nil {
			t.Fatalf("Add() returned an error: %v", err)
		}
	}
	findings := aggregator.Findings()
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	finding := findings[0]
	if len(finding.Evidence) != 3 {
		t.Errorf("got %d evidence events, want 3", len(finding.Evidence))
	}
	if !strings.Contains(finding.Fact, "2 unique IP address(es)") {
		t.Errorf("summary should report 2 unique IPs; got %q", finding.Fact)
	}
	if strings.Count(finding.Fact, "192.0.2.10") != 1 {
		t.Errorf("duplicate IP should appear once in summary; got %q", finding.Fact)
	}
	if strings.Count(finding.Fact, "192.0.2.11") != 1 {
		t.Errorf("second IP should appear once in summary; got %q", finding.Fact)
	}
	if err := finding.Validate(); err != nil {
		t.Errorf("summary finding is invalid: %v", err)
	}

}

func TestAggregatorSeparatesTargets(t *testing.T) {
	aggregator := NewAggregator()

	input := []events.Event{
		makeDNSEvent("dns-010", "one.example.test", "192.0.2.10"),
		makeDNSEvent("dns-011", "two.example.test", "192.0.2.11"),
	}
	for _, event := range input {
		if err := aggregator.Add(event); err != nil {
			t.Fatalf("Add() returned an error: %v", err)
		}
	}
	findings := aggregator.Findings()
	if len(findings) != 2 {
		t.Errorf("got %d findings, want 2", len(findings))
	}

}

func TestAggregatorRejectsInvalidEvents(t *testing.T) {
	aggregator := NewAggregator()

	event := makeDNSEvent("dns-020", "example.test", "not-an-ip")
	if err := aggregator.Add(event); err == nil {
		t.Fatal("expected invalid IP address to be rejected")
	}
	if len(aggregator.Findings()) != 0 {
		t.Error("invalid event must not produce a finding")
	}

}

func TestAggregatorRequiresUniqueEventIDs(t *testing.T) {
	aggregator := NewAggregator()

	first := makeDNSEvent("dns-030", "example.test", "192.0.2.10")
	second := makeDNSEvent("dns-030", "example.test", "192.0.2.11")
	if err := aggregator.Add(first); err != nil {
		t.Fatalf("Add(first) returned an error: %v", err)
	}
	if err := aggregator.Add(second); err == nil {
		t.Fatal("expected duplicate event ID to be rejected")
	}

}

func TestAggregatorSummaryIsDeterministic(t *testing.T) {
	build := func(input []events.Event) string {
		aggregator := NewAggregator()

		for _, event := range input {
			if err := aggregator.Add(event); err != nil {
				t.Fatalf("Add() returned an error: %v", err)
			}
		}
		findings := aggregator.Findings()
		if len(findings) != 1 {
			t.Fatalf("got %d findings, want 1", len(findings))
		}
		return fmt.Sprintf("%s|%s", findings[0].Title, findings[0].Fact)
	}
	first := []events.Event{
		makeDNSEvent("dns-040", "example.test", "192.0.2.10"),
		makeDNSEvent("dns-041", "example.test", "192.0.2.11"),
	}
	second := []events.Event{
		makeDNSEvent("dns-041", "example.test", "192.0.2.11"),
		makeDNSEvent("dns-040", "example.test", "192.0.2.10"),
	}
	if a, b := build(first), build(second); a != b {
		t.Errorf("summary changed with event order:\nfirst:  %s\nsecond: %s", a, b)
	}

}
