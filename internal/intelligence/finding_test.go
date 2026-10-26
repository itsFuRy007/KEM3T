package intelligence

import (
	"testing"
	"time"

	"github.com/itsFuRy007/kem3t/internal/events"
)

func TestValidFinding(t *testing.T) {
	evidence := events.Event{
		ID:        "event-001",
		Type:      events.EventSubdomainDiscovered,
		Timestamp: time.Now(),
		Target:    "dev.example.com",
		Source:    "test-collector",
	}

	finding := Finding{
		Title:       "Development-related hostname observed",
		Priority:    PriorityInterest,
		Fact:        "The hostname dev.example.com was discovered.",
		Observation: "The hostname contains the keyword dev.",
		PossibleSignificance: "It may indicate development or staging " +
			"infrastructure, but this is unverified.",
		Evidence: []events.Event{evidence},
		NextSteps: []string{
			"Verify the asset.",
			"Identify its exposed services.",
		},
	}

	if err := finding.Validate(); err != nil {
		t.Fatalf("expected valid finding, got error: %v", err)
	}
}

func TestFindingRequiresEvidence(t *testing.T) {
	finding := Finding{
		Title:    "Test finding",
		Priority: PriorityInfo,
		Fact:     "A test observation.",
	}

	if err := finding.Validate(); err == nil {
		t.Fatal("expected finding without evidence to be rejected")
	}
}

func TestAnalyzeDevelopmentSubdomain(t *testing.T) {
	event := events.Event{
		ID:        "event-010",
		Type:      events.EventSubdomainDiscovered,
		Timestamp: time.Now(),
		Target:    "dev.example.com",
		Source:    "test-collector",
	}

	engine := &Engine{}

	finding, err := engine.Analyze(event)
	if err != nil {
		t.Fatalf("Analyze returned an error: %v", err)
	}

	if finding == nil {
		t.Fatal("expected a finding")
	}

	if finding.Priority != PriorityInterest {
		t.Fatalf("expected INTERESTING priority, got %s", finding.Priority)
	}

	if len(finding.Evidence) != 1 {
		t.Fatalf("expected 1 evidence event, got %d", len(finding.Evidence))
	}
}

func TestAnalyzeOrdinarySubdomain(t *testing.T) {
	event := events.Event{
		ID:        "event-011",
		Type:      events.EventSubdomainDiscovered,
		Timestamp: time.Now(),
		Target:    "api.example.com",
		Source:    "test-collector",
	}

	engine := &Engine{}

	finding, err := engine.Analyze(event)
	if err != nil {
		t.Fatalf("Analyze returned an error: %v", err)
	}

	if finding == nil {
		t.Fatal("expected a finding")
	}

	if finding.Priority != PriorityInfo {
		t.Fatalf("expected INFO priority, got %s", finding.Priority)
	}
}
