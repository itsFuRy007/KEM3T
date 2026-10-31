package investigation

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/itsFuRy007/kem3t/internal/evidence"
)

func ctNameEvidence(id, name string) evidence.Evidence {
	value, _ := json.Marshal(evidence.CTDNSNameDetails{Target: "example.com", DNSName: name, Source: "crt.sh"})
	return evidence.Evidence{ID: id, EntityID: "example.com", Type: evidence.TypeCTDNSName, Value: string(value)}
}

func TestCTSubdomainPlannerSchedulesOnlyNewInScopeNames(t *testing.T) {
	planner := NewCTSubdomainDNSPlanner(4)
	state := PlanningState{
		Target: "example.com",
		NewEvidence: []evidence.Evidence{
			ctNameEvidence("ct-1", "www.example.com"),
			ctNameEvidence("ct-2", "api.example.com"),
			ctNameEvidence("ct-3", "admin.example.com"),
			ctNameEvidence("ct-4", "example.com"),
			ctNameEvidence("ct-5", "example.com.attacker.test"),
		},
		Completed: []StageOutcome{{Name: "dns-subdomain:www.example.com"}},
		Scheduled: []string{"dns-subdomain:api.example.com"},
	}
	stages, err := planner.Next(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	if len(stages) != 1 || stages[0].Name() != "dns-subdomain:admin.example.com" {
		t.Fatalf("unexpected adaptive DNS stages: %+v", stages)
	}
}

func TestCTSubdomainPlannerEnforcesConfiguredCap(t *testing.T) {
	planner := NewCTSubdomainDNSPlanner(2)
	limitations := make([]string, 0)
	state := PlanningState{Target: "example.com", Limitations: &limitations, NewEvidence: []evidence.Evidence{
		ctNameEvidence("ct-1", "a.example.com"), ctNameEvidence("ct-2", "b.example.com"), ctNameEvidence("ct-3", "c.example.com"),
	}, Scheduled: []string{"dns-subdomain:a.example.com"}}
	stages, err := planner.Next(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	if len(stages) != 1 {
		t.Fatalf("expected only one remaining stage under cap, got %d", len(stages))
	}
	if len(limitations) != 1 || !strings.Contains(limitations[0], "1 candidate name(s) were not queried") {
		t.Fatalf("expected explicit truncation limitation, got %v", limitations)
	}
}

func TestCTSubdomainPlannerReportsCapWhenNoStageCanBeScheduled(t *testing.T) {
	planner := NewCTSubdomainDNSPlanner(1)
	limitations := make([]string, 0)
	state := PlanningState{
		Target:      "example.com",
		Scheduled:   []string{"dns-subdomain:a.example.com"},
		NewEvidence: []evidence.Evidence{ctNameEvidence("ct-b", "b.example.com")},
		Limitations: &limitations,
	}
	stages, err := planner.Next(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	if len(stages) != 0 {
		t.Fatalf("expected no stages when cap is exhausted, got %+v", stages)
	}
	if len(limitations) != 1 || !strings.Contains(limitations[0], "1 candidate name(s) were not queried") {
		t.Fatalf("cap exhaustion was not reported: %v", limitations)
	}
}

func TestCTSubdomainPlannerCountsScheduledAndCompletedNamesOnce(t *testing.T) {
	planner := NewCTSubdomainDNSPlanner(2)
	state := PlanningState{
		Target:    "example.com",
		Scheduled: []string{"dns-subdomain:a.example.com"},
		Completed: []StageOutcome{{Name: "dns-subdomain:a.example.com"}},
		NewEvidence: []evidence.Evidence{
			ctNameEvidence("ct-b", "b.example.com"),
			ctNameEvidence("ct-c", "c.example.com"),
		},
	}
	stages, err := planner.Next(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	if len(stages) != 1 || stages[0].Name() != "dns-subdomain:b.example.com" {
		t.Fatalf("duplicate scheduled/completed name consumed cap twice: %+v", stages)
	}
}
