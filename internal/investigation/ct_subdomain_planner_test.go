package investigation

import (
	"context"
	"encoding/json"
	"testing"
	"strings"

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
	state := PlanningState{Target: "example.com", NewEvidence: []evidence.Evidence{
		ctNameEvidence("ct-1", "a.example.com"), ctNameEvidence("ct-2", "b.example.com"), ctNameEvidence("ct-3", "c.example.com"),
	}, Scheduled: []string{"dns-subdomain:a.example.com"}}
	stages, err := planner.Next(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	if len(stages) != 1 {
		t.Fatalf("expected only one remaining stage under cap, got %d", len(stages))
	}
	limited, ok := stages[0].(limitedStage)
	if !ok || !strings.Contains(limited.limitation, "1 candidate name(s) were not queried") {
		t.Fatalf("expected explicit truncation limitation, got %#v", stages[0])
	}
}
