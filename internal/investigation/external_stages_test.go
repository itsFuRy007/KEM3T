package investigation

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/itsFuRy007/kem3t/internal/evidence"
	"github.com/itsFuRy007/kem3t/internal/externalintel"
)

func TestExternalCTStageRegistersIntoTheSameInvestigation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `[{"id":17,"common_name":"www.example.com","name_value":"www.example.com\\napi.example.com","issuer_name":"Test CA","not_before":"2026-01-01","not_after":"2027-01-01"}]`)
	}))
	defer server.Close()
	client := &externalintel.CTClient{Endpoint: server.URL, HTTPClient: server.Client(), Now: func() time.Time { return time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC) }}
	registry := evidence.NewRegistry()
	result, err := (&Engine{Registry: registry, Stages: []Stage{NewCTStageWithClient(client)}}).Run(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.AllEvidence()) == 0 || len(registry.AllObservations()) == 0 {
		t.Fatal("external CT evidence was not registered")
	}
	if len(result.Graph.Nodes) == 0 || result.Report.Target != "example.com" {
		t.Fatalf("external stage did not contribute to shared graph/report: %+v", result)
	}
	if result.Stages[0].Result.Evidence == 0 {
		t.Fatalf("external stage contribution was not reported: %+v", result.Stages[0])
	}
}

func TestStageLimitationsPreserveProviderCaveatsAndTruncation(t *testing.T) {
	got := stageLimitations([]string{"provider caveat"}, "Passive DNS", true)
	if len(got) != 2 || got[0] != "provider caveat" {
		t.Fatalf("provider limitations were not preserved: %v", got)
	}
	if !strings.Contains(got[1], "truncated") {
		t.Fatalf("truncation limitation missing: %v", got)
	}
}
