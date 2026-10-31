package externalintel

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/itsFuRy007/kem3t/internal/evidence"
	"github.com/itsFuRy007/kem3t/internal/graph"
)

func TestThreatIntelLookupReturnsCommunityContextNotVerdict(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/indicators/domain/example.com/general" {
			t.Errorf("path=%q", r.URL.Path)
		}
		if r.Header.Get("X-OTX-API-KEY") != "test-secret" {
			t.Error("expected API key header")
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, "{\"indicator\":\"example.com\",\"type\":\"domain\",\"pulse_info\":{\"count\":2,\"pulses\":[{\"id\":\"pulse-2\",\"name\":\"Example report\",\"tags\":[\"phishing\",\"test\",\"phishing\"],\"created\":\"2025-01-01\",\"modified\":\"2026-01-01\"},{\"id\":\"pulse-2\",\"name\":\"Example report\",\"tags\":[\"test\"]}]}}")
	}))
	defer server.Close()
	client := &ThreatIntelClient{HTTPClient: server.Client(), BaseURL: server.URL + "/api/v1", APIKey: "test-secret", Now: func() time.Time { return time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC) }}
	report, err := client.Lookup(context.Background(), "Example.COM.")
	if err != nil {
		t.Fatal(err)
	}
	if report.Target != "example.com" || report.IndicatorType != "domain" || report.PulseCount != 2 || len(report.Pulses) != 1 || !report.Truncated {
		t.Fatalf("unexpected report: %+v", report)
	}
	if len(report.Pulses[0].Tags) != 2 || report.Pulses[0].Tags[0] != "phishing" {
		t.Fatalf("tags not normalized: %v", report.Pulses[0].Tags)
	}
}

func TestThreatIntelRejectsPrivateIPAndMismatchedResponse(t *testing.T) {
	if _, err := (&ThreatIntelClient{}).Lookup(context.Background(), "192.168.1.1"); err == nil {
		t.Fatal("expected private IP rejection")
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "{\"indicator\":\"attacker.test\",\"pulse_info\":{\"count\":0,\"pulses\":[]}}")
	}))
	defer server.Close()
	client := &ThreatIntelClient{HTTPClient: server.Client(), BaseURL: server.URL}
	if _, err := client.Lookup(context.Background(), "example.com"); err == nil {
		t.Fatal("expected mismatched indicator rejection")
	}
}

func TestRegisterThreatIntelReportBuildsProvenanceGraph(t *testing.T) {
	registry := evidence.NewRegistry()
	report := ThreatIntelReport{Target: "example.com", IndicatorType: "domain", Source: "otx.example.test", RetrievedAt: time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC), PulseCount: 1, Pulses: []ThreatPulse{{ID: "pulse-1", Name: "Community report", Tags: []string{"phishing"}}}}
	added, err := RegisterThreatIntelReport(registry, report)
	if err != nil {
		t.Fatal(err)
	}
	if !added {
		t.Fatal("expected observation")
	}
	g, err := graph.BuildFromRegistry(registry)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Nodes) != 2 || len(g.Edges) != 1 {
		t.Fatalf("unexpected graph: %d nodes %d edges", len(g.Nodes), len(g.Edges))
	}
	edge := g.Edges[0]
	if edge.Type != graph.EdgeIndicatorMentionedInPulse || len(edge.EvidenceIDs) != 1 || len(edge.ObservationIDs) != 1 {
		t.Fatalf("missing provenance: %+v", edge)
	}
}

func TestThreatIntelEmptyPulsesDoNotImplyBenignness(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "{\"indicator\":\"example.com\",\"pulse_info\":{\"count\":0,\"pulses\":[]}}")
	}))
	defer server.Close()
	report, err := (&ThreatIntelClient{HTTPClient: server.Client(), BaseURL: server.URL}).Lookup(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Pulses) != 0 || len(report.Limitations) < 2 {
		t.Fatalf("expected empty result with limitations: %+v", report)
	}
}
