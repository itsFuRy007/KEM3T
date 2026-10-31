package externalintel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/itsFuRy007/kem3t/internal/evidence"
	"github.com/itsFuRy007/kem3t/internal/graph"
)

func TestPassiveDNSLookupFiltersScopesAndDeduplicates(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/indicators/domain/example.com/passive_dns" {
			t.Errorf("path=%q", r.URL.Path)
		}
		if r.URL.Query().Get("limit") != "500" {
			t.Errorf("limit=%q", r.URL.Query().Get("limit"))
		}
		if r.Header.Get("X-OTX-API-KEY") != "test-secret" {
			t.Error("expected configured API key header")
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, "{\"count\":7,\"passive_dns\":[{\"address\":\"8.8.8.8\",\"hostname\":\"WWW.EXAMPLE.COM.\",\"record_type\":\"A\",\"first\":\"2020-01-01\",\"last\":\"2026-01-01\",\"asn\":\"AS15169\"},{\"address\":\"8.8.8.8\",\"hostname\":\"www.example.com\",\"record_type\":\"A\",\"first\":\"2020-01-01\",\"last\":\"2026-01-01\",\"asn\":\"AS15169\"},{\"address\":\"2001:4860:4860::8888\",\"hostname\":\"api.example.com\",\"record_type\":\"AAAA\",\"first\":\"2021-01-01\",\"last\":\"2026-01-01\"},{\"address\":\"1.2.3.4\",\"hostname\":\"example.com.attacker.test\",\"record_type\":\"A\"},{\"address\":\"1.2.3.4\",\"hostname\":\"other.test\",\"record_type\":\"A\"},{\"address\":\"not-an-ip\",\"hostname\":\"example.com\",\"record_type\":\"A\"},{\"address\":\"8.8.8.8\",\"hostname\":\"example.com\",\"record_type\":\"AAAA\"}]}")
	}))
	defer server.Close()
	client := &PassiveDNSClient{HTTPClient: server.Client(), BaseURL: server.URL + "/api/v1", APIKey: "test-secret", Now: func() time.Time { return time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC) }}
	report, err := client.LookupDomain(context.Background(), "Example.COM.")
	if err != nil {
		t.Fatal(err)
	}
	if report.Target != "example.com" || report.SourceRecordCount != 7 || len(report.Records) != 2 {
		t.Fatalf("unexpected report: %+v", report)
	}
	if report.Records[0].Hostname != "api.example.com" || report.Records[1].Hostname != "www.example.com" {
		t.Fatalf("unexpected order: %+v", report.Records)
	}
	if !strings.Contains(strings.Join(report.Limitations, " "), "historical") {
		t.Fatal("missing historical interpretation caveat")
	}
}

func TestPassiveDNSRejectsInvalidTargetAndInsecureEndpoint(t *testing.T) {
	for _, tc := range []struct{ target, base string }{{"192.0.2.1", "https://otx.alienvault.com/api/v1"}, {"example.com", "http://otx.example/api/v1"}, {"", "https://otx.alienvault.com/api/v1"}} {
		if _, err := (&PassiveDNSClient{BaseURL: tc.base}).LookupDomain(context.Background(), tc.target); err == nil {
			t.Fatalf("expected rejection for target=%q base=%q", tc.target, tc.base)
		}
	}
}

func TestRegisterPassiveDNSReportPersistsHistoricalGraphProvenance(t *testing.T) {
	registry := evidence.NewRegistry()
	report := PassiveDNSReport{Target: "example.com", Source: "otx.alienvault.com", RetrievedAt: time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC), Truncated: true, Records: []PassiveDNSRecord{{Hostname: "www.example.com", Address: "8.8.8.8", RecordType: "A", FirstSeen: "2020-01-01", LastSeen: "2026-01-01"}}}
	added, err := RegisterPassiveDNSReport(registry, report)
	if err != nil {
		t.Fatal(err)
	}
	if added != 1 {
		t.Fatalf("added=%d", added)
	}
	stored := registry.AllEvidence()
	if len(stored) != 1 {
		t.Fatalf("expected one evidence record, got %d", len(stored))
	}
	var details evidence.PassiveDNSDetails
	if err := json.Unmarshal([]byte(stored[0].Value), &details); err != nil {
		t.Fatal(err)
	}
	if !details.Truncated {
		t.Fatal("truncation state was not preserved in passive-DNS evidence")
	}
	g, err := graph.BuildFromRegistry(registry)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Nodes) != 2 || len(g.Edges) != 1 {
		t.Fatalf("unexpected graph: nodes=%d edges=%d", len(g.Nodes), len(g.Edges))
	}
	edge := g.Edges[0]
	if edge.Type != graph.EdgePassiveDNSResolvesTo || len(edge.EvidenceIDs) != 1 || len(edge.ObservationIDs) != 1 {
		t.Fatalf("missing passive DNS provenance: %+v", edge)
	}
	added, err = RegisterPassiveDNSReport(registry, report)
	if err != nil {
		t.Fatal(err)
	}
	if added != 0 {
		t.Fatalf("duplicate observation count=%d", added)
	}
}

func TestRegisterPassiveDNSRejectsOutOfScopeHostname(t *testing.T) {
	registry := evidence.NewRegistry()
	report := PassiveDNSReport{Target: "example.com", Source: "otx", RetrievedAt: time.Now().UTC(), Records: []PassiveDNSRecord{{Hostname: "example.com.attacker.test", Address: "8.8.8.8", RecordType: "A"}}}
	if _, err := RegisterPassiveDNSReport(registry, report); err == nil {
		t.Fatal("expected out-of-scope hostname rejection")
	}
}
