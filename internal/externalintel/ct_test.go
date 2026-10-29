package externalintel

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/itsFuRy007/kem3t/internal/evidence"
	"github.com/itsFuRy007/kem3t/internal/graph"
)

func TestCTLookupNormalizesDeduplicatesAndScopesNames(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("q"); got != "%.example.com" {
			t.Errorf("query scope = %q", got)
		}
		if r.URL.Query().Get("output") != "json" {
			t.Errorf("expected JSON output")
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `[
			{"id":10,"common_name":"WWW.Example.com","name_value":"www.example.com\napi.example.com\nnotexample.com\n*.shop.example.com","issuer_name":"Issuer A","not_before":"2025-01-01","not_after":"2026-01-01"},
			{"id":10,"common_name":"www.example.com","name_value":"api.example.com","issuer_name":"Issuer A"},
			{"id":11,"common_name":"other.test","name_value":"admin.example.com","issuer_name":"Issuer B"}
		]`)
	}))
	defer server.Close()

	client := &CTClient{
		Endpoint: server.URL,
		HTTPClient: server.Client(),
		Now: func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) },
	}
	report, err := client.LookupDomain(context.Background(), "Example.COM.")
	if err != nil { t.Fatal(err) }
	if report.Target != "example.com" { t.Fatalf("target = %q", report.Target) }
	if report.CertificateRecords != 2 { t.Fatalf("records = %d", report.CertificateRecords) }
	if report.UniqueDNSNames != 4 { t.Fatalf("unique names = %d (%v)", report.UniqueDNSNames, report.DNSNames) }
	if strings.Join(report.DNSNames, ",") != "admin.example.com,api.example.com,shop.example.com,www.example.com" {
		t.Fatalf("unexpected names: %v", report.DNSNames)
	}
	if report.UniqueIssuers != 2 { t.Fatalf("issuers = %d", report.UniqueIssuers) }
	if len(report.Limitations) < 2 { t.Fatal("expected explicit limitations") }
}

func TestCTRejectsInvalidTargetAndNonHTTPSEndpoint(t *testing.T) {
	for _, tc := range []struct{ target, endpoint string }{
		{"", "https://crt.sh/"},
		{"192.0.2.1", "https://crt.sh/"},
		{"example.com", "http://crt.sh/"},
	} {
		client := &CTClient{Endpoint: tc.endpoint}
		if _, err := client.LookupDomain(context.Background(), tc.target); err == nil {
			t.Fatalf("expected validation error for target=%q endpoint=%q", tc.target, tc.endpoint)
		}
	}
}

func TestCTRejectsOversizedAndInvalidResponses(t *testing.T) {
	for _, body := range []string{"not-json", strings.Repeat(" ", maxCTResponseBytes+1)} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = fmt.Fprint(w, body)
		}))
		client := &CTClient{Endpoint: server.URL, HTTPClient: server.Client()}
		_, err := client.LookupDomain(context.Background(), "example.com")
		server.Close()
		if err == nil { t.Fatal("expected response error") }
	}
}

func TestCTPropagatesContextCancellation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := &CTClient{Endpoint: server.URL, HTTPClient: server.Client()}
	if _, err := client.LookupDomain(ctx, "example.com"); err == nil {
		t.Fatal("expected cancellation error")
	}
}

func TestRegisterCTReportBuildsEvidenceBackedGraph(t *testing.T) {
	registry := evidence.NewRegistry()
	retrieved := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	report := CTReport{
		Target: "example.com", Source: "crt.sh", RetrievedAt: retrieved,
		Records: []CTRecord{{
			CertificateID: 42, DNSNames: []string{"example.com", "www.example.com", "api.example.com"},
			IssuerName: "Example CA", NotBefore: "2026-01-01", NotAfter: "2027-01-01",
		}},
	}
	added, err := RegisterCTReport(registry, report)
	if err != nil { t.Fatal(err) }
	if added != 3 { t.Fatalf("registered observations = %d, want 3", added) }

	g, err := graph.BuildFromRegistry(registry)
	if err != nil { t.Fatal(err) }
	if len(g.Nodes) != 4 { t.Fatalf("graph nodes = %d, want 4", len(g.Nodes)) }
	if len(g.Edges) != 4 { t.Fatalf("graph edges = %d, want 4", len(g.Edges)) }
	for _, edge := range g.Edges {
		if len(edge.EvidenceIDs) == 0 || len(edge.ObservationIDs) == 0 {
			t.Fatalf("CT graph edge lacks provenance: %+v", edge)
		}
	}

	added, err = RegisterCTReport(registry, report)
	if err != nil { t.Fatal(err) }
	if added != 0 { t.Fatalf("duplicate report added %d observations, want 0", added) }
}

func TestRegisterCTReportRejectsOutOfScopeName(t *testing.T) {
	registry := evidence.NewRegistry()
	report := CTReport{
		Target: "example.com", Source: "crt.sh", RetrievedAt: time.Now().UTC(),
		Records: []CTRecord{{CertificateID: 9, DNSNames: []string{"attacker.test"}}},
	}
	if _, err := RegisterCTReport(registry, report); err == nil {
		t.Fatal("expected out-of-scope CT name to be rejected")
	}
}
