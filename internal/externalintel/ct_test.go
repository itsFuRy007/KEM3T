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
	queries := make(chan string, 2)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("q")
		queries <- query
		if r.URL.Query().Get("output") != "json" {
			t.Errorf("expected JSON output")
		}
		w.Header().Set("Content-Type", "application/json")
		switch query {
		case "example.com":
			fmt.Fprint(w, `[
				{"id":12,"common_name":"Example.com","name_value":"example.com","issuer_name":"Issuer C","not_before":"2025-01-01","not_after":"2026-01-01"}
			]`)
		case "%.example.com":
			fmt.Fprint(w, `[
				{"id":10,"common_name":"WWW.Example.com","name_value":"www.example.com\napi.example.com\nnotexample.com\n*.shop.example.com","issuer_name":"Issuer A","not_before":"2025-01-01","not_after":"2026-01-01"},
				{"id":10,"common_name":"www.example.com","name_value":"api.example.com","issuer_name":"Issuer A"},
				{"id":11,"common_name":"other.test","name_value":"admin.example.com","issuer_name":"Issuer B"}
			]`)
		default:
			t.Errorf("unexpected CT query %q", query)
			http.Error(w, "unexpected query", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	client := &CTClient{
		Endpoint:   server.URL,
		HTTPClient: server.Client(),
		Now:        func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) },
	}
	report, err := client.LookupDomain(context.Background(), "Example.COM.")
	if err != nil {
		t.Fatal(err)
	}
	if got := <-queries; got != "example.com" {
		t.Fatalf("first CT query = %q, want exact apex", got)
	}
	if got := <-queries; got != "%.example.com" {
		t.Fatalf("second CT query = %q, want subdomains", got)
	}
	if report.Target != "example.com" {
		t.Fatalf("target = %q", report.Target)
	}
	if report.CertificateRecords != 3 {
		t.Fatalf("records = %d", report.CertificateRecords)
	}
	if report.UniqueDNSNames != 5 {
		t.Fatalf("unique names = %d (%v)", report.UniqueDNSNames, report.DNSNames)
	}
	if strings.Join(report.DNSNames, ",") != "admin.example.com,api.example.com,example.com,shop.example.com,www.example.com" {
		t.Fatalf("unexpected names: %v", report.DNSNames)
	}
	if report.UniqueIssuers != 3 {
		t.Fatalf("issuers = %d", report.UniqueIssuers)
	}
	if len(report.Limitations) < 2 {
		t.Fatal("expected explicit limitations")
	}
}

func TestCTDeduplicatesIDLessRowsAcrossQueries(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `[{"common_name":"www.example.com","name_value":"www.example.com","issuer_name":"Example CA","not_before":"2026-01-01","not_after":"2027-01-01"}]`)
	}))
	defer server.Close()

	client := &CTClient{Endpoint: server.URL, HTTPClient: server.Client()}
	report, err := client.LookupDomain(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if report.CertificateRecords != 1 {
		t.Fatalf("ID-less duplicate rows produced %d records, want 1", report.CertificateRecords)
	}
	if len(report.Records) != 1 || report.Records[0].CertificateID != 0 {
		t.Fatalf("unexpected ID-less record result: %+v", report.Records)
	}
}

func TestCTUsesConfiguredTimeoutWithCustomHTTPClient(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	client := &CTClient{
		Endpoint:   server.URL,
		HTTPClient: server.Client(),
		Timeout:    25 * time.Millisecond,
	}
	started := time.Now()
	_, err := client.LookupDomain(context.Background(), "example.com")
	if err == nil {
		t.Fatal("expected configured CT timeout to cancel the request")
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("CT request timeout was not applied promptly: %s", elapsed)
	}
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
		if err == nil {
			t.Fatal("expected response error")
		}
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
	added, err := RegisterCTReport(registry, report, evidence.ObservationProvenance{
		CollectionRunID: "investigation-ct-test", Stage: "certificate-transparency",
	})
	if err != nil {
		t.Fatal(err)
	}
	if added != 3 {
		t.Fatalf("registered observations = %d, want 3", added)
	}
	for _, observation := range registry.AllObservations() {
		if observation.CollectionRunID != "investigation-ct-test" || observation.Stage != "certificate-transparency" {
			t.Fatalf("external-intelligence provenance was not attached: %+v", observation)
		}
	}

	g, err := graph.BuildFromRegistry(registry)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Nodes) != 4 {
		t.Fatalf("graph nodes = %d, want 4", len(g.Nodes))
	}
	if len(g.Edges) != 4 {
		t.Fatalf("graph edges = %d, want 4", len(g.Edges))
	}
	for _, edge := range g.Edges {
		if len(edge.EvidenceIDs) == 0 || len(edge.ObservationIDs) == 0 {
			t.Fatalf("CT graph edge lacks provenance: %+v", edge)
		}
	}

	added, err = RegisterCTReport(registry, report)
	if err != nil {
		t.Fatal(err)
	}
	if added != 0 {
		t.Fatalf("duplicate report added %d observations, want 0", added)
	}
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

func TestRegisterCTReportDoesNotPersistPartialResultsOnValidationFailure(t *testing.T) {
	registry := evidence.NewRegistry()
	report := CTReport{
		Target: "example.com", Source: "crt.sh", RetrievedAt: time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC),
		Records: []CTRecord{
			{CertificateID: 100, DNSNames: []string{"www.example.com"}},
			{CertificateID: 101, DNSNames: []string{"attacker.test"}},
		},
	}
	if _, err := RegisterCTReport(registry, report); err == nil {
		t.Fatal("expected out-of-scope CT name to be rejected")
	}
	if len(registry.AllEvidence()) != 0 || len(registry.AllObservations()) != 0 {
		t.Fatalf("invalid CT report left partial registry state: evidence=%d observations=%d", len(registry.AllEvidence()), len(registry.AllObservations()))
	}
}

func TestRegisterCTReportKeepsEvidenceIdentityStableAcrossRetrievals(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "evidence.db")
	registry, err := evidence.OpenRegistry(dbPath)
	if err != nil {
		t.Fatalf("open SQLite evidence registry: %v", err)
	}
	firstRetrieved := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	report := CTReport{
		Target: "example.com", Source: "crt.sh", RetrievedAt: firstRetrieved,
		Records: []CTRecord{{
			CertificateID: 42,
			DNSNames:      []string{"example.com", "www.example.com"},
			IssuerName:    "Example CA",
			NotBefore:     "2026-01-01",
			NotAfter:      "2027-01-01",
		}},
	}
	if added, err := RegisterCTReport(registry, report); err != nil || added != 2 {
		t.Fatalf("first registration = (%d, %v), want (2, nil)", added, err)
	}
	firstEvidence := registry.AllEvidence()
	firstIDs := []string{firstEvidence[0].ID, firstEvidence[1].ID}

	report.RetrievedAt = firstRetrieved.Add(time.Hour)
	if added, err := RegisterCTReport(registry, report); err != nil || added != 2 {
		t.Fatalf("second registration = (%d, %v), want two new observations", added, err)
	}
	secondEvidence := registry.AllEvidence()
	if len(secondEvidence) != 2 {
		t.Fatalf("evidence count = %d, want 2 stable facts", len(secondEvidence))
	}
	if secondEvidence[0].ID != firstIDs[0] || secondEvidence[1].ID != firstIDs[1] {
		t.Fatalf("CT evidence identity changed across retrievals: first=%v second=%v", firstIDs, []string{secondEvidence[0].ID, secondEvidence[1].ID})
	}
	if got := len(registry.AllObservations()); got != 4 {
		t.Fatalf("observation count = %d, want 4 retrieval observations", got)
	}
	if err := registry.Close(); err != nil {
		t.Fatalf("close SQLite evidence registry: %v", err)
	}
	reopened, err := evidence.OpenRegistry(dbPath)
	if err != nil {
		t.Fatalf("reopen SQLite evidence registry: %v", err)
	}
	defer reopened.Close()
	if got := len(reopened.AllEvidence()); got != 2 {
		t.Fatalf("persisted evidence count = %d, want 2 stable facts", got)
	}
	if got := len(reopened.AllObservations()); got != 4 {
		t.Fatalf("persisted observation count = %d, want 4 retrieval observations", got)
	}
}
