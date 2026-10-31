package externalintel

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/itsFuRy007/kem3t/internal/evidence"
	"github.com/itsFuRy007/kem3t/internal/graph"
)

func TestRDAPLookupUsesBootstrapAndNormalizesMetadata(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		switch {
		case r.URL.Path == "/bootstrap":
			fmt.Fprintf(w, "{\"services\":[[[\"com\"],[%q]]]}", server.URL+"/rdap")
		case r.URL.Path == "/rdap/domain/example.com":
			fmt.Fprint(w, "{\"ldhName\":\"EXAMPLE.COM\",\"handle\":\"EXAMPLE-123\",\"status\":[\"active\",\"active\",\"client transfer prohibited\"],\"nameservers\":[{\"ldhName\":\"NS1.EXAMPLE.COM.\"},{\"ldhName\":\"ns2.example.com\"},{\"ldhName\":\"ns1.example.com\"}],\"events\":[{\"eventAction\":\"registration\",\"eventDate\":\"2020-01-01T00:00:00Z\"},{\"eventAction\":\"expiration\",\"eventDate\":\"2027-01-01T00:00:00Z\"}],\"entities\":[{\"roles\":[\"registrar\"],\"vcardArray\":[\"vcard\",[[\"version\",{},\"text\",\"4.0\"],[\"fn\",{},\"text\",\"Example Registrar\"],[\"email\",{},\"text\",\"private@example.com\"]]]}]}")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := &RDAPClient{HTTPClient: server.Client(), BootstrapURL: server.URL + "/bootstrap", Now: func() time.Time { return time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC) }}
	report, err := client.LookupDomain(context.Background(), "Example.COM.")
	if err != nil {
		t.Fatal(err)
	}
	if report.Target != "example.com" || report.Handle != "EXAMPLE-123" {
		t.Fatalf("unexpected target/handle: %+v", report)
	}
	if report.Registrar != "Example Registrar" {
		t.Fatalf("registrar=%q", report.Registrar)
	}
	if strings.Join(report.Status, ",") != "active,client transfer prohibited" {
		t.Fatalf("status=%v", report.Status)
	}
	if strings.Join(report.NameServers, ",") != "ns1.example.com,ns2.example.com" {
		t.Fatalf("nameservers=%v", report.NameServers)
	}
	if len(report.Events) != 2 || report.RetrievedAt.IsZero() {
		t.Fatalf("events/time missing: %+v", report)
	}
	encoded := fmt.Sprintf("%+v", report)
	if strings.Contains(encoded, "private@example.com") {
		t.Fatal("RDAP contact email must not be collected")
	}
	if len(report.Limitations) < 2 {
		t.Fatal("expected interpretation limits")
	}
}

func TestRDAPRejectsInvalidTargetAndInsecureBootstrap(t *testing.T) {
	for _, tc := range []struct{ target, bootstrap string }{{"192.0.2.1", "https://data.iana.org/rdap/dns.json"}, {"example.com", "http://example.test/bootstrap"}, {"", "https://data.iana.org/rdap/dns.json"}} {
		client := &RDAPClient{BootstrapURL: tc.bootstrap}
		if _, err := client.LookupDomain(context.Background(), tc.target); err == nil {
			t.Fatalf("expected error for target=%q bootstrap=%q", tc.target, tc.bootstrap)
		}
	}
}

func TestRDAPRejectsMismatchedDomainResponse(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bootstrap" {
			fmt.Fprintf(w, "{\"services\":[[[\"com\"],[%q]]]}", server.URL+"/rdap")
			return
		}
		fmt.Fprint(w, "{\"ldhName\":\"not-example.com\",\"nameservers\":[]}")
	}))
	defer server.Close()
	client := &RDAPClient{HTTPClient: server.Client(), BootstrapURL: server.URL + "/bootstrap"}
	if _, err := client.LookupDomain(context.Background(), "example.com"); err == nil {
		t.Fatal("expected target mismatch rejection")
	}
}

func TestRegisterRDAPReportPersistsProvenanceAndGraph(t *testing.T) {
	registry := evidence.NewRegistry()
	report := RDAPReport{Target: "example.com", Source: "rdap.example.test", RetrievedAt: time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC), Handle: "EXAMPLE-123", Registrar: "Example Registrar", Status: []string{"active"}, NameServers: []string{"ns1.example.com", "ns2.example.com"}, Events: []RDAPEvent{{Action: "registration", Date: "2020-01-01T00:00:00Z"}}}
	added, err := RegisterRDAPReport(registry, report)
	if err != nil {
		t.Fatal(err)
	}
	if !added {
		t.Fatal("expected first observation to be added")
	}
	g, err := graph.BuildFromRegistry(registry)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Nodes) != 4 || len(g.Edges) != 3 {
		t.Fatalf("unexpected graph size nodes=%d edges=%d", len(g.Nodes), len(g.Edges))
	}
	for _, edge := range g.Edges {
		if len(edge.EvidenceIDs) == 0 || len(edge.ObservationIDs) == 0 {
			t.Fatalf("edge lacks provenance: %+v", edge)
		}
	}
	added, err = RegisterRDAPReport(registry, report)
	if err != nil {
		t.Fatal(err)
	}
	if added {
		t.Fatal("duplicate timestamp should not add another observation")
	}
	report.RetrievedAt = report.RetrievedAt.Add(time.Hour)
	added, err = RegisterRDAPReport(registry, report)
	if err != nil {
		t.Fatal(err)
	}
	if !added {
		t.Fatal("new retrieval time should be recorded as another observation")
	}
}

func TestRegisterRDAPReportRejectsInvalidNameserver(t *testing.T) {
	registry := evidence.NewRegistry()
	report := RDAPReport{Target: "example.com", Source: "rdap.example.test", RetrievedAt: time.Now().UTC(), NameServers: []string{"bad..name"}}
	if _, err := RegisterRDAPReport(registry, report); err == nil {
		t.Fatal("expected invalid nameserver rejection")
	}
}

func TestIPRDAPLookupUsesMostSpecificIANAServiceAndValidatesRange(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		switch r.URL.Path {
		case "/ipv4-bootstrap":
			fmt.Fprintf(w, "{\"services\":[[[\"8.0.0.0/8\"],[%q]],[[\"8.8.8.0/24\"],[%q]]]}", server.URL+"/broad", server.URL+"/specific")
		case "/specific/ip/8.8.8.8":
			fmt.Fprint(w, "{\"handle\":\"NET-8-8-8-0-1\",\"name\":\"Google LLC\",\"startAddress\":\"8.8.8.0\",\"endAddress\":\"8.8.8.255\",\"country\":\"US\",\"type\":\"DIRECT ALLOCATION\",\"status\":[\"active\"]}")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := &RDAPClient{HTTPClient: server.Client(), IPBootstrapURL: server.URL + "/ipv4-bootstrap", Now: func() time.Time { return time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC) }}
	report, err := client.LookupIP(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if report.Target != "8.8.8.8" || report.Source != strings.TrimPrefix(server.URL, "https://") || report.Name != "Google LLC" || report.StartAddress != "8.8.8.0" || report.EndAddress != "8.8.8.255" {
		t.Fatalf("unexpected IP RDAP report: %+v", report)
	}
}

func TestIPRDAPRejectsRangeThatDoesNotContainTarget(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bootstrap" {
			fmt.Fprintf(w, "{\"services\":[[[\"8.0.0.0/8\"],[%q]]]}", server.URL+"/rdap")
			return
		}
		fmt.Fprint(w, "{\"startAddress\":\"1.1.1.0\",\"endAddress\":\"1.1.1.255\"}")
	}))
	defer server.Close()
	client := &RDAPClient{HTTPClient: server.Client(), IPBootstrapURL: server.URL + "/bootstrap"}
	if _, err := client.LookupIP(context.Background(), "8.8.8.8"); err == nil {
		t.Fatal("expected range mismatch rejection")
	}
}

func TestRegisterIPRDAPReportPersistsGraphProvenance(t *testing.T) {
	registry := evidence.NewRegistry()
	report := IPRDAPReport{Target: "8.8.8.8", Source: "rdap.example.test", RetrievedAt: time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC), Handle: "NET-8-8-8-0-1", Name: "Google LLC", StartAddress: "8.8.8.0", EndAddress: "8.8.8.255", Country: "US"}
	added, err := RegisterIPRDAPReport(registry, report)
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
	if len(g.Nodes) != 2 || len(g.Edges) != 1 || g.Edges[0].Type != graph.EdgeIPInNetworkRange || len(g.Edges[0].EvidenceIDs) != 1 || len(g.Edges[0].ObservationIDs) != 1 {
		t.Fatalf("unexpected graph/provenance: %+v", g)
	}
}

func TestRegisterIPRDAPReportRejectsInvalidNetworkRanges(t *testing.T) {
	base := IPRDAPReport{
		Target: "8.8.8.8", Source: "rdap.example.test",
		RetrievedAt:  time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC),
		StartAddress: "8.8.8.0", EndAddress: "8.8.8.255",
	}
	tests := []struct {
		name  string
		start string
		end   string
	}{
		{name: "missing start", start: "", end: "8.8.8.255"},
		{name: "invalid start", start: "not-an-ip", end: "8.8.8.255"},
		{name: "invalid end", start: "8.8.8.0", end: "not-an-ip"},
		{name: "reversed range", start: "8.8.8.255", end: "8.8.8.0"},
		{name: "wrong address family", start: "2001:db8::1", end: "2001:db8::2"},
		{name: "range excludes target", start: "1.1.1.0", end: "1.1.1.255"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			registry := evidence.NewRegistry()
			report := base
			report.StartAddress = test.start
			report.EndAddress = test.end
			if _, err := RegisterIPRDAPReport(registry, report); err == nil {
				t.Fatal("expected invalid network range to be rejected")
			}
			if len(registry.AllEvidence()) != 0 || len(registry.AllObservations()) != 0 {
				t.Fatal("invalid IP RDAP report was persisted")
			}
		})
	}
}

func TestRegisterIPRDAPReportNormalizesMappedIPv4Target(t *testing.T) {
	registry := evidence.NewRegistry()
	report := IPRDAPReport{
		Target: "::ffff:8.8.8.8", Source: "rdap.example.test",
		RetrievedAt:  time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC),
		StartAddress: "8.8.8.0", EndAddress: "8.8.8.255",
	}
	if _, err := RegisterIPRDAPReport(registry, report); err != nil {
		t.Fatal(err)
	}
	records := registry.AllEvidence()
	if len(records) != 1 || records[0].EntityID != "8.8.8.8" {
		t.Fatalf("mapped IPv4 target was not normalized: %+v", records)
	}
}

func TestRegisterIPRDAPReportRejectsZoneIdentifiers(t *testing.T) {
	registry := evidence.NewRegistry()
	report := IPRDAPReport{
		Target: "fe80::1%eth0", Source: "rdap.example.test",
		RetrievedAt:  time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC),
		StartAddress: "fe80::", EndAddress: "fe80::ffff",
	}
	if _, err := RegisterIPRDAPReport(registry, report); err == nil {
		t.Fatal("expected zone-scoped IP target to be rejected")
	}
	if len(registry.AllEvidence()) != 0 {
		t.Fatal("zone-scoped IP report was persisted")
	}
}

func TestRDAPRejectsHTTPSDowngradeRedirectWithCustomClient(t *testing.T) {
	var plainHits atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plainHits.Add(1)
		fmt.Fprint(w, `{"ldhName":"example.com","nameservers":[]}`)
	}))
	defer plain.Close()

	var secure *httptest.Server
	secure = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/bootstrap":
			fmt.Fprintf(w, `{"services":[[["com"],[%q]]]}`, secure.URL+"/rdap")
		case "/rdap/domain/example.com":
			http.Redirect(w, r, plain.URL+"/rdap", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer secure.Close()

	client := &RDAPClient{
		HTTPClient:   secure.Client(),
		BootstrapURL: secure.URL + "/bootstrap",
	}
	if _, err := client.LookupDomain(context.Background(), "example.com"); err == nil {
		t.Fatal("expected HTTPS downgrade redirect to be rejected")
	}
	if plainHits.Load() != 0 {
		t.Fatal("RDAP client followed an HTTPS-to-HTTP redirect")
	}
}
