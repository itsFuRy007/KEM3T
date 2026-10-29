package graph

import (
	"strings"
	"testing"
)

func TestPivotTraversesEvidenceBackedInfrastructureRelationships(t *testing.T) {
	fingerprint := strings.Repeat("a1", 32)
	certificateID := "tls-cert:" + fingerprint

	graph := Graph{
		Nodes: []Node{
			{ID: "domain:api.example.com", Type: NodeDomain, Value: "api.example.com"},
			{ID: "domain:www.example.com", Type: NodeDomain, Value: "www.example.com"},
			{ID: "ip:192.0.2.10", Type: NodeIP, Value: "192.0.2.10"},
			{ID: "service:192.0.2.10:443:https", Type: NodeNetworkService, Value: "192.0.2.10:443 (https)"},
			{ID: certificateID, Type: NodeTLSCertificate, Value: fingerprint},
		},
		Edges: []Edge{
			{ID: "hosts-service:192.0.2.10:443:https", Type: EdgeHostsService, Source: "ip:192.0.2.10", Target: "service:192.0.2.10:443:https", Port: 443, EvidenceIDs: []string{"service-1"}},
			{ID: "presents-certificate:api.example.com:443:" + fingerprint, Type: EdgePresentsCertificate, Source: "domain:api.example.com", Target: certificateID, Port: 443, EvidenceIDs: []string{"tls-1"}},
			{ID: "resolves-to:api.example.com:192.0.2.10", Type: EdgeResolvesTo, Source: "domain:api.example.com", Target: "ip:192.0.2.10", EvidenceIDs: []string{"dns-1"}},
			{ID: "resolves-to:www.example.com:192.0.2.10", Type: EdgeResolvesTo, Source: "domain:www.example.com", Target: "ip:192.0.2.10", EvidenceIDs: []string{"dns-2"}},
		},
	}

	assertPivot := func(kind PivotKind, source string, want ...string) {
		t.Helper()
		got, err := Pivot(graph, source, kind)
		if err != nil {
			t.Fatalf("Pivot(%q, %q) returned error: %v", kind, source, err)
		}
		if len(got) != len(want) {
			t.Fatalf("Pivot(%q, %q) returned %d nodes, want %d", kind, source, len(got), len(want))
		}
		for i, id := range want {
			if got[i].ID != id {
				t.Fatalf("Pivot(%q, %q)[%d] = %q, want %q", kind, source, i, got[i].ID, id)
			}
		}
	}

	assertPivot(PivotDomainToIPs, "domain:api.example.com", "ip:192.0.2.10")
	assertPivot(PivotIPToDomains, "ip:192.0.2.10", "domain:api.example.com", "domain:www.example.com")
	assertPivot(PivotIPToServices, "ip:192.0.2.10", "service:192.0.2.10:443:https")
	assertPivot(PivotServiceToHosts, "service:192.0.2.10:443:https", "ip:192.0.2.10")
	assertPivot(PivotHostToCertificates, "domain:api.example.com", certificateID)
	assertPivot(PivotCertificateToHosts, certificateID, "domain:api.example.com")
}

func TestRelatedReturnsDeterministicNeighbors(t *testing.T) {
	graph := Graph{
		Nodes: []Node{
			{ID: "domain:a.example.com", Type: NodeDomain, Value: "a.example.com"},
			{ID: "ip:192.0.2.10", Type: NodeIP, Value: "192.0.2.10"},
		},
		Edges: []Edge{
			{ID: "resolves-to:a.example.com:192.0.2.10", Type: EdgeResolvesTo, Source: "domain:a.example.com", Target: "ip:192.0.2.10", EvidenceIDs: []string{"dns-1"}},
		},
	}

	got, err := Related(graph, "ip:192.0.2.10")
	if err != nil {
		t.Fatalf("Related() returned error: %v", err)
	}
	if len(got) != 1 || got[0].ID != "domain:a.example.com" {
		t.Fatalf("unexpected related nodes: %+v", got)
	}
}

func TestPivotRejectsUnknownSourceAndUnsupportedKind(t *testing.T) {
	graph := Graph{
		Nodes: []Node{{ID: "domain:example.com", Type: NodeDomain, Value: "example.com"}},
	}

	if _, err := Pivot(graph, "domain:missing.example.com", PivotDomainToIPs); err == nil {
		t.Fatal("expected missing pivot source to be rejected")
	}
	if _, err := Pivot(graph, "domain:example.com", PivotKind("UNKNOWN")); err == nil {
		t.Fatal("expected unsupported pivot kind to be rejected")
	}
}
