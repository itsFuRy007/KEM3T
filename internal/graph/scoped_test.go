package graph

import (
	"testing"
	"time"

	"github.com/itsFuRy007/kem3t/internal/evidence"
)

func TestBuildForTargetExcludesUnrelatedWorkspaceEvidence(t *testing.T) {
	registry := evidence.NewRegistry()
	records := []evidence.Evidence{
		{ID: "biteyt-dns", EntityID: "biteyt.com", Type: evidence.TypeDNSAddress, Value: "192.0.2.10"},
		{ID: "subdomain-dns", EntityID: "api.biteyt.com", Type: evidence.TypeDNSAddress, Value: "192.0.2.11"},
		{ID: "other-dns", EntityID: "example.com", Type: evidence.TypeDNSAddress, Value: "192.0.2.20"},
		{ID: "loopback-dns", EntityID: "localhost.example", Type: evidence.TypeDNSAddress, Value: "127.0.0.1"},
	}
	for _, record := range records {
		if err := registry.AddEvidence(record); err != nil {
			t.Fatalf("AddEvidence(%s): %v", record.ID, err)
		}
	}
	observations := []evidence.Observation{
		{ID: "obs-biteyt", EvidenceID: "biteyt-dns", Source: "dns", ObservedAt: time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC), EventIDs: []string{"event-biteyt"}},
		{ID: "obs-subdomain", EvidenceID: "subdomain-dns", Source: "dns", ObservedAt: time.Date(2026, 10, 30, 0, 0, 1, 0, time.UTC), EventIDs: []string{"event-subdomain"}},
		{ID: "obs-other", EvidenceID: "other-dns", Source: "dns", ObservedAt: time.Date(2026, 10, 30, 0, 0, 2, 0, time.UTC), EventIDs: []string{"event-other"}},
	}
	for _, observation := range observations {
		if err := registry.AddObservation(observation); err != nil {
			t.Fatalf("AddObservation(%s): %v", observation.ID, err)
		}
	}

	got, err := BuildFromRegistryForTarget(registry, "BITEYT.COM.")
	if err != nil {
		t.Fatalf("BuildFromRegistryForTarget(): %v", err)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("scoped graph is invalid: %v", err)
	}
	if len(got.Edges) != 2 {
		t.Fatalf("edges = %d, want only target and subdomain DNS edges", len(got.Edges))
	}
	for _, node := range got.Nodes {
		if node.Value == "example.com" || node.Value == "localhost.example" || node.Value == "127.0.0.1" {
			t.Errorf("unrelated workspace node leaked into target graph: %+v", node)
		}
	}
	for _, edge := range got.Edges {
		for _, id := range edge.EvidenceIDs {
			if id == "other-dns" || id == "loopback-dns" {
				t.Errorf("unrelated evidence %q leaked into target graph", id)
			}
		}
		for _, id := range edge.ObservationIDs {
			if id == "obs-other" {
				t.Errorf("unrelated observation %q leaked into target graph", id)
			}
		}
	}
}

func TestBuildForTargetIncludesIPLevelEvidenceForResolvedAddresses(t *testing.T) {
	registry := evidence.NewRegistry()
	dns := evidence.Evidence{ID: "target-dns", EntityID: "biteyt.com", Type: evidence.TypeDNSAddress, Value: "192.0.2.10"}
	tcpDetails := []byte(`{"target":"192.0.2.10","protocol":"tcp","port":443,"state":"open"}`)
	tcp := evidence.Evidence{ID: "target-tcp", EntityID: "192.0.2.10", Type: evidence.TypeTCPPort, Value: string(tcpDetails)}
	for _, record := range []evidence.Evidence{dns, tcp} {
		if err := registry.AddEvidence(record); err != nil {
			t.Fatalf("AddEvidence(%s): %v", record.ID, err)
		}
	}
	got, err := BuildFromRegistryForTarget(registry, "biteyt.com")
	if err != nil {
		t.Fatalf("BuildFromRegistryForTarget(): %v", err)
	}
	if len(got.Edges) != 2 {
		t.Fatalf("edges = %d, want DNS and target-IP TCP edges", len(got.Edges))
	}
}
