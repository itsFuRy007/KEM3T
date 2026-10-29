package graph

import (
	"testing"
	"time"

	"github.com/itsFuRy007/kem3t/internal/observations"
)

func TestAttachServicesAddsEvidenceBackedServiceRelationship(t *testing.T) {
	base := Graph{Nodes: []Node{
		{ID: "domain:example.com", Type: NodeDomain, Value: "example.com"},
	}}
	service := observations.Service{
		ID: "service:example.com:443:https", Target: "example.com", Port: 443,
		Transport: "tcp", Application: "https", State: "observed",
		EvidenceIDs: []string{"evidence-1"}, Sources: []string{"http"},
		ObservedAt: time.Date(2026, 10, 29, 10, 0, 0, 0, time.UTC),
	}
	got, err := AttachServices(base, []observations.Service{service})
	if err != nil {
		t.Fatalf("AttachServices() error = %v", err)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("resulting graph is invalid: %v", err)
	}
	if len(got.Nodes) != 2 || len(got.Edges) != 1 {
		t.Fatalf("expected host and service nodes plus one edge, got %d nodes and %d edges", len(got.Nodes), len(got.Edges))
	}
	edge := got.Edges[0]
	if edge.ID != "hosts-service:example.com:443:https" || edge.EvidenceIDs[0] != "evidence-1" {
		t.Fatalf("unexpected evidence-backed service edge: %#v", edge)
	}
}

func TestAttachServicesSkipsServicesWithoutEvidence(t *testing.T) {
	base := Graph{Nodes: []Node{{ID: "domain:example.com", Type: NodeDomain, Value: "example.com"}}}
	service := observations.Service{Target: "example.com", Port: 443, Application: "https"}
	got, err := AttachServices(base, []observations.Service{service})
	if err != nil {
		t.Fatalf("AttachServices() error = %v", err)
	}
	if len(got.Nodes) != 1 || len(got.Edges) != 0 {
		t.Fatalf("service without evidence should not add graph records: %#v", got)
	}
}
