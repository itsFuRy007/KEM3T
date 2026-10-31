package pipeline

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/itsFuRy007/kem3t/internal/evidence"
	"github.com/itsFuRy007/kem3t/internal/graph"
	"github.com/itsFuRy007/kem3t/internal/history"
)

func TestRunTCPRejectsInvalidPortRange(t *testing.T) {
	_, err := RunTCP(context.Background(), "127.0.0.1", 9000, 1, t.TempDir())
	if err == nil {
		t.Fatal("expected invalid port range error")
	}
}

func TestRunTCPRejectsEmptyTarget(t *testing.T) {
	_, err := RunTCP(context.Background(), " ", 1, 10, t.TempDir())
	if err == nil {
		t.Fatal("expected empty target error")
	}
}

func TestRunTCPRejectsNilContext(t *testing.T) {
	_, err := RunTCP(nil, "127.0.0.1", 1, 10, t.TempDir())
	if err == nil {
		t.Fatal("expected nil context error")
	}
}

func TestRunTCPStoresEvidenceAndBuildsGraph(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port

	dir := t.TempDir()
	result, err := RunTCP(context.Background(), "127.0.0.1", port, port, dir)
	if err != nil {
		t.Fatalf("RunTCP() error: %v", err)
	}
	if len(result.Evidence) == 0 {
		t.Fatal("expected evidence for the open TCP port")
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 intelligence finding for the open TCP port, got %d", len(result.Findings))
	}
	if result.Findings[0].Title != "Open TCP port observed" {
		t.Fatalf("unexpected TCP finding title: %q", result.Findings[0].Title)
	}
	if result.Findings[0].Priority != "INFO" {
		t.Fatalf("unexpected TCP finding priority: %q", result.Findings[0].Priority)
	}
	if len(result.Report.Findings) != 1 {
		t.Fatalf("expected 1 finding in intelligence report, got %d", len(result.Report.Findings))
	}
	if len(result.Report.PrioritizedFindings) != 1 {
		t.Fatalf("expected 1 prioritized finding in intelligence report, got %d", len(result.Report.PrioritizedFindings))
	}
	if len(result.Graph.Nodes) < 2 {
		t.Fatalf("expected target and TCP-port nodes, got %d", len(result.Graph.Nodes))
	}
	if len(result.Graph.Edges) == 0 {
		t.Fatal("expected an edge connecting the target to its open port")
	}
	foundPort, foundEdge := false, false
	for _, node := range result.Graph.Nodes {
		if node.Type == "TCP_PORT" && node.Value == fmt.Sprintf("127.0.0.1:%d", port) {
			foundPort = true
		}
	}
	for _, edge := range result.Graph.Edges {
		if edge.Type == "HAS_OPEN_PORT" && edge.Port == port {
			foundEdge = true
		}
	}
	if !foundPort {
		t.Fatalf("graph missing TCP port node for port %d", port)
	}
	if !foundEdge {
		t.Fatalf("graph missing HAS_OPEN_PORT edge for port %d", port)
	}
	if err := result.Graph.Validate(); err != nil {
		t.Fatalf("graph validation failed: %v", err)
	}

	registry, err := evidence.OpenRegistry(filepath.Join(dir, "evidence.db"))
	if err != nil {
		t.Fatalf("reopen evidence registry: %v", err)
	}
	defer registry.Close()

	if got := len(registry.AllEvidence()); got == 0 {
		t.Fatal("evidence was not persisted")
	}

	historyStore, err := history.NewStore(filepath.Join(dir, "history"))
	if err != nil {
		t.Fatalf("open generalized history store: %v", err)
	}
	snapshots, err := historyStore.List()
	if err != nil {
		t.Fatalf("load generalized history snapshots: %v", err)
	}
	if len(snapshots) != 1 || snapshots[0].Collector != "investigation" || len(snapshots[0].Records) != 1 {
		t.Fatalf("successful TCP run did not persist an evidence-backed history snapshot: %+v", snapshots)
	}
}

func TestRunTCPPersistsClosedStateWithoutCreatingOpenPortRelationship(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	result, err := RunTCP(context.Background(), "127.0.0.1", port, port, dir)
	if err != nil {
		t.Fatalf("RunTCP() error = %v", err)
	}
	if len(result.Events) != 1 || result.Events[0].Data["state"] != "closed" {
		t.Fatalf("events = %+v, want one closed event", result.Events)
	}
	if len(result.Evidence) != 1 || result.Evidence[0].Type != evidence.TypeTCPPortObservation {
		t.Fatalf("evidence = %+v, want one durable TCP state observation", result.Evidence)
	}
	if len(result.Observations) != 1 {
		t.Fatalf("observations = %d, want 1", len(result.Observations))
	}
	if len(result.Graph.Edges) != 1 || result.Graph.Edges[0].Type != graph.EdgeObservedTCPPortState ||
		result.Graph.Edges[0].State != "closed" {
		t.Fatalf("closed port should create only an evidence-backed closed-state relationship, got: %+v", result.Graph.Edges)
	}
	for _, edge := range result.Graph.Edges {
		if edge.Type == graph.EdgeHasOpenPort {
			t.Fatalf("closed port was incorrectly represented as open: %+v", edge)
		}
	}
	if len(result.Normalized.Services) != 1 || result.Normalized.Services[0].State != "closed" {
		t.Fatalf("normalized services = %+v, want closed state", result.Normalized.Services)
	}
	if len(result.Findings) != 1 || !strings.Contains(result.Findings[0].Title, "Closed") {
		t.Fatalf("findings = %+v, want closed-state intelligence", result.Findings)
	}

	registry, err := evidence.OpenRegistry(filepath.Join(dir, "evidence.db"))
	if err != nil {
		t.Fatalf("reopen evidence registry: %v", err)
	}
	defer registry.Close()
	if len(registry.AllEvidence()) != 1 || len(registry.AllObservations()) != 1 {
		t.Fatalf("durable registry did not retain closed state: evidence=%d observations=%d", len(registry.AllEvidence()), len(registry.AllObservations()))
	}
	historyStore, err := history.NewStore(filepath.Join(dir, "history"))
	if err != nil {
		t.Fatalf("open TCP history: %v", err)
	}
	snapshots, err := historyStore.List()
	if err != nil {
		t.Fatalf("read TCP history: %v", err)
	}
	if len(snapshots) != 1 || len(snapshots[0].Records) != 1 {
		t.Fatalf("closed state missing from history snapshot: %+v", snapshots)
	}
}
