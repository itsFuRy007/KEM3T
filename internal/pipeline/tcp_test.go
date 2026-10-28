package pipeline

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"testing"

	"github.com/itsFuRy007/kem3t/internal/evidence"
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
}
