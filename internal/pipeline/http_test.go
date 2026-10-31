package pipeline

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/itsFuRy007/kem3t/internal/evidence"
	"github.com/itsFuRy007/kem3t/internal/graph"
)

func TestRunHTTPPersistsEvidenceAndBuildsGraph(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<title>Pipeline test</title>"))
	}))
	defer server.Close()

	dir := t.TempDir()
	result, err := RunHTTP(context.Background(), server.URL, "auto", 0, dir)
	if err != nil {
		t.Fatalf("RunHTTP() error = %v", err)
	}
	if result.Event == nil {
		t.Fatal("expected HTTP event")
	}
	if result.Report.Target != "127.0.0.1" || result.Report.ReferenceRunID == "" {
		t.Fatalf("HTTP adapter did not return the shared intelligence report: %+v", result.Report)
	}
	if result.Evidence.Type != evidence.TypeHTTPService {
		t.Fatalf("evidence type = %q", result.Evidence.Type)
	}
	if result.Observation.EvidenceID != result.Evidence.ID {
		t.Fatal("observation does not reference evidence")
	}
	if err := result.Graph.Validate(); err != nil {
		t.Fatalf("graph validation: %v", err)
	}
	foundService, foundEdge := false, false
	for _, node := range result.Graph.Nodes {
		if node.Type == graph.NodeHTTPService && node.Value == fmt.Sprintf("http://127.0.0.1:%d", server.Listener.Addr().(*net.TCPAddr).Port) {
			foundService = true
		}
	}
	for _, edge := range result.Graph.Edges {
		if edge.Type == graph.EdgeServesHTTP && edge.EvidenceIDs[0] == result.Evidence.ID && len(edge.ObservationIDs) == 1 {
			foundEdge = true
		}
	}
	if !foundService {
		t.Fatal("graph missing HTTP service node")
	}
	if !foundEdge {
		t.Fatal("graph missing provenance-linked SERVES_HTTP edge")
	}

	registry, err := evidence.OpenRegistry(filepath.Join(dir, "evidence.db"))
	if err != nil {
		t.Fatalf("reopen registry: %v", err)
	}
	defer registry.Close()
	if got := len(registry.AllEvidence()); got != 1 {
		t.Fatalf("persisted evidence count = %d, want 1", got)
	}
	if got := len(registry.AllObservations()); got != 1 {
		t.Fatalf("persisted observation count = %d, want 1", got)
	}
}

func TestRunHTTPRejectsInvalidInput(t *testing.T) {
	if _, err := RunHTTP(context.Background(), "example.com", "invalid", 0, t.TempDir()); err == nil {
		t.Fatal("expected invalid scheme error")
	}
	if _, err := RunHTTP(nil, "example.com", "auto", 0, t.TempDir()); err == nil {
		t.Fatal("expected nil context error")
	}
}
