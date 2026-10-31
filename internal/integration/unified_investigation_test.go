package integration

import (
	"context"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/itsFuRy007/kem3t/internal/evidence"
	"github.com/itsFuRy007/kem3t/internal/graph"
	"github.com/itsFuRy007/kem3t/internal/investigation"
)

// TestUnifiedInvestigationEngineCombinesTCPHTTPAndTLS runs the three active
// collectors as stages in one Engine run, sharing one registry and provenance ID.
func TestUnifiedInvestigationEngineCombinesTCPHTTPAndTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Server", "KEM3T-unified-fixture")
		_, _ = w.Write([]byte("<!doctype html><html><head><title>Unified fixture</title></head><body>loopback only</body></html>"))
	}))
	defer server.Close()

	certificatePEM := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: server.Certificate().Raw,
	})
	certificatePath := filepath.Join(t.TempDir(), "unified-loopback-root.pem")
	if err := os.WriteFile(certificatePath, certificatePEM, 0600); err != nil {
		t.Fatalf("write loopback trust certificate: %v", err)
	}
	t.Setenv("SSL_CERT_FILE", certificatePath)

	port := server.Listener.Addr().(*net.TCPAddr).Port
	target := "127.0.0.1"
	registry, err := evidence.OpenRegistry(filepath.Join(t.TempDir(), "evidence.db"))
	if err != nil {
		t.Fatalf("open evidence registry: %v", err)
	}
	defer registry.Close()

	engine := investigation.Engine{
		Registry: registry,
		Stages: []investigation.Stage{
			investigation.NewTCPStage(target, port, port),
			investigation.NewTLSStage(target, port),
			investigation.NewHTTPStage(target, "https", port),
		},
		SnapshotDir: t.TempDir(),
	}
	result, err := engine.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("unified investigation: %v", err)
	}
	if result.Partial {
		t.Fatalf("unified investigation unexpectedly partial: %#v", result.Stages)
	}
	if len(result.Stages) != 3 {
		t.Fatalf("stage count = %d, want 3", len(result.Stages))
	}
	for _, stage := range result.Stages {
		if stage.Error != "" {
			t.Errorf("stage %q failed: %s", stage.Name, stage.Error)
		}
		if stage.Result.Evidence == 0 || stage.Result.Observations == 0 {
			t.Errorf("stage %q did not persist evidence and observations: %+v", stage.Name, stage.Result)
		}
	}

	edgeTypes := make(map[graph.EdgeType]bool)
	for _, edge := range result.Graph.Edges {
		edgeTypes[edge.Type] = true
	}
	for _, edgeType := range []graph.EdgeType{
		graph.EdgeHasOpenPort, graph.EdgePresentsCertificate, graph.EdgeServesHTTP,
	} {
		if !edgeTypes[edgeType] {
			t.Errorf("unified graph is missing %s relationship: %#v", edgeType, result.Graph.Edges)
		}
	}

	if result.Report.ReferenceRunID != result.RunID {
		t.Fatalf("report reference run = %q, want Engine run %q", result.Report.ReferenceRunID, result.RunID)
	}
	if len(result.Report.ServiceSurfaces) != 1 {
		t.Fatalf("service surface count = %d, want 1: %#v", len(result.Report.ServiceSurfaces), result.Report.ServiceSurfaces)
	}
	surface := result.Report.ServiceSurfaces[0]
	if surface.Target != target || surface.Port != port {
		t.Fatalf("unexpected service surface endpoint: %s:%d", surface.Target, surface.Port)
	}
	if surface.TemporalScope != "REFERENCE_RUN_ONLY" {
		t.Fatalf("surface temporal scope = %q, want REFERENCE_RUN_ONLY", surface.TemporalScope)
	}
	for _, protocol := range []string{"TCP", "HTTP", "TLS"} {
		if !containsIntegrationString(surface.Protocols, protocol) {
			t.Errorf("surface protocols %v do not include %s", surface.Protocols, protocol)
		}
	}
	if len(surface.ObservationRefs) != 3 {
		t.Fatalf("observation reference count = %d, want 3: %#v", len(surface.ObservationRefs), surface.ObservationRefs)
	}
	for _, ref := range surface.ObservationRefs {
		if ref.CollectionRunID != result.RunID || !ref.ReferenceRun {
			t.Errorf("observation does not share the unified run provenance: %+v", ref)
		}
	}
	if len(surface.HTTP) != 1 || surface.HTTP[0].StatusCode != http.StatusOK || !surface.HTTP[0].TLSVerified {
		t.Fatalf("unexpected HTTP/TLS service observation: %#v", surface.HTTP)
	}
	if len(surface.TLS) != 1 || !surface.TLS[0].Verified {
		t.Fatalf("TLS certificate was not trusted using the test-only trust root: %#v", surface.TLS)
	}
}
