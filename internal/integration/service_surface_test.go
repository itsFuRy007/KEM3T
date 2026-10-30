package integration

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/itsFuRy007/kem3t/internal/evidence"
	"github.com/itsFuRy007/kem3t/internal/intelligence"
	"github.com/itsFuRy007/kem3t/internal/pipeline"
)

// TestCrossLayerServiceSurfaceEndToEndLocalhost runs the real TCP, HTTPS, and
// TLS pipelines against one local endpoint, then rebuilds the report from the
// shared persistent evidence registry.
func TestCrossLayerServiceSurfaceEndToEndLocalhost(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Server", "KEM3T-controlled-fixture")
		_, _ = w.Write([]byte("<!doctype html><html><head><title>Cross-layer fixture</title></head><body>local only</body></html>"))
	}))
	defer server.Close()

	// Trust only this test server's self-signed certificate for the HTTPS
	// collector. The trust file lives in the test's temporary directory.
	certificatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: server.Certificate().Raw,
	})
	certificatePath := filepath.Join(t.TempDir(), "loopback-root.pem")
	if err := os.WriteFile(certificatePath, certificatePEM, 0600); err != nil {
		t.Fatalf("write loopback trust certificate: %v", err)
	}
	t.Setenv("SSL_CERT_FILE", certificatePath)

	port := server.Listener.Addr().(*net.TCPAddr).Port
	target := "127.0.0.1"
	snapshotDir := t.TempDir()
	ctx := context.Background()

	tcpResult, err := pipeline.RunTCP(ctx, target, port, port, snapshotDir)
	if err != nil {
		t.Fatalf("RunTCP: %v", err)
	}
	if len(tcpResult.Evidence) != 1 {
		t.Fatalf("TCP evidence count = %d, want 1", len(tcpResult.Evidence))
	}

	httpResult, err := pipeline.RunHTTP(ctx, target, "https", port, snapshotDir)
	if err != nil {
		t.Fatalf("RunHTTP against the same HTTPS endpoint: %v", err)
	}
	if httpResult.Event == nil || httpResult.Evidence.Type != evidence.TypeHTTPService {
		t.Fatal("HTTPS pipeline did not produce HTTP service evidence")
	}

	tlsResult, err := pipeline.RunTLS(ctx, target, port, snapshotDir)
	if err != nil {
		t.Fatalf("RunTLS against the same endpoint: %v", err)
	}
	if tlsResult.Event == nil || tlsResult.Evidence.Type != evidence.TypeTLSCertificate {
		t.Fatal("TLS pipeline did not produce certificate evidence")
	}

	registry, err := evidence.OpenRegistry(filepath.Join(snapshotDir, "evidence.db"))
	if err != nil {
		t.Fatalf("reopen shared evidence registry: %v", err)
	}
	defer registry.Close()

	report, err := (&intelligence.ReportEngine{}).Build(target, tcpResult.Findings, registry)
	if err != nil {
		t.Fatalf("build cross-layer intelligence report: %v", err)
	}
	if len(report.ServiceSurfaces) != 1 {
		t.Fatalf("service surface count = %d, want 1: %#v", len(report.ServiceSurfaces), report.ServiceSurfaces)
	}

	surface := report.ServiceSurfaces[0]
	if surface.Target != target || surface.Port != port {
		t.Fatalf("surface endpoint = %s:%d, want %s:%d", surface.Target, surface.Port, target, port)
	}
	for _, protocol := range []string{"TCP", "HTTP", "TLS"} {
		if !containsIntegrationString(surface.Protocols, protocol) {
			t.Errorf("surface protocols %v do not include %s", surface.Protocols, protocol)
		}
	}
	if len(surface.HTTP) != 1 || surface.HTTP[0].StatusCode != http.StatusOK {
		t.Fatalf("unexpected HTTP observations: %#v", surface.HTTP)
	}
	if len(surface.TLS) != 1 {
		t.Fatalf("TLS observation count = %d, want 1", len(surface.TLS))
	}

	expectedEvidence := []string{
		tcpResult.Evidence[0].ID,
		httpResult.Evidence.ID,
		tlsResult.Evidence.ID,
	}
	for _, evidenceID := range expectedEvidence {
		if !containsIntegrationString(surface.EvidenceIDs, evidenceID) {
			t.Errorf("service surface is missing evidence reference %q: %v", evidenceID, surface.EvidenceIDs)
		}
	}
	if len(surface.ObservationRefs) != 3 {
		t.Fatalf("observation provenance count = %d, want 3: %#v", len(surface.ObservationRefs), surface.ObservationRefs)
	}
	for _, evidenceID := range expectedEvidence {
		found := false
		for _, ref := range surface.ObservationRefs {
			if ref.EvidenceID == evidenceID && strings.TrimSpace(ref.ObservationID) != "" &&
				strings.TrimSpace(ref.Source) != "" && !ref.ObservedAt.IsZero() {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing timestamped source observation reference for evidence %q", evidenceID)
		}
	}

	var serviceHypothesis *intelligence.Hypothesis
	for i := range report.Hypotheses {
		if strings.HasPrefix(report.Hypotheses[i].ID, "hypothesis:service-https:") {
			serviceHypothesis = &report.Hypotheses[i]
			break
		}
	}
	if serviceHypothesis == nil {
		t.Fatal("report did not generate the expected HTTPS/TLS endpoint hypothesis")
	}
	if serviceHypothesis.Confidence != intelligence.HypothesisConfidenceLow {
		t.Errorf("service hypothesis confidence = %q, want LOW", serviceHypothesis.Confidence)
	}
	for _, evidenceID := range expectedEvidence {
		if !containsIntegrationString(serviceHypothesis.SupportingIDs, evidenceID) {
			t.Errorf("hypothesis is missing supporting evidence %q", evidenceID)
		}
	}
	if !strings.Contains(strings.ToLower(serviceHypothesis.Statement), "does not identify the backend application") {
		t.Errorf("hypothesis overstates backend attribution: %q", serviceHypothesis.Statement)
	}
	if !strings.Contains(strings.ToLower(serviceHypothesis.Alternative), "load balancer") {
		t.Errorf("hypothesis is missing a plausible alternative explanation: %q", serviceHypothesis.Alternative)
	}

	foundNarrativeSignal := false
	for _, signal := range report.Narrative.Signals {
		if signal.Kind == "SERVICE_SURFACE" && signal.ID == "service-surface:"+surface.ID {
			foundNarrativeSignal = true
			break
		}
	}
	if !foundNarrativeSignal {
		t.Fatal("research narrative is missing the cross-layer service-surface signal")
	}
}

func containsIntegrationString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
