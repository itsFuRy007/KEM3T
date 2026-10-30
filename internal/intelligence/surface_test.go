package intelligence

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/itsFuRy007/kem3t/internal/evidence"
)

func TestBuildServiceSurfacesJoinsOnlyMatchingTargetAndPort(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	fingerprint := strings.Repeat("a", 64)
	records := []evidence.Evidence{
		{
			ID: "tcp-open", EntityID: "lab.example", Type: evidence.TypeTCPPort,
			Value: `{"target":"lab.example","protocol":"tcp","port":443,"state":"open"}`,
		},
		{
			ID: "https-response", EntityID: "lab.example", Type: evidence.TypeHTTPService,
			Value: `{"target":"lab.example","scheme":"https","port":443,"url":"https://lab.example:443/","final_url":"https://lab.example:443/","status_code":200,"content_type":"text/html","server":"fixture","title":"Lab","redirect_count":0,"tls_version":"TLS 1.3","tls_verified":false}`,
		},
		{
			ID: "tls-cert", EntityID: "lab.example", Type: evidence.TypeTLSCertificate,
			Value: fmt.Sprintf(`{"target":"lab.example","port":443,"subject":"CN=lab.example","issuer":"CN=KEM3T Test","not_before":%q,"not_after":%q,"sha256_fingerprint":%q,"tls_version":"TLS 1.3","verified":false}`,
				now.Add(-time.Hour).Format(time.RFC3339), now.Add(24*time.Hour).Format(time.RFC3339), fingerprint),
		},
		{
			ID: "http-other-port", EntityID: "lab.example", Type: evidence.TypeHTTPService,
			Value: `{"target":"lab.example","scheme":"http","port":8080,"url":"http://lab.example:8080/","final_url":"http://lab.example:8080/","status_code":200,"content_type":"text/plain","title":"Other","redirect_count":0,"tls_verified":false}`,
		},
		{
			ID: "unrelated-host", EntityID: "other.example", Type: evidence.TypeTCPPort,
			Value: `{"target":"other.example","protocol":"tcp","port":443,"state":"open"}`,
		},
	}
	observations := make([]evidence.Observation, 0, len(records))
	for _, item := range records {
		observations = append(observations, evidence.Observation{
			ID: "obs-" + item.ID, EvidenceID: item.ID, Source: "controlled-lab",
			ObservedAt: now, EventIDs: []string{"event-" + item.ID},
		})
	}

	surfaces, err := BuildServiceSurfaces("lab.example", records, observations)
	if err != nil {
		t.Fatalf("BuildServiceSurfaces() error = %v", err)
	}
	if len(surfaces) != 2 {
		t.Fatalf("surfaces = %d, want 2 (443 and 8080): %+v", len(surfaces), surfaces)
	}
	var httpsSurface, httpSurface *ServiceSurface
	for i := range surfaces {
		switch surfaces[i].Port {
		case 443:
			httpsSurface = &surfaces[i]
		case 8080:
			httpSurface = &surfaces[i]
		}
	}
	if httpsSurface == nil || httpSurface == nil {
		t.Fatalf("expected separate 443 and 8080 surfaces: %+v", surfaces)
	}
	if len(httpsSurface.HTTP) != 1 || len(httpsSurface.TLS) != 1 || !containsString(httpsSurface.TCPStates, "OPEN") {
		t.Fatalf("443 surface did not join TCP/HTTPS/TLS evidence: %+v", httpsSurface)
	}
	if len(httpsSurface.EvidenceIDs) != 3 || len(httpsSurface.ObservationIDs) != 3 {
		t.Fatalf("443 surface lost evidence provenance: %+v", httpsSurface)
	}
	if len(httpSurface.HTTP) != 1 || len(httpSurface.TLS) != 0 || len(httpSurface.TCPStates) != 0 {
		t.Fatalf("8080 surface incorrectly inherited evidence from port 443: %+v", httpSurface)
	}

	hypotheses, err := GenerateServiceHypotheses(surfaces)
	if err != nil {
		t.Fatalf("GenerateServiceHypotheses() error = %v", err)
	}
	if len(hypotheses) != 1 {
		t.Fatalf("hypotheses = %d, want one HTTPS/TLS hypothesis: %+v", len(hypotheses), hypotheses)
	}
	if hypotheses[0].Confidence != HypothesisConfidenceLow {
		t.Fatalf("service hypothesis confidence = %q, want conservative LOW", hypotheses[0].Confidence)
	}
	if len(hypotheses[0].SupportingIDs) != 3 {
		t.Fatalf("hypothesis evidence refs = %v, want all three endpoint evidence records", hypotheses[0].SupportingIDs)
	}
	if !strings.Contains(hypotheses[0].Limitations, "backend") {
		t.Fatalf("hypothesis does not disclose backend limitation: %q", hypotheses[0].Limitations)
	}
}

func TestBuildServiceSurfacesPreservesMultipleTCPStates(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	records := []evidence.Evidence{
		{ID: "open", EntityID: "lab.example", Type: evidence.TypeTCPPort, Value: `{"target":"lab.example","protocol":"tcp","port":8443,"state":"open"}`},
		{ID: "closed", EntityID: "lab.example", Type: evidence.TypeTCPPortObservation, Value: `{"target":"lab.example","protocol":"tcp","port":8443,"state":"closed","reason":"connection refused"}`},
	}
	observations := []evidence.Observation{
		{ID: "obs-open", EvidenceID: "open", Source: "first-run", ObservedAt: now, EventIDs: []string{"evt-open"}},
		{ID: "obs-closed", EvidenceID: "closed", Source: "second-run", ObservedAt: now.Add(time.Hour), EventIDs: []string{"evt-closed"}},
	}
	surfaces, err := BuildServiceSurfaces("lab.example", records, observations)
	if err != nil {
		t.Fatalf("BuildServiceSurfaces() error = %v", err)
	}
	if len(surfaces) != 1 {
		t.Fatalf("surfaces = %d, want 1", len(surfaces))
	}
	if len(surfaces[0].TCPStates) != 2 || !containsString(surfaces[0].TCPStates, "OPEN") || !containsString(surfaces[0].TCPStates, "CLOSED") {
		t.Fatalf("multiple states were collapsed or lost: %+v", surfaces[0].TCPStates)
	}
	if !strings.Contains(strings.Join(surfaces[0].Limitations, " "), "timestamps") {
		t.Fatalf("state-change timing limitation missing: %+v", surfaces[0].Limitations)
	}
}

func TestGenerateServiceHypothesesDoesNotInferFromPlainHTTP(t *testing.T) {
	surface := ServiceSurface{
		ID: "service-surface:lab.example:80", Target: "lab.example", Port: 80,
		HTTP:        []ServiceHTTPObservation{{EvidenceID: "http", Scheme: "http", StatusCode: 200}},
		EvidenceIDs: []string{"http"}, Protocols: []string{"HTTP"}, Summary: "lab.example:80 | HTTP 200",
		Limitations: []string{"Endpoint-level only."},
	}
	hypotheses, err := GenerateServiceHypotheses([]ServiceSurface{surface})
	if err != nil {
		t.Fatalf("GenerateServiceHypotheses() error = %v", err)
	}
	if len(hypotheses) != 0 {
		t.Fatalf("plain HTTP without TLS evidence produced a TLS hypothesis: %+v", hypotheses)
	}
}

func TestReportEngineIncludesCrossLayerServiceSurfaceAndHypothesis(t *testing.T) {
	registry := evidence.NewRegistry()
	fingerprint := strings.Repeat("b", 64)
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	records := []evidence.Evidence{
		{ID: "tcp-open-report", EntityID: "lab.example", Type: evidence.TypeTCPPort, Value: `{"target":"lab.example","protocol":"tcp","port":443,"state":"open"}`},
		{ID: "https-report", EntityID: "lab.example", Type: evidence.TypeHTTPService, Value: `{"target":"lab.example","scheme":"https","port":443,"url":"https://lab.example/","final_url":"https://lab.example/","status_code":200,"title":"Lab","redirect_count":0,"tls_verified":false}`},
		{ID: "tls-report", EntityID: "lab.example", Type: evidence.TypeTLSCertificate, Value: fmt.Sprintf(`{"target":"lab.example","port":443,"subject":"CN=lab.example","issuer":"CN=Test","not_before":%q,"not_after":%q,"sha256_fingerprint":%q,"tls_version":"TLS 1.3","verified":false}`, now.Add(-time.Hour).Format(time.RFC3339), now.Add(time.Hour).Format(time.RFC3339), fingerprint)},
	}
	for _, item := range records {
		if err := registry.AddEvidence(item); err != nil {
			t.Fatalf("AddEvidence(%s): %v", item.ID, err)
		}
		if err := registry.AddObservation(evidence.Observation{
			ID: "obs-" + item.ID, EvidenceID: item.ID, Source: "controlled-lab",
			ObservedAt: now, EventIDs: []string{"event-" + item.ID},
		}); err != nil {
			t.Fatalf("AddObservation(%s): %v", item.ID, err)
		}
	}

	report, err := (&ReportEngine{}).Build("lab.example", nil, registry)
	if err != nil {
		t.Fatalf("ReportEngine.Build() error = %v", err)
	}
	if len(report.ServiceSurfaces) != 1 {
		t.Fatalf("service surfaces = %d, want 1: %+v", len(report.ServiceSurfaces), report.ServiceSurfaces)
	}
	if len(report.Hypotheses) != 1 || report.Hypotheses[0].Confidence != HypothesisConfidenceLow {
		t.Fatalf("cross-layer hypothesis missing or overconfident: %+v", report.Hypotheses)
	}
	foundSurfaceSignal := false
	for _, signal := range report.Narrative.Signals {
		if signal.Kind == "SERVICE_SURFACE" && strings.Contains(signal.Summary, "HTTPS 200") {
			foundSurfaceSignal = true
			if len(signal.References) < 4 {
				t.Fatalf("service-surface narrative lost provenance: %+v", signal)
			}
		}
	}
	if !foundSurfaceSignal {
		t.Fatalf("research narrative omitted service surface: %+v", report.Narrative.Signals)
	}
	if len(report.InvestigationPlan.Items) == 0 {
		t.Fatal("investigation plan did not receive service-surface verification steps")
	}
}
