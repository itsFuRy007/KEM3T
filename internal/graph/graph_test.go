package graph

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/itsFuRy007/kem3t/internal/evidence"
	"github.com/itsFuRy007/kem3t/internal/observations"
)

func TestBuildCreatesDNSGraph(t *testing.T) {
	records := []evidence.Evidence{
		{
			ID:       "evidence-1",
			EntityID: "example.com",
			Type:     evidence.TypeDNSAddress,
			Value:    "192.0.2.10",
		},
		{
			ID:       "evidence-2",
			EntityID: "api.example.com",
			Type:     evidence.TypeDNSAddress,
			Value:    "192.0.2.10",
		},
	}

	observations := []evidence.Observation{
		{
			ID:         "observation-1",
			EvidenceID: "evidence-1",
			Source:     "dns",
			ObservedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			EventIDs:   []string{"event-1"},
		},
	}

	got, err := Build(records, observations)
	if err != nil {
		t.Fatalf("Build() returned error: %v", err)
	}

	if len(got.Nodes) != 3 {
		t.Fatalf("expected 3 nodes, got %d", len(got.Nodes))
	}

	if len(got.Edges) != 2 {
		t.Fatalf("expected 2 edges, got %d", len(got.Edges))
	}

	if err := got.Validate(); err != nil {
		t.Fatalf("generated graph is invalid: %v", err)
	}

	foundObservation := false
	for _, edge := range got.Edges {
		if edge.ID == "resolves-to:example.com:192.0.2.10" {
			if len(edge.EvidenceIDs) != 1 || edge.EvidenceIDs[0] != "evidence-1" {
				t.Fatalf("unexpected evidence references: %v", edge.EvidenceIDs)
			}
			if len(edge.ObservationIDs) != 1 || edge.ObservationIDs[0] != "observation-1" {
				t.Fatalf("unexpected observation references: %v", edge.ObservationIDs)
			}
			foundObservation = true
		}
	}

	if !foundObservation {
		t.Fatal("expected edge for example.com was not found")
	}
}

func TestBuildRejectsObservationWithMissingEvidence(t *testing.T) {
	observation := evidence.Observation{
		ID:         "observation-1",
		EvidenceID: "missing-evidence",
		Source:     "dns",
		ObservedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		EventIDs:   []string{"event-1"},
	}

	if _, err := Build(nil, []evidence.Observation{observation}); err == nil {
		t.Fatal("expected observation referencing missing evidence to be rejected")
	}
}

func TestBuildAllowsEvidenceWithoutObservations(t *testing.T) {
	record := evidence.Evidence{
		ID:       "evidence-1",
		EntityID: "example.com",
		Type:     evidence.TypeDNSAddress,
		Value:    "192.0.2.10",
	}

	got, err := Build([]evidence.Evidence{record}, nil)
	if err != nil {
		t.Fatalf("Build() returned error: %v", err)
	}
	if len(got.Edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(got.Edges))
	}
	if len(got.Edges[0].ObservationIDs) != 0 {
		t.Fatalf("expected no observation references, got %v", got.Edges[0].ObservationIDs)
	}
}
func TestBuildRejectsInvalidEvidence(t *testing.T) {
	records := []evidence.Evidence{
		{
			ID:       "invalid",
			EntityID: "example.com",
			Type:     evidence.TypeDNSAddress,
			Value:    "not-an-ip",
		},
	}

	if _, err := Build(records, nil); err == nil {
		t.Fatal("expected invalid evidence to be rejected")
	}
}

func TestBuildRejectsDuplicateEvidenceIDs(t *testing.T) {
	record := evidence.Evidence{
		ID:       "duplicate",
		EntityID: "example.com",
		Type:     evidence.TypeDNSAddress,
		Value:    "192.0.2.10",
	}

	if _, err := Build([]evidence.Evidence{record, record}, nil); err == nil {
		t.Fatal("expected duplicate evidence IDs to be rejected")
	}
}

func TestBuildRejectsDuplicateObservationIDs(t *testing.T) {
	observation := evidence.Observation{
		ID:         "duplicate",
		EvidenceID: "evidence-1",
		Source:     "dns",
		ObservedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		EventIDs:   []string{"event-1"},
	}

	if _, err := Build(nil, []evidence.Observation{observation, observation}); err == nil {
		t.Fatal("expected duplicate observation IDs to be rejected")
	}
}

func TestBuildFromRegistryRejectsNilRegistry(t *testing.T) {
	if _, err := BuildFromRegistry(nil); err == nil {
		t.Fatal("expected nil registry to be rejected")
	}
}

func TestBuildIsDeterministicAcrossInputOrder(t *testing.T) {
	records := []evidence.Evidence{
		{ID: "evidence-b", EntityID: "example.com", Type: evidence.TypeDNSAddress, Value: "192.0.2.10"},
		{ID: "evidence-a", EntityID: "EXAMPLE.COM", Type: evidence.TypeDNSAddress, Value: "192.0.2.10"},
	}
	observations := []evidence.Observation{
		{ID: "observation-b", EvidenceID: "evidence-b", Source: "dns", ObservedAt: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC), EventIDs: []string{"event-b"}},
		{ID: "observation-a", EvidenceID: "evidence-a", Source: "dns", ObservedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), EventIDs: []string{"event-a"}},
	}

	first, err := Build(records, observations)
	if err != nil {
		t.Fatalf("Build() first call returned error: %v", err)
	}

	reversedRecords := []evidence.Evidence{records[1], records[0]}
	reversedObservations := []evidence.Observation{observations[1], observations[0]}
	second, err := Build(reversedRecords, reversedObservations)
	if err != nil {
		t.Fatalf("Build() second call returned error: %v", err)
	}

	if len(first.Nodes) != len(second.Nodes) || len(first.Edges) != len(second.Edges) {
		t.Fatal("graph output sizes differ when input order changes")
	}
	for i := range first.Nodes {
		if first.Nodes[i] != second.Nodes[i] {
			t.Fatalf("node order differs at index %d", i)
		}
	}
	for i := range first.Edges {
		a, b := first.Edges[i], second.Edges[i]
		if a.ID != b.ID || a.Type != b.Type || a.Source != b.Source || a.Target != b.Target {
			t.Fatalf("edge differs at index %d", i)
		}
		if len(a.EvidenceIDs) != len(b.EvidenceIDs) || len(a.ObservationIDs) != len(b.ObservationIDs) {
			t.Fatalf("edge references differ at index %d", i)
		}
		for j := range a.EvidenceIDs {
			if a.EvidenceIDs[j] != b.EvidenceIDs[j] {
				t.Fatalf("evidence references differ at edge %d", i)
			}
		}
		for j := range a.ObservationIDs {
			if a.ObservationIDs[j] != b.ObservationIDs[j] {
				t.Fatalf("observation references differ at edge %d", i)
			}
		}
	}
}

func TestBuildAggregatesEvidenceAndObservations(t *testing.T) {
	records := []evidence.Evidence{
		{ID: "evidence-a", EntityID: "example.com", Type: evidence.TypeDNSAddress, Value: "192.0.2.10"},
		{ID: "evidence-b", EntityID: "EXAMPLE.COM", Type: evidence.TypeDNSAddress, Value: "192.0.2.10"},
	}
	observations := []evidence.Observation{
		{ID: "observation-a", EvidenceID: "evidence-a", Source: "dns", ObservedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), EventIDs: []string{"event-a"}},
		{ID: "observation-b", EvidenceID: "evidence-b", Source: "dns", ObservedAt: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC), EventIDs: []string{"event-b"}},
	}

	got, err := Build(records, observations)
	if err != nil {
		t.Fatalf("Build() returned error: %v", err)
	}
	if len(got.Edges) != 1 {
		t.Fatalf("expected 1 aggregated edge, got %d", len(got.Edges))
	}

	edge := got.Edges[0]
	if len(edge.EvidenceIDs) != 2 || edge.EvidenceIDs[0] != "evidence-a" || edge.EvidenceIDs[1] != "evidence-b" {
		t.Fatalf("unexpected evidence references: %v", edge.EvidenceIDs)
	}
	if len(edge.ObservationIDs) != 2 || edge.ObservationIDs[0] != "observation-a" || edge.ObservationIDs[1] != "observation-b" {
		t.Fatalf("unexpected observation references: %v", edge.ObservationIDs)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("generated graph is invalid: %v", err)
	}
}

func TestBuildIsDeterministic(t *testing.T) {
	records := []evidence.Evidence{
		{
			ID:       "evidence-b",
			EntityID: "b.example.com",
			Type:     evidence.TypeDNSAddress,
			Value:    "192.0.2.20",
		},
		{
			ID:       "evidence-a",
			EntityID: "a.example.com",
			Type:     evidence.TypeDNSAddress,
			Value:    "192.0.2.10",
		},
	}

	first, err := Build(records, nil)
	if err != nil {
		t.Fatalf("first Build() returned error: %v", err)
	}

	second, err := Build(records, nil)
	if err != nil {
		t.Fatalf("second Build() returned error: %v", err)
	}

	if len(first.Nodes) != len(second.Nodes) || len(first.Edges) != len(second.Edges) {
		t.Fatal("graph output sizes differ")
	}

	for i := range first.Nodes {
		if first.Nodes[i] != second.Nodes[i] {
			t.Fatalf("node order differs at index %d", i)
		}
	}

	for i := range first.Edges {
		a, b := first.Edges[i], second.Edges[i]
		if a.ID != b.ID || a.Source != b.Source || a.Target != b.Target {
			t.Fatalf("edge order differs at index %d", i)
		}
	}
}

func TestBuildRejectsEvidenceIDWithSurroundingWhitespace(t *testing.T) {
	records := []evidence.Evidence{
		{
			ID:       " evidence-1 ",
			EntityID: "example.com",
			Type:     evidence.TypeDNSAddress,
			Value:    "192.0.2.1",
		},
	}

	if _, err := Build(records, nil); err == nil {
		t.Fatal("expected error for evidence ID with surrounding whitespace")
	}
}

func TestBuildRejectsObservationIDWithSurroundingWhitespace(t *testing.T) {
	records := []evidence.Evidence{
		{
			ID:       "evidence-1",
			EntityID: "example.com",
			Type:     evidence.TypeDNSAddress,
			Value:    "192.0.2.1",
		},
	}
	observations := []evidence.Observation{
		{
			ID:         " observation-1 ",
			EvidenceID: "evidence-1",
			Source:     "test",
			ObservedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			EventIDs:   []string{"event-1"},
		},
	}

	if _, err := Build(records, observations); err == nil {
		t.Fatal("expected error for observation ID with surrounding whitespace")
	}
}

func TestBuildRejectsObservationEvidenceIDWithSurroundingWhitespace(t *testing.T) {
	records := []evidence.Evidence{
		{
			ID:       "evidence-1",
			EntityID: "example.com",
			Type:     evidence.TypeDNSAddress,
			Value:    "192.0.2.1",
		},
	}
	observations := []evidence.Observation{
		{
			ID:         "observation-1",
			EvidenceID: " evidence-1 ",
			Source:     "test",
			ObservedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			EventIDs:   []string{"event-1"},
		},
	}

	if _, err := Build(records, observations); err == nil {
		t.Fatal("expected error for observation evidence ID with surrounding whitespace")
	}
}

func TestBuildCreatesTLSCertificateGraph(t *testing.T) {
	fingerprint := strings.Repeat("a1", 32)
	details := evidence.TLSCertificateDetails{
		Target:             "example.com",
		Port:               443,
		Subject:            "CN=example.com",
		Issuer:             "CN=Test CA",
		SerialNumber:       "12345",
		DNSNames:           []string{"example.com"},
		NotBefore:          time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:           time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		SHA256Fingerprint:  fingerprint,
		SignatureAlgorithm: "ECDSA-SHA256",
		PublicKeyAlgorithm: "ECDSA",
		TLSVersion:         "TLS 1.3",
		Verified:           true,
	}

	value, err := json.Marshal(details)
	if err != nil {
		t.Fatalf("could not marshal TLS details: %v", err)
	}

	records := []evidence.Evidence{
		{
			ID:       "tls-evidence-1",
			EntityID: "example.com",
			Type:     evidence.TypeTLSCertificate,
			Value:    string(value),
		},
	}

	observations := []evidence.Observation{
		{
			ID:         "tls-observation-1",
			EvidenceID: "tls-evidence-1",
			Source:     "tls",
			ObservedAt: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
			EventIDs:   []string{"tls-event-1"},
		},
	}

	got, err := Build(records, observations)
	if err != nil {
		t.Fatalf("Build() returned error: %v", err)
	}

	if err := got.Validate(); err != nil {
		t.Fatalf("generated graph is invalid: %v", err)
	}

	if len(got.Nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(got.Nodes))
	}
	if len(got.Edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(got.Edges))
	}

	var foundDomain, foundCertificate bool
	for _, node := range got.Nodes {
		switch node.Type {
		case NodeDomain:
			foundDomain = node.ID == "domain:example.com"
		case NodeTLSCertificate:
			foundCertificate = node.ID == "tls-cert:"+fingerprint &&
				node.Value == fingerprint
		}
	}
	if !foundDomain || !foundCertificate {
		t.Fatalf("expected domain and certificate nodes, got %+v", got.Nodes)
	}

	edge := got.Edges[0]
	expectedID := "presents-certificate:example.com:443:" + fingerprint
	if edge.ID != expectedID {
		t.Fatalf("unexpected edge ID: %q", edge.ID)
	}
	if edge.Type != EdgePresentsCertificate || edge.Port != 443 {
		t.Fatalf("unexpected TLS edge type or port: %+v", edge)
	}
	if edge.Source != "domain:example.com" ||
		edge.Target != "tls-cert:"+fingerprint {
		t.Fatalf("unexpected TLS edge endpoints: %+v", edge)
	}
	if len(edge.EvidenceIDs) != 1 || edge.EvidenceIDs[0] != "tls-evidence-1" {
		t.Fatalf("unexpected evidence references: %v", edge.EvidenceIDs)
	}
	if len(edge.ObservationIDs) != 1 ||
		edge.ObservationIDs[0] != "tls-observation-1" {
		t.Fatalf("unexpected observation references: %v", edge.ObservationIDs)
	}
}

func TestValidateRejectsNonHexTLSFingerprint(t *testing.T) {
	fingerprint := strings.Repeat("z", 64)
	graph := Graph{
		Nodes: []Node{
			{ID: "tls-cert:" + fingerprint, Type: NodeTLSCertificate, Value: fingerprint},
		},
		Edges: []Edge{},
	}

	if err := graph.Validate(); err == nil {
		t.Fatal("expected non-hex TLS fingerprint to be rejected")
	}
}

func TestBuildCreatesTLSGraphForIPAddress(t *testing.T) {
	fingerprint := strings.Repeat("b2", 32)
	details := evidence.TLSCertificateDetails{
		Target:            "192.0.2.10",
		Port:              8443,
		NotBefore:         time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:          time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		SHA256Fingerprint: fingerprint,
		TLSVersion:        "TLS 1.3",
	}

	value, err := json.Marshal(details)
	if err != nil {
		t.Fatalf("could not marshal TLS details: %v", err)
	}

	record := evidence.Evidence{
		ID:       "tls-ip-evidence",
		EntityID: "192.0.2.10",
		Type:     evidence.TypeTLSCertificate,
		Value:    string(value),
	}

	got, err := Build([]evidence.Evidence{record}, nil)
	if err != nil {
		t.Fatalf("Build() returned error: %v", err)
	}

	if err := got.Validate(); err != nil {
		t.Fatalf("generated graph is invalid: %v", err)
	}
	if len(got.Nodes) != 2 || len(got.Edges) != 1 {
		t.Fatalf("unexpected graph size: %d nodes, %d edges", len(got.Nodes), len(got.Edges))
	}

	edge := got.Edges[0]
	if edge.Source != "ip:192.0.2.10" || edge.Port != 8443 {
		t.Fatalf("unexpected IP TLS edge: %+v", edge)
	}
}

// TestBuildCreatesTCPPortGraph verifies that TCP port evidence creates a host,
// port node, and HAS_OPEN_PORT edge with evidence and observation references.
func TestBuildCreatesTCPPortGraph(t *testing.T) {
	details := evidence.TCPPortDetails{
		Target:   "example.com",
		Protocol: "tcp",
		Port:     443,
		State:    "open",
	}
	value, err := json.Marshal(details)
	if err != nil {
		t.Fatalf("marshal TCP details: %v", err)
	}

	record := evidence.Evidence{
		ID:       "tcp-port:example.com:443",
		EntityID: "example.com",
		Type:     evidence.TypeTCPPort,
		Value:    string(value),
	}
	observation := evidence.Observation{
		ID:         "observation:tcp-443",
		EvidenceID: record.ID,
		Source:     "tcp",
		ObservedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		EventIDs:   []string{"event:tcp-443"},
	}

	g, err := Build([]evidence.Evidence{record}, []evidence.Observation{observation})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if err := g.Validate(); err != nil {
		t.Fatalf("Graph.Validate() error = %v", err)
	}

	nodes := make(map[string]Node)
	for _, node := range g.Nodes {
		nodes[node.ID] = node
	}

	if node, ok := nodes["domain:example.com"]; !ok || node.Type != NodeDomain {
		t.Fatalf("missing expected domain node: %+v", node)
	}
	if node, ok := nodes["tcp-port:example.com:443"]; !ok ||
		node.Type != NodeTCPPort || node.Value != "example.com:443" {
		t.Fatalf("missing or invalid TCP port node: %+v", node)
	}

	var found bool
	for _, edge := range g.Edges {
		if edge.ID != "has-open-port:example.com:443" {
			continue
		}
		found = true
		if edge.Type != EdgeHasOpenPort ||
			edge.Source != "domain:example.com" ||
			edge.Target != "tcp-port:example.com:443" ||
			edge.Port != 443 {
			t.Fatalf("unexpected TCP edge: %+v", edge)
		}
		if len(edge.EvidenceIDs) != 1 || edge.EvidenceIDs[0] != record.ID {
			t.Errorf("unexpected edge evidence IDs: %v", edge.EvidenceIDs)
		}
		if len(edge.ObservationIDs) != 1 ||
			edge.ObservationIDs[0] != observation.ID {
			t.Errorf("unexpected edge observation IDs: %v", edge.ObservationIDs)
		}
		break
	}
	if !found {
		t.Fatal("missing HAS_OPEN_PORT edge for example.com:443")
	}
}

func TestBuildRepresentsClosedAndUnknownTCPObservationsWithoutOpenPortClaims(t *testing.T) {
	records := make([]evidence.Evidence, 0, 2)
	observations := make([]evidence.Observation, 0, 2)
	for _, state := range []string{"closed", "unknown"} {
		details := evidence.TCPPortObservationDetails{
			Target: "127.0.0.1", Protocol: "tcp", Port: 8080,
			State: state, Reason: "controlled test observation",
		}
		value, err := json.Marshal(details)
		if err != nil {
			t.Fatalf("marshal %s details: %v", state, err)
		}
		record := evidence.Evidence{
			ID: "tcp-port-observation:" + state, EntityID: "127.0.0.1",
			Type: evidence.TypeTCPPortObservation, Value: string(value),
		}
		records = append(records, record)
		observations = append(observations, evidence.Observation{
			ID: "observation:" + state, EvidenceID: record.ID, Source: "tcp",
			ObservedAt: time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC),
			EventIDs: []string{"event:" + state},
		})
	}
	got, err := Build(records, observations)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("Graph.Validate() error = %v", err)
	}
	if len(got.Nodes) != 2 || len(got.Edges) != 2 {
		t.Fatalf("graph should contain host/port nodes and two state edges; got %d nodes, %d edges", len(got.Nodes), len(got.Edges))
	}
	states := make(map[string]Edge)
	for _, edge := range got.Edges {
		if edge.Type != EdgeObservedTCPPortState {
			t.Fatalf("unexpected edge type %q", edge.Type)
		}
		states[edge.State] = edge
	}
	for _, state := range []string{"closed", "unknown"} {
		edge, ok := states[state]
		if !ok {
			t.Errorf("missing %s state edge", state)
			continue
		}
		if edge.Source != "ip:127.0.0.1" || edge.Target != "tcp-port:127.0.0.1:8080" || edge.Port != 8080 {
			t.Errorf("invalid %s state edge: %+v", state, edge)
		}
		if len(edge.EvidenceIDs) != 1 || len(edge.ObservationIDs) != 1 {
			t.Errorf("%s edge lost provenance: %+v", state, edge)
		}
	}
}

func TestAttachServicesDoesNotCreateHostedServiceForClosedOrUnknownTCP(t *testing.T) {
	services := []observations.Service{
		{ID: "closed", Target: "127.0.0.1", Port: 80, Transport: "tcp", State: "closed", EvidenceIDs: []string{"closed-evidence"}},
		{ID: "unknown", Target: "127.0.0.1", Port: 81, Transport: "tcp", State: "unknown", EvidenceIDs: []string{"unknown-evidence"}},
	}
	got, err := AttachServices(Graph{}, services)
	if err != nil {
		t.Fatalf("AttachServices() error = %v", err)
	}
	if len(got.Nodes) != 0 || len(got.Edges) != 0 {
		t.Fatalf("non-open TCP states created graph services: nodes=%+v edges=%+v", got.Nodes, got.Edges)
	}
}
