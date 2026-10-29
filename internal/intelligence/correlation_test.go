package intelligence

import (
	"testing"
	"time"

	"github.com/itsFuRy007/kem3t/internal/evidence"
)

func TestCorrelateEvidenceFindsSharedIPAddress(t *testing.T) {
	engine := &CorrelationEngine{}

	records := []evidence.Evidence{
		{
			ID:       "ev-a",
			EntityID: "a.example.com",
			Type:     evidence.TypeDNSAddress,
			Value:    "192.0.2.10",
		},
		{
			ID:       "ev-b",
			EntityID: "b.example.com",
			Type:     evidence.TypeDNSAddress,
			Value:    "192.0.2.10",
		},
		{
			ID:       "ev-c",
			EntityID: "c.example.com",
			Type:     evidence.TypeDNSAddress,
			Value:    "192.0.2.20",
		},
	}

	observations := []evidence.Observation{
		{
			ID:         "obs-a",
			EvidenceID: "ev-a",
			Source:     "test",
			ObservedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			EventIDs:   []string{"event-a"},
		},
		{
			ID:         "obs-b",
			EvidenceID: "ev-b",
			Source:     "test",
			ObservedAt: time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC),
			EventIDs:   []string{"event-b"},
		},
	}

	results, err := engine.CorrelateEvidence(records, observations)
	if err != nil {
		t.Fatalf("CorrelateEvidence returned error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 correlation, got %d", len(results))
	}

	got := results[0]
	if got.Type != CorrelationSharedIPAddress {
		t.Fatalf("unexpected correlation type: %q", got.Type)
	}
	if got.SharedValue != "192.0.2.10" {
		t.Fatalf("unexpected shared value: %q", got.SharedValue)
	}
	if len(got.Entities) != 2 {
		t.Fatalf("expected 2 entities, got %d", len(got.Entities))
	}
	if got.Entities[0] != "a.example.com" || got.Entities[1] != "b.example.com" {
		t.Fatalf("entities are not correctly normalized and sorted: %#v", got.Entities)
	}
	if len(got.EvidenceIDs) != 2 {
		t.Fatalf("expected 2 evidence IDs, got %d", len(got.EvidenceIDs))
	}
	if len(got.ObservationIDs) != 2 {
		t.Fatalf("expected 2 observation IDs, got %d", len(got.ObservationIDs))
	}
	if got.ObservationCount != 2 {
		t.Fatalf("expected 2 observations, got %d", got.ObservationCount)
	}
	if got.Confidence != "HIGH" {
		t.Fatalf("unexpected confidence: %q", got.Confidence)
	}
}

func TestCorrelateEvidenceIgnoresSingleEntityAddress(t *testing.T) {
	engine := &CorrelationEngine{}

	records := []evidence.Evidence{
		{
			ID:       "ev-a",
			EntityID: "a.example.com",
			Type:     evidence.TypeDNSAddress,
			Value:    "192.0.2.10",
		},
	}

	results, err := engine.CorrelateEvidence(records, nil)
	if err != nil {
		t.Fatalf("CorrelateEvidence returned error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected no correlations, got %d", len(results))
	}
}

func TestCorrelateEvidenceRejectsInvalidEvidence(t *testing.T) {
	engine := &CorrelationEngine{}

	_, err := engine.CorrelateEvidence([]evidence.Evidence{
		{
			ID:       "invalid",
			EntityID: "a.example.com",
			Type:     evidence.TypeDNSAddress,
			Value:    "not-an-ip",
		},
	}, nil)

	if err == nil {
		t.Fatal("expected invalid evidence error")
	}
}

func TestCorrelateEvidenceRejectsInvalidObservation(t *testing.T) {
	engine := &CorrelationEngine{}

	_, err := engine.CorrelateEvidence(nil, []evidence.Observation{
		{ID: "invalid"},
	})

	if err == nil {
		t.Fatal("expected invalid observation error")
	}
}

func TestCorrelateReadsFromRegistry(t *testing.T) {
	registry := evidence.NewRegistry()
	engine := &CorrelationEngine{}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	records := []evidence.Evidence{
		{
			ID:       "dns-address:a.example.com:192.0.2.50",
			EntityID: "a.example.com",
			Type:     evidence.TypeDNSAddress,
			Value:    "192.0.2.50",
		},
		{
			ID:       "dns-address:b.example.com:192.0.2.50",
			EntityID: "b.example.com",
			Type:     evidence.TypeDNSAddress,
			Value:    "192.0.2.50",
		},
	}

	for _, record := range records {
		if err := registry.AddEvidence(record); err != nil {
			t.Fatalf("AddEvidence(%q): %v", record.ID, err)
		}
	}

	observations := []evidence.Observation{
		{
			ID:         "observation:event-a",
			EvidenceID: records[0].ID,
			Source:     "test",
			ObservedAt: now,
			EventIDs:   []string{"event-a"},
		},
		{
			ID:         "observation:event-b",
			EvidenceID: records[1].ID,
			Source:     "test",
			ObservedAt: now.Add(time.Second),
			EventIDs:   []string{"event-b"},
		},
	}

	for _, observation := range observations {
		if err := registry.AddObservation(observation); err != nil {
			t.Fatalf("AddObservation(%q): %v", observation.ID, err)
		}
	}

	results, err := engine.Correlate(registry)
	if err != nil {
		t.Fatalf("Correlate returned error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 correlation, got %d", len(results))
	}

	result := results[0]
	if result.SharedValue != "192.0.2.50" {
		t.Fatalf("unexpected shared IP: %q", result.SharedValue)
	}
	if len(result.Entities) != 2 {
		t.Fatalf("expected 2 entities, got %d", len(result.Entities))
	}
	if result.ObservationCount != 2 {
		t.Fatalf("expected 2 observations, got %d", result.ObservationCount)
	}
}

func TestCorrelateRejectsNilRegistry(t *testing.T) {
	engine := &CorrelationEngine{}

	_, err := engine.Correlate(nil)
	if err == nil {
		t.Fatal("expected error for nil registry")
	}
}

func TestCorrelateEvidenceForTargetScopesAndNormalizesAddresses(t *testing.T) {
	engine := &CorrelationEngine{}
	records := []evidence.Evidence{
		{ID: "ev-a", EntityID: "A.EXAMPLE.COM.", Type: evidence.TypeDNSAddress, Value: "2001:0db8:0:0:0:0:0:1"},
		{ID: "ev-b", EntityID: "b.example.com", Type: evidence.TypeDNSAddress, Value: "2001:db8::1"},
		{ID: "ev-c", EntityID: "c.example.net", Type: evidence.TypeDNSAddress, Value: "192.0.2.20"},
		{ID: "ev-d", EntityID: "d.example.net", Type: evidence.TypeDNSAddress, Value: "192.0.2.20"},
	}

	results, err := engine.CorrelateEvidenceForTarget(records, nil, "a.example.com")
	if err != nil {
		t.Fatalf("CorrelateEvidenceForTarget returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected one target-related correlation, got %d", len(results))
	}
	if results[0].SharedValue != "2001:db8::1" {
		t.Fatalf("expected normalized IPv6 address, got %q", results[0].SharedValue)
	}
	if results[0].ConfidenceScope != "OBSERVED_SHARED_ADDRESS" {
		t.Fatalf("unexpected confidence scope: %q", results[0].ConfidenceScope)
	}
	if results[0].Confidence != "HIGH" {
		t.Fatalf("unexpected association confidence: %q", results[0].Confidence)
	}
}

func TestCorrelateEvidenceRejectsDanglingObservationReference(t *testing.T) {
	engine := &CorrelationEngine{}
	_, err := engine.CorrelateEvidence(nil, []evidence.Observation{
		{
			ID:         "orphan-observation",
			EvidenceID: "missing-evidence",
			Source:     "test",
			ObservedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			EventIDs:   []string{"event-1"},
		},
	})
	if err == nil {
		t.Fatal("expected dangling observation reference to be rejected")
	}
}
