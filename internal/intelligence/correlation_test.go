package intelligence

import (
	"encoding/json"
 "fmt"
	"testing"
	"time"
	"strings"

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


func tlsEvidenceForTest(t *testing.T, id, target, fingerprint string) evidence.Evidence {
	t.Helper()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	details := evidence.TLSCertificateDetails{
		Target: target, Port: 443, SHA256Fingerprint: fingerprint,
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		TLSVersion: "TLS 1.3",
	}
	value, err := json.Marshal(details)
	if err != nil {
		t.Fatalf("marshal TLS details: %v", err)
	}
	return evidence.Evidence{ID: id, EntityID: target, Type: evidence.TypeTLSCertificate, Value: string(value)}
}

func TestCorrelateEvidenceFindsSharedTLSCertificateFingerprint(t *testing.T) {
	fingerprint := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	records := []evidence.Evidence{
		tlsEvidenceForTest(t, "tls-a", "a.example.com", fingerprint),
		tlsEvidenceForTest(t, "tls-b", "b.example.com", strings.ToUpper(fingerprint)),
		tlsEvidenceForTest(t, "tls-c", "c.example.com", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
	}
	results, err := (&CorrelationEngine{}).CorrelateEvidence(records, nil)
	if err != nil {
		t.Fatalf("CorrelateEvidence returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected one shared-certificate correlation, got %d", len(results))
	}
	got := results[0]
	if got.Type != CorrelationSharedTLSCertificateFingerprint {
		t.Fatalf("unexpected correlation type: %q", got.Type)
	}
	if got.ID != "shared-tls-cert:"+fingerprint || got.SharedValue != fingerprint {
		t.Fatalf("unexpected normalized certificate correlation: %#v", got)
	}
	if len(got.Entities) != 2 || got.Entities[0] != "a.example.com" || got.Entities[1] != "b.example.com" {
		t.Fatalf("unexpected related entities: %#v", got.Entities)
	}
	if got.ConfidenceScope != "OBSERVED_SHARED_CERTIFICATE_FINGERPRINT" {
		t.Fatalf("unexpected confidence scope: %q", got.ConfidenceScope)
	}
	if !strings.Contains(got.Limitations, "not common ownership") {
		t.Fatalf("expected explicit correlation limitations, got %q", got.Limitations)
	}
}

func TestCorrelateEvidenceScopesSharedTLSCertificateToTarget(t *testing.T) {
	fingerprint := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	records := []evidence.Evidence{
		tlsEvidenceForTest(t, "tls-a", "a.example.com", fingerprint),
		tlsEvidenceForTest(t, "tls-b", "b.example.com", fingerprint),
		tlsEvidenceForTest(t, "tls-c", "c.example.net", fingerprint),
	}
	results, err := (&CorrelationEngine{}).CorrelateEvidenceForTarget(records, nil, "a.example.com")
	if err != nil {
		t.Fatalf("CorrelateEvidenceForTarget returned error: %v", err)
	}
	if len(results) != 1 || len(results[0].Entities) != 3 {
		t.Fatalf("expected target correlation to retain all related entities, got %#v", results)
	}
}


func TestCorrelateEvidenceRejectsMalformedTLSFingerprints(t *testing.T) {
	tests := []struct {
		name        string
		fingerprint string
	}{
		{name: "empty", fingerprint: ""},
		{name: "too short", fingerprint: "abcd"},
		{name: "non hexadecimal", fingerprint: strings.Repeat("g", 64)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			records := []evidence.Evidence{
				tlsEvidenceForTest(t, "tls-a", "a.example.com", test.fingerprint),
			}
			if _, err := (&CorrelationEngine{}).CorrelateEvidence(records, nil); err == nil {
				t.Fatal("expected malformed TLS fingerprint to be rejected")
			}
		})
	}
}


func TestCorrelationReportsDistinctSourcesWithoutClaimingIndependence(t *testing.T) {
	records := []evidence.Evidence{
		{ID: "ev-a", EntityID: "a.example.com", Type: evidence.TypeDNSAddress, Value: "192.0.2.44"},
		{ID: "ev-b", EntityID: "b.example.com", Type: evidence.TypeDNSAddress, Value: "192.0.2.44"},
	}
	observations := []evidence.Observation{
		{ID: "obs-a", EvidenceID: "ev-a", Source: "resolver-a", ObservedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), EventIDs: []string{"event-a"}},
		{ID: "obs-b", EvidenceID: "ev-b", Source: "resolver-b", ObservedAt: time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC), EventIDs: []string{"event-b"}},
	}
	results, err := (&CorrelationEngine{}).CorrelateEvidence(records, observations)
	if err != nil {
		t.Fatalf("CorrelateEvidence returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected one correlation, got %d", len(results))
	}
	got := results[0]
	if got.DistinctSourceCount != 2 {
		t.Fatalf("distinct source count = %d, want 2", got.DistinctSourceCount)
	}
	if len(got.SourceNames) != 2 || got.SourceNames[0] != "resolver-a" || got.SourceNames[1] != "resolver-b" {
		t.Fatalf("source names should be unique and sorted: %#v", got.SourceNames)
	}
	if !strings.Contains(got.Limitations, "do not prove independent corroboration") {
		t.Fatalf("source diversity must not be presented as proof of independence: %q", got.Limitations)
	}
	if got.Confidence != "HIGH" {
		t.Fatalf("observed association confidence contract unexpectedly changed: %q", got.Confidence)
	}
}

func TestCorrelateEvidenceFindsSharedCTRecordAndHistoricalIP(t *testing.T){
 now:=time.Date(2026,10,29,12,0,0,0,time.UTC)
 makeCT:=func(id,target,name string)evidence.Evidence{
  details:=evidence.CTDNSNameDetails{Target:target,DNSName:name,CertificateID:77,IssuerName:"Example CA",Source:"crt.sh",RetrievedAt:now}
  value,err:=json.Marshal(details);if err!=nil{t.Fatal(err)}
  return evidence.Evidence{ID:id,EntityID:target,Type:evidence.TypeCTDNSName,Value:string(value)}
 }
 makePDNS:=func(id,target,hostname string)evidence.Evidence{
  details:=evidence.PassiveDNSDetails{Target:target,Hostname:hostname,Address:"203.0.113.7",RecordType:"A",FirstSeen:"2024-01-01",LastSeen:"2025-01-01",Source:"otx.alienvault.com"}
  value,err:=json.Marshal(details);if err!=nil{t.Fatal(err)}
  return evidence.Evidence{ID:id,EntityID:target,Type:evidence.TypePassiveDNS,Value:string(value)}
 }
 records:=[]evidence.Evidence{
  makeCT("ct-a","a.example.com","a.example.com"),
  makeCT("ct-b","b.example.net","b.example.net"),
  makePDNS("pdns-a","a.example.com","a.example.com"),
  makePDNS("pdns-b","b.example.net","b.example.net"),
 }
 observations:=[]evidence.Observation{
  {ID:"obs-ct-a",EvidenceID:"ct-a",Source:"crt.sh",ObservedAt:now,EventIDs:[]string{"evt-ct-a"}},
  {ID:"obs-ct-b",EvidenceID:"ct-b",Source:"crt.sh",ObservedAt:now,EventIDs:[]string{"evt-ct-b"}},
  {ID:"obs-pdns-a",EvidenceID:"pdns-a",Source:"otx.alienvault.com",ObservedAt:now,EventIDs:[]string{"evt-pdns-a"}},
  {ID:"obs-pdns-b",EvidenceID:"pdns-b",Source:"otx.alienvault.com",ObservedAt:now,EventIDs:[]string{"evt-pdns-b"}},
 }
 results,err:=(&CorrelationEngine{}).CorrelateEvidence(records,observations);if err!=nil{t.Fatal(err)}
 if len(results)!=2{t.Fatalf("expected CT and historical-IP correlations, got %+v",results)}
 foundCT,foundHistorical:=false,false
 for _,result:=range results{
  if len(result.Entities)!=2||len(result.EvidenceIDs)!=2||len(result.ObservationIDs)!=2{t.Fatalf("incomplete provenance: %+v",result)}
  switch result.Type{
  case CorrelationSharedCTCertificateRecord:
   foundCT=true
   if result.SharedValue!="crt.sh#77"{t.Fatalf("unexpected CT key: %q",result.SharedValue)}
   if !strings.Contains(result.Limitations,"not proof of common ownership"){t.Fatalf("missing CT limitations: %s",result.Limitations)}
  case CorrelationSharedHistoricalIPAddress:
   foundHistorical=true
   if result.SharedValue!="203.0.113.7"{t.Fatalf("unexpected historical IP: %q",result.SharedValue)}
   if !strings.Contains(result.Limitations,"Historical passive-DNS overlap"){t.Fatalf("missing historical DNS limitations: %s",result.Limitations)}
  }
 }
 if !foundCT||!foundHistorical{t.Fatalf("missing correlation types: %+v",results)}
}

func TestCorrelateExternalEvidenceHonorsTargetScope(t *testing.T){
 now:=time.Date(2026,10,29,12,0,0,0,time.UTC)
 records:=make([]evidence.Evidence,0,2)
 observations:=make([]evidence.Observation,0,2)
 for i,target:=range []string{"a.example.com","b.example.net"}{
  details:=evidence.CTDNSNameDetails{Target:target,DNSName:target,CertificateID:99,Source:"crt.sh",RetrievedAt:now}
  value,_:=json.Marshal(details);id:=fmt.Sprintf("ct-%d",i)
  records=append(records,evidence.Evidence{ID:id,EntityID:target,Type:evidence.TypeCTDNSName,Value:string(value)})
  observations=append(observations,evidence.Observation{ID:"obs-"+id,EvidenceID:id,Source:"crt.sh",ObservedAt:now,EventIDs:[]string{"evt-"+id}})
 }
 results,err:=(&CorrelationEngine{}).CorrelateEvidenceForTarget(records,observations,"a.example.com");if err!=nil{t.Fatal(err)}
 if len(results)!=1||len(results[0].Entities)!=2{t.Fatalf("expected only target-related CT correlation, got %+v",results)}
}
