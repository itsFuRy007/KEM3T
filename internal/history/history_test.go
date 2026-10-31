package history

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/itsFuRy007/kem3t/internal/evidence"
)

func TestBuildSnapshotAndCompareAcrossCollectionTypes(t *testing.T) {
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	run1 := evidence.CollectionRun{ID: "tcp-1", Target: "api.example.test", StartedAt: start, FinishedAt: start.Add(time.Minute), Status: evidence.CollectionRunCompleted}
	run2 := evidence.CollectionRun{ID: "tcp-2", Target: "api.example.test", StartedAt: start.Add(time.Hour), FinishedAt: start.Add(time.Hour + time.Minute), Status: evidence.CollectionRunCompleted}
	e1 := evidence.Evidence{ID: "tcp-port:api.example.test:443", EntityID: "api.example.test", Type: evidence.TypeTCPPort, Value: `{"target":"api.example.test","protocol":"tcp","port":443,"state":"open"}`}
	e2 := evidence.Evidence{ID: "tcp-port:api.example.test:8443", EntityID: "api.example.test", Type: evidence.TypeTCPPort, Value: `{"target":"api.example.test","protocol":"tcp","port":8443,"state":"open"}`}
	obs := []evidence.Observation{
		{ID: "obs-1", EvidenceID: e1.ID, ObservedAt: start.Add(time.Second)},
		{ID: "obs-2", EvidenceID: e2.ID, ObservedAt: start.Add(time.Hour + time.Second)},
	}
	first, err := BuildSnapshot(run1, []evidence.Evidence{e1, e2}, obs)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildSnapshot(run2, []evidence.Evidence{e1, e2}, obs)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Records) != 1 || first.Records[0].Key != "TCP_PORT_STATE|api.example.test|00443" {
		t.Fatalf("unexpected first snapshot: %+v", first)
	}
	if len(second.Records) != 1 || second.Records[0].Key != "TCP_PORT_STATE|api.example.test|08443" {
		t.Fatalf("unexpected second snapshot: %+v", second)
	}
	changes, err := Compare(first, second)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 2 {
		t.Fatalf("got %d changes, want port add and remove: %+v", len(changes), changes)
	}
}

func TestSnapshotStoreRoundTripAndDeterministicTimeline(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "history"))
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	makeSnapshot := func(id string, offset time.Duration) Snapshot {
		return Snapshot{RunID: id, Target: "example.test", Collector: "dns", CollectedAt: at.Add(offset), Records: []Record{{Key: "DNS_ADDRESS|example.test|192.0.2.1", Type: evidence.TypeDNSAddress, EntityID: "example.test", ValueHash: "abc", EvidenceIDs: []string{"e1"}, ObservationIDs: []string{"o1"}, ObservedAt: at.Add(offset)}}}
	}
	s1 := makeSnapshot("dns-1", 0)
	s2 := makeSnapshot("dns-2", time.Hour)
	s2.Records = []Record{{Key: "DNS_ADDRESS|example.test|192.0.2.2", Type: evidence.TypeDNSAddress, EntityID: "example.test", ValueHash: "def", EvidenceIDs: []string{"e2"}, ObservationIDs: []string{"o2"}, ObservedAt: at.Add(time.Hour)}}
	if err := store.Save(s2); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(s1); err != nil {
		t.Fatal(err)
	}
	got, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].RunID != "dns-1" || got[1].RunID != "dns-2" {
		t.Fatalf("unexpected snapshot order: %+v", got)
	}
	timeline, err := BuildTimeline(got)
	if err != nil {
		t.Fatal(err)
	}
	if len(timeline.Changes) != 2 {
		t.Fatalf("unexpected timeline changes: %+v", timeline.Changes)
	}
	added, removed := 0, 0
	for _, change := range timeline.Changes {
		switch change.Type {
		case ChangeAdded:
			added++
		case ChangeRemoved:
			removed++
		}
	}
	if added != 1 || removed != 1 {
		t.Fatalf("expected one add and one removal, got added=%d removed=%d: %+v", added, removed, timeline.Changes)
	}
}

func TestBuildSnapshotRejectsFailedRuns(t *testing.T) {
	run := evidence.CollectionRun{ID: "dns-1", Target: "example.test", StartedAt: time.Now().Add(-time.Minute), FinishedAt: time.Now(), Status: evidence.CollectionRunFailed}
	if _, err := BuildSnapshot(run, nil, nil); err == nil {
		t.Fatal("expected failed run to be rejected")
	}
}

func TestBuildSnapshotNormalizesURLAndScopesCollectorType(t *testing.T) {
	start := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	run := evidence.CollectionRun{
		ID: "http-1", Target: "https://api.example.test/path", StartedAt: start,
		FinishedAt: start.Add(time.Minute), Status: evidence.CollectionRunCompleted,
	}
	httpEvidence := evidence.Evidence{
		ID: "http-service:api.example.test:443:https", EntityID: "api.example.test",
		Type:  evidence.TypeHTTPService,
		Value: `{"target":"api.example.test","scheme":"https","port":443,"url":"https://api.example.test","final_url":"https://api.example.test","status_code":200,"redirect_count":0}`,
	}
	tcpEvidence := evidence.Evidence{
		ID: "tcp-port:api.example.test:443", EntityID: "api.example.test",
		Type:  evidence.TypeTCPPort,
		Value: `{"target":"api.example.test","protocol":"tcp","port":443,"state":"open"}`,
	}
	observations := []evidence.Observation{
		{ID: "http-observation", EvidenceID: httpEvidence.ID, ObservedAt: start.Add(time.Second)},
		{ID: "tcp-observation", EvidenceID: tcpEvidence.ID, ObservedAt: start.Add(2 * time.Second)},
	}
	snapshot, err := BuildSnapshot(run, []evidence.Evidence{httpEvidence, tcpEvidence}, observations)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Target != "api.example.test" {
		t.Fatalf("target = %q, want api.example.test", snapshot.Target)
	}
	if len(snapshot.Records) != 1 || snapshot.Records[0].Type != evidence.TypeHTTPService {
		t.Fatalf("snapshot must contain only HTTP records from the HTTP run: %+v", snapshot.Records)
	}
}

func TestBuildUnifiedInvestigationSnapshotIncludesMultipleCollectorTypes(t *testing.T) {
	start := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	run := evidence.CollectionRun{ID: "investigation-1", Target: "example.com", StartedAt: start, FinishedAt: start.Add(time.Minute), Status: evidence.CollectionRunCompleted}
	dns := evidence.Evidence{ID: "dns-address:example.com:203.0.113.8", EntityID: "example.com", Type: evidence.TypeDNSAddress, Value: "203.0.113.8"}
	tcp := evidence.Evidence{ID: "tcp-port:example.com:443", EntityID: "example.com", Type: evidence.TypeTCPPort, Value: `{"target":"example.com","protocol":"tcp","port":443,"state":"open"}`}
	ct := evidence.Evidence{ID: "ct-dns-name:example.com:api.example.com", EntityID: "example.com", Type: evidence.TypeCTDNSName, Value: "api.example.com"}
	subdomainDNS := evidence.Evidence{ID: "dns-address:api.example.com:203.0.113.9", EntityID: "api.example.com", Type: evidence.TypeDNSAddress, Value: "203.0.113.9"}
	ipRDAP := evidence.Evidence{ID: "ip-rdap:203.0.113.9", EntityID: "203.0.113.9", Type: evidence.TypeIPRDAPNetwork, Value: "network details"}
	observations := []evidence.Observation{
		{ID: "obs-dns", EvidenceID: dns.ID, Source: "dns", ObservedAt: start.Add(time.Second), EventIDs: []string{"event-dns"}},
		{ID: "obs-tcp", EvidenceID: tcp.ID, Source: "tcp", ObservedAt: start.Add(2 * time.Second), EventIDs: []string{"event-tcp"}},
		{ID: "obs-ct", EvidenceID: ct.ID, Source: "ct", ObservedAt: start.Add(3 * time.Second), EventIDs: []string{"event-ct"}},
		{ID: "obs-subdomain-dns", EvidenceID: subdomainDNS.ID, Source: "dns", ObservedAt: start.Add(4 * time.Second), EventIDs: []string{"event-subdomain-dns"}},
		{ID: "obs-ip-rdap", EvidenceID: ipRDAP.ID, Source: "rdap", ObservedAt: start.Add(5 * time.Second), EventIDs: []string{"event-ip-rdap"}},
	}
	snapshot, err := BuildSnapshot(run, []evidence.Evidence{dns, tcp, ct, subdomainDNS, ipRDAP}, observations)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Collector != "investigation" {
		t.Fatalf("unexpected collector identity %q", snapshot.Collector)
	}
	if len(snapshot.Records) != 5 {
		t.Fatalf("expected root, subdomain, linked-IP, TCP, and CT evidence in one snapshot, got %+v", snapshot.Records)
	}
}


func TestBuildSnapshotUsesExplicitRunProvenanceOverTimestampWindows(t *testing.T) {
	start := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	run := evidence.CollectionRun{
		ID: "dns-current", Target: "example.test", StartedAt: start,
		FinishedAt: start.Add(time.Minute), Status: evidence.CollectionRunCompleted,
	}
	current := evidence.Evidence{ID: "dns-current-evidence", EntityID: "example.test", Type: evidence.TypeDNSAddress, Value: "192.0.2.10"}
	otherRun := evidence.Evidence{ID: "dns-other-evidence", EntityID: "example.test", Type: evidence.TypeDNSAddress, Value: "192.0.2.11"}
	legacy := evidence.Evidence{ID: "dns-legacy-evidence", EntityID: "example.test", Type: evidence.TypeDNSAddress, Value: "192.0.2.12"}
	observations := []evidence.Observation{
		{ID: "current-outside-window", EvidenceID: current.ID, CollectionRunID: run.ID, ObservedAt: start.Add(-time.Hour)},
		{ID: "other-run-inside-window", EvidenceID: otherRun.ID, CollectionRunID: "dns-previous", ObservedAt: start.Add(time.Second)},
		{ID: "legacy-inside-window", EvidenceID: legacy.ID, ObservedAt: start.Add(2 * time.Second)},
	}
	snapshot, err := BuildSnapshot(run, []evidence.Evidence{current, otherRun, legacy}, observations)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Records) != 2 {
		t.Fatalf("expected explicit current-run record plus legacy timestamp record, got %+v", snapshot.Records)
	}
	for _, record := range snapshot.Records {
		for _, id := range record.ObservationIDs {
			if id == "other-run-inside-window" {
				t.Fatalf("observation from another run leaked into snapshot: %+v", snapshot.Records)
			}
		}
	}
}
