package history

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/itsFuRy007/kem3t/internal/evidence"
)

func TestBuildSnapshotRetainsClosedAndUnknownTCPStates(t *testing.T) {
	started := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	records := make([]evidence.Evidence, 0, 2)
	observations := make([]evidence.Observation, 0, 2)
	for i, state := range []string{"closed", "unknown"} {
		details := evidence.TCPPortObservationDetails{Target:"127.0.0.1", Protocol:"tcp", Port:32000+i, State:state, Reason:"test reason"}
		value, err := json.Marshal(details)
		if err != nil { t.Fatal(err) }
		item := evidence.Evidence{ID:"tcp-state-"+state, EntityID:"127.0.0.1", Type:evidence.TypeTCPPortObservation, Value:string(value)}
		if err := item.Validate(); err != nil { t.Fatal(err) }
		records = append(records, item)
		observations = append(observations, evidence.Observation{ID:"obs-"+state, EvidenceID:item.ID, Source:"tcp-collector", ObservedAt:started.Add(time.Minute), EventIDs:[]string{"event-"+state}})
	}
	run := evidence.CollectionRun{ID:"tcp-123", Target:"127.0.0.1", StartedAt:started, FinishedAt:started.Add(2*time.Minute), Status:evidence.CollectionRunCompleted, EventCount:2}
	snapshot, err := BuildSnapshot(run, records, observations)
	if err != nil { t.Fatalf("BuildSnapshot() error = %v", err) }
	if len(snapshot.Records) != 2 { t.Fatalf("snapshot records = %d, want 2", len(snapshot.Records)) }
	if snapshot.Records[0].Key == snapshot.Records[1].Key { t.Fatal("distinct ports collapsed into one history key") }
}

func TestTCPStateHistoryUsesStablePortKeyAcrossStateTransitions(t *testing.T) {
	openValue, _ := json.Marshal(evidence.TCPPortDetails{Target:"127.0.0.1", Protocol:"tcp", Port:443, State:"open"})
	closedValue, _ := json.Marshal(evidence.TCPPortObservationDetails{Target:"127.0.0.1", Protocol:"tcp", Port:443, State:"closed", Reason:"connection refused"})
	openKey, err := recordKey(evidence.Evidence{ID:"open",EntityID:"127.0.0.1",Type:evidence.TypeTCPPort,Value:string(openValue)})
	if err != nil { t.Fatal(err) }
	closedKey, err := recordKey(evidence.Evidence{ID:"closed",EntityID:"127.0.0.1",Type:evidence.TypeTCPPortObservation,Value:string(closedValue)})
	if err != nil { t.Fatal(err) }
	if openKey != closedKey { t.Fatalf("state transition keys differ: %q != %q", openKey, closedKey) }
}
