package history

import (
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/itsFuRy007/kem3t/internal/evidence"
)

func TestBuildSnapshotAndCompareAcrossCollectionTypes(t *testing.T) {
	start:=time.Date(2026,10,1,0,0,0,0,time.UTC)
	run1:=evidence.CollectionRun{ID:"tcp-1",Target:"api.example.test",StartedAt:start,FinishedAt:start.Add(time.Minute),Status:evidence.CollectionRunCompleted}
	run2:=evidence.CollectionRun{ID:"tcp-2",Target:"api.example.test",StartedAt:start.Add(time.Hour),FinishedAt:start.Add(time.Hour+time.Minute),Status:evidence.CollectionRunCompleted}
	e1:=evidence.Evidence{ID:"tcp-port:api.example.test:443",EntityID:"api.example.test",Type:evidence.TypeTCPPort,Value:`{"target":"api.example.test","protocol":"tcp","port":443,"state":"open"}`}
	e2:=evidence.Evidence{ID:"tcp-port:api.example.test:8443",EntityID:"api.example.test",Type:evidence.TypeTCPPort,Value:`{"target":"api.example.test","protocol":"tcp","port":8443,"state":"open"}`}
	obs:=[]evidence.Observation{
		{ID:"obs-1",EvidenceID:e1.ID,ObservedAt:start.Add(time.Second)},
		{ID:"obs-2",EvidenceID:e2.ID,ObservedAt:start.Add(time.Hour+time.Second)},
	}
	first,err:=BuildSnapshot(run1,[]evidence.Evidence{e1,e2},obs);if err!=nil{t.Fatal(err)}
	second,err:=BuildSnapshot(run2,[]evidence.Evidence{e1,e2},obs);if err!=nil{t.Fatal(err)}
	if len(first.Records)!=1||first.Records[0].Key!= "TCP_PORT|api.example.test|00443"{t.Fatalf("unexpected first snapshot: %+v",first)}
	if len(second.Records)!=1||second.Records[0].Key!="TCP_PORT|api.example.test|08443"{t.Fatalf("unexpected second snapshot: %+v",second)}
	changes,err:=Compare(first,second);if err!=nil{t.Fatal(err)}
	if len(changes)!=2{t.Fatalf("got %d changes, want port add and remove: %+v",len(changes),changes)}
}

func TestSnapshotStoreRoundTripAndDeterministicTimeline(t *testing.T){
	store,err:=NewStore(filepath.Join(t.TempDir(),"history"));if err!=nil{t.Fatal(err)}
	at:=time.Date(2026,10,1,0,0,0,0,time.UTC)
	makeSnapshot:=func(id string,offset time.Duration)Snapshot{return Snapshot{RunID:id,Target:"example.test",Collector:"dns",CollectedAt:at.Add(offset),Records:[]Record{{Key:"DNS_ADDRESS|example.test|192.0.2.1",Type:evidence.TypeDNSAddress,EntityID:"example.test",ValueHash:"abc",EvidenceIDs:[]string{"e1"},ObservationIDs:[]string{"o1"},ObservedAt:at.Add(offset)}}}}
	s1:=makeSnapshot("dns-1",0);s2:=makeSnapshot("dns-2",time.Hour);s2.Records=[]Record{{Key:"DNS_ADDRESS|example.test|192.0.2.2",Type:evidence.TypeDNSAddress,EntityID:"example.test",ValueHash:"def",EvidenceIDs:[]string{"e2"},ObservationIDs:[]string{"o2"},ObservedAt:at.Add(time.Hour)}}
	if err:=store.Save(s2);err!=nil{t.Fatal(err)};if err:=store.Save(s1);err!=nil{t.Fatal(err)}
	got,err:=store.List();if err!=nil{t.Fatal(err)}
	if len(got)!=2||got[0].RunID!="dns-1"||got[1].RunID!="dns-2"{t.Fatalf("unexpected snapshot order: %+v",got)}
	timeline,err:=BuildTimeline(got);if err!=nil{t.Fatal(err)}
	if len(timeline.Changes)!=2{t.Fatalf("unexpected timeline changes: %+v",timeline.Changes)}
	if !reflect.DeepEqual(timeline.Changes[0].Type,ChangeAdded){t.Fatalf("first change = %s",timeline.Changes[0].Type)}
}

func TestBuildSnapshotRejectsFailedRuns(t *testing.T){
	run:=evidence.CollectionRun{ID:"dns-1",Target:"example.test",StartedAt:time.Now().Add(-time.Minute),FinishedAt:time.Now(),Status:evidence.CollectionRunFailed}
	if _,err:=BuildSnapshot(run,nil,nil);err==nil{t.Fatal("expected failed run to be rejected")}
}
