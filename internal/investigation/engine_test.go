package investigation

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/itsFuRy007/kem3t/internal/evidence"
	"github.com/itsFuRy007/kem3t/internal/history"
)

type testStage struct {
	name string
	err error
}

func (s testStage) Name() string { return s.name }
func (s testStage) Run(ctx context.Context, target string, registry *evidence.Registry) (StageResult, error) {
	if s.err != nil { return StageResult{}, s.err }
	item := evidence.Evidence{ID:"dns-evidence-1", EntityID:target, Type:evidence.TypeDNSAddress, Value:"203.0.113.10"}
	if err:=registry.AddEvidence(item); err!=nil && !errors.Is(err,evidence.ErrEvidenceExists) { return StageResult{},err }
	observation:=evidence.Observation{ID:"dns-observation-1",EvidenceID:item.ID,Source:"test-stage",ObservedAt:time.Date(2026,1,1,0,0,0,0,time.UTC),EventIDs:[]string{"event-1"}}
	if err:=registry.AddObservation(observation); err!=nil && !errors.Is(err,evidence.ErrObservationExists) { return StageResult{},err }
	return StageResult{Events:1,Evidence:1,Observations:1},nil
}

func TestEngineUsesOneRegistryForGraphAndReport(t *testing.T) {
	registry:=evidence.NewRegistry()
	snapshotDir:=t.TempDir()
	engine:=Engine{Registry:registry,Stages:[]Stage{testStage{name:"dns"}},SnapshotDir:snapshotDir,Now:func()time.Time{return time.Date(2026,1,1,0,0,0,0,time.UTC)}}
	result,err:=engine.Run(context.Background(),"example.com")
	if err!=nil { t.Fatal(err) }
	if !result.HistoryPersisted { t.Fatal("expected completed investigation history snapshot to be persisted") }
	if result.Target!="example.com" || len(result.Graph.Nodes)!=2 || len(result.Graph.Edges)!=1 { t.Fatalf("unexpected graph: %+v",result.Graph) }
	if result.Report.Target!="example.com" { t.Fatalf("unexpected report target %q",result.Report.Target) }
	runs,err:=registry.CollectionRuns("example.com")
	if err!=nil || len(runs)!=1 || runs[0].Status!=evidence.CollectionRunCompleted { t.Fatalf("unexpected run history: %+v, %v",runs,err) }
	store,err:=history.NewStore(filepath.Join(snapshotDir,"history")); if err!=nil {t.Fatal(err)}
	snapshots,err:=store.List(); if err!=nil||len(snapshots)!=1||snapshots[0].Collector!="investigation"||len(snapshots[0].Records)!=1 {t.Fatalf("unified history snapshot was not persisted: %+v, %v",snapshots,err)}
}

func TestEnginePreservesSuccessfulEvidenceWhenStageFails(t *testing.T) {
	registry:=evidence.NewRegistry()
	engine:=Engine{Registry:registry,Stages:[]Stage{testStage{name:"dns"},testStage{name:"optional-source",err:errors.New("source unavailable")}}}
	result,err:=engine.Run(context.Background(),"example.com")
	if err!=nil { t.Fatalf("partial source failure should preserve usable result: %v",err) }
	if !result.Partial || len(result.Stages)!=2 || result.Stages[1].Error=="" { t.Fatalf("failure was not represented: %+v",result.Stages) }
	if len(result.Graph.Edges)!=1 { t.Fatalf("successful evidence was lost: %+v",result.Graph) }
}

func TestEngineRejectsCanceledContextBeforeStartingRun(t *testing.T) {
	ctx,cancel:=context.WithCancel(context.Background());cancel()
	registry:=evidence.NewRegistry()
	_,err:=(&Engine{Registry:registry,Stages:[]Stage{testStage{name:"dns"}}}).Run(ctx,"example.com")
	if !errors.Is(err,context.Canceled) { t.Fatalf("expected cancellation, got %v",err) }
	runs,_:=registry.CollectionRuns("example.com")
	if len(runs)!=0 { t.Fatalf("canceled run should not be persisted: %+v",runs) }
}

func TestEngineAcceptsSuccessfulEmptyLookup(t *testing.T) {
	registry:=evidence.NewRegistry()
	stage:=FuncStage{StageName:"empty-source",Lookup:func(context.Context,string,*evidence.Registry)(StageResult,error){return StageResult{Limitations:[]string{"source returned no records"}},nil}}
	result,err:=(&Engine{Registry:registry,Stages:[]Stage{stage}}).Run(context.Background(),"example.com")
	if err!=nil {t.Fatal(err)}
	if result.Partial {t.Fatal("successful empty lookup must not be marked partial")}
	if result.Report.Target!="example.com" {t.Fatalf("missing target-scoped report: %+v",result.Report)}
	runs,err:=registry.CollectionRuns("example.com")
	if err!=nil||len(runs)!=1||runs[0].Status!=evidence.CollectionRunCompleted {t.Fatalf("empty successful run should be completed: %+v, %v",runs,err)}
}

type fixedResolver struct{}
func (fixedResolver) LookupIPAddr(context.Context,string)([]net.IPAddr,error) {
	return []net.IPAddr{{IP:net.ParseIP("203.0.113.25")}},nil
}

func TestEngineIntegratesExistingDNSCollectorEndToEnd(t *testing.T) {
	registry:=evidence.NewRegistry()
	engine:=Engine{Registry:registry,Stages:[]Stage{NewDNSStageWithResolver("example.com",fixedResolver{})}}
	result,err:=engine.Run(context.Background(),"example.com")
	if err!=nil {t.Fatal(err)}
	if len(registry.AllEvidence())!=1||len(registry.AllObservations())!=1 {t.Fatalf("DNS collector output missing from shared registry")}
	if len(result.Graph.Nodes)!=2||len(result.Graph.Edges)!=1 {t.Fatalf("unexpected integrated graph: %+v",result.Graph)}
	if result.Report.Target!="example.com" {t.Fatalf("unexpected intelligence report: %+v",result.Report)}
	if len(result.Stages)!=1||result.Stages[0].Result.Evidence!=1 {t.Fatalf("unexpected stage outcome: %+v",result.Stages)}
}

type plannerFunc func(context.Context,PlanningState)([]Stage,error)
func (f plannerFunc) Next(ctx context.Context,state PlanningState)([]Stage,error){return f(ctx,state)}

func TestEnginePlansNextStageFromNewEvidence(t *testing.T) {
	registry:=evidence.NewRegistry()
	plannerCalls:=0
	next:=FuncStage{StageName:"evidence-follow-up",Lookup:func(_ context.Context,_ string,r *evidence.Registry)(StageResult,error){
		if len(r.AllEvidence())==0 {t.Fatal("planner scheduled follow-up without evidence")}
		return StageResult{Limitations:[]string{"follow-up is a bounded test stage"}},nil
	}}
	planner:=plannerFunc(func(_ context.Context,state PlanningState)([]Stage,error){
		plannerCalls++
		if plannerCalls==1 && len(state.Evidence)==1 {return []Stage{next},nil}
		return nil,nil
	})
	engine:=Engine{Registry:registry,Stages:[]Stage{testStage{name:"dns"}},Planner:planner,MaxStages:3}
	result,err:=engine.Run(context.Background(),"example.com")
	if err!=nil {t.Fatal(err)}
	if len(result.Stages)!=2||result.Stages[1].Name!="evidence-follow-up" {t.Fatalf("adaptive stage was not executed: %+v",result.Stages)}
	if plannerCalls!=2 {t.Fatalf("planner should be consulted after each completed stage; got %d calls",plannerCalls)}
}

func TestEngineRejectsAdaptivePlanThatExceedsStageLimit(t *testing.T) {
	registry:=evidence.NewRegistry()
	planner:=plannerFunc(func(context.Context,PlanningState)([]Stage,error){
		return []Stage{FuncStage{StageName:"follow-up-a",Lookup:func(context.Context,string,*evidence.Registry)(StageResult,error){return StageResult{},nil}},FuncStage{StageName:"follow-up-b",Lookup:func(context.Context,string,*evidence.Registry)(StageResult,error){return StageResult{},nil}}},nil
	})
	result,err:=(&Engine{Registry:registry,Stages:[]Stage{testStage{name:"dns"}},Planner:planner,MaxStages:2}).Run(context.Background(),"example.com")
	if err==nil {t.Fatal("expected adaptive stage limit error")}
	if !result.Partial {t.Fatal("stage limit error should be marked partial")}
	runs,loadErr:=registry.CollectionRuns("example.com")
	if loadErr!=nil||len(runs)!=1||runs[0].ErrorMessage=="" {t.Fatalf("planner failure missing from collection history: %+v, %v",runs,loadErr)}
}

func TestEngineGraphExcludesUnrelatedTargetsFromSharedRegistry(t *testing.T) {
	registry:=evidence.NewRegistry()
	unrelated:=evidence.Evidence{ID:"dns-address:other.example:198.51.100.9",EntityID:"other.example",Type:evidence.TypeDNSAddress,Value:"198.51.100.9"}
	if err:=registry.AddEvidence(unrelated);err!=nil {t.Fatal(err)}
	if err:=registry.AddObservation(evidence.Observation{ID:"other-observation",EvidenceID:unrelated.ID,Source:"test",ObservedAt:time.Date(2026,1,1,0,0,0,0,time.UTC),EventIDs:[]string{"other-event"}});err!=nil {t.Fatal(err)}
	result,err:=(&Engine{Registry:registry,Stages:[]Stage{testStage{name:"dns"}}}).Run(context.Background(),"example.com")
	if err!=nil {t.Fatal(err)}
	for _,node:=range result.Graph.Nodes {
		if node.Value=="other.example"||node.Value=="198.51.100.9" {t.Fatalf("unrelated target leaked into investigation graph: %+v",node)}
	}
	if len(result.Graph.Nodes)!=2 {t.Fatalf("expected only target domain and linked IP, got %+v",result.Graph.Nodes)}
}

func TestEngineMarksRunFailedWhenHistorySnapshotPersistenceFails(t *testing.T) {
	snapshotPath := filepath.Join(t.TempDir(), "history-is-a-file")
	if err := os.WriteFile(snapshotPath, []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	registry := evidence.NewRegistry()
	result, err := (&Engine{Registry: registry, Stages: []Stage{testStage{name: "dns"}}, SnapshotDir: snapshotPath}).Run(context.Background(), "example.com")
	if err == nil || !strings.Contains(err.Error(), "persist unified investigation history") {
		t.Fatalf("expected history persistence error, got %v", err)
	}
	if !result.Partial || result.HistoryPersisted {
		t.Fatalf("failed history persistence must be partial and unpersisted: %+v", result)
	}
	runs, loadErr := registry.CollectionRuns("example.com")
	if loadErr != nil || len(runs) != 1 {
		t.Fatalf("expected one finalized run, got %+v, %v", runs, loadErr)
	}
	if runs[0].Status != evidence.CollectionRunFailed || !strings.Contains(runs[0].ErrorMessage, "persist unified investigation history") {
		t.Fatalf("history persistence failure was not reflected in run status: %+v", runs[0])
	}
}
