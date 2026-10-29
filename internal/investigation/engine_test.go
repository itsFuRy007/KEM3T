package investigation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/itsFuRy007/kem3t/internal/evidence"
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
	engine:=Engine{Registry:registry,Stages:[]Stage{testStage{name:"dns"}}}
	result,err:=engine.Run(context.Background(),"example.com")
	if err!=nil { t.Fatal(err) }
	if result.Target!="example.com" || len(result.Graph.Nodes)!=2 || len(result.Graph.Edges)!=1 { t.Fatalf("unexpected graph: %+v",result.Graph) }
	if result.Report.Target!="example.com" { t.Fatalf("unexpected report target %q",result.Report.Target) }
	runs,err:=registry.CollectionRuns("example.com")
	if err!=nil || len(runs)!=1 || runs[0].Status!=evidence.CollectionRunCompleted { t.Fatalf("unexpected run history: %+v, %v",runs,err) }
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
