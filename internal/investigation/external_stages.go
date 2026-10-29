package investigation

import (
	"context"
	"fmt"

	"github.com/itsFuRy007/kem3t/internal/evidence"
	"github.com/itsFuRy007/kem3t/internal/externalintel"
)

// FuncStage adapts a bounded external-intelligence lookup to the shared
// investigation registry without introducing a second persistence path.
type FuncStage struct {
	StageName string
	Lookup func(context.Context, string, *evidence.Registry) (StageResult, error)
}

func (s FuncStage) Name() string { return s.StageName }
func (s FuncStage) Run(ctx context.Context, target string, registry *evidence.Registry) (StageResult, error) {
	if ctx == nil { return StageResult{}, fmt.Errorf("context is required") }
	if registry == nil { return StageResult{}, fmt.Errorf("shared evidence registry is required") }
	if s.Lookup == nil { return StageResult{}, fmt.Errorf("lookup function is required") }
	return s.Lookup(ctx, target, registry)
}

func NewCTStage() Stage {
	return FuncStage{StageName:"certificate-transparency", Lookup:func(ctx context.Context,target string,registry *evidence.Registry)(StageResult,error){
		report,err:=(&externalintel.CTClient{}).LookupDomain(ctx,target); if err!=nil{return StageResult{},err}
		count,err:=externalintel.RegisterCTReport(registry,report); return StageResult{Evidence:count,Observations:count},err
	}}
}

func NewRDAPDomainStage() Stage {
	return FuncStage{StageName:"rdap-domain", Lookup:func(ctx context.Context,target string,registry *evidence.Registry)(StageResult,error){
		report,err:=(&externalintel.RDAPClient{}).LookupDomain(ctx,target); if err!=nil{return StageResult{},err}
		registered,err:=externalintel.RegisterRDAPReport(registry,report); count:=0; if registered {count=1}
		return StageResult{Evidence:count,Observations:count},err
	}}
}

func NewPassiveDNSStage() Stage {
	return FuncStage{StageName:"passive-dns", Lookup:func(ctx context.Context,target string,registry *evidence.Registry)(StageResult,error){
		report,err:=(&externalintel.PassiveDNSClient{}).LookupDomain(ctx,target); if err!=nil{return StageResult{},err}
		count,err:=externalintel.RegisterPassiveDNSReport(registry,report); return StageResult{Evidence:count,Observations:count},err
	}}
}

func NewThreatIntelStage() Stage {
	return FuncStage{StageName:"threat-intelligence", Lookup:func(ctx context.Context,target string,registry *evidence.Registry)(StageResult,error){
		report,err:=(&externalintel.ThreatIntelClient{}).Lookup(ctx,target); if err!=nil{return StageResult{},err}
		registered,err:=externalintel.RegisterThreatIntelReport(registry,report); count:=0; if registered {count=1}
		return StageResult{Evidence:count,Observations:count},err
	}}
}

func NewIPRDAPStage() Stage {
	return FuncStage{StageName:"rdap-ip", Lookup:func(ctx context.Context,target string,registry *evidence.Registry)(StageResult,error){
		report,err:=(&externalintel.RDAPClient{}).LookupIP(ctx,target); if err!=nil{return StageResult{},err}
		registered,err:=externalintel.RegisterIPRDAPReport(registry,report); count:=0; if registered {count=1}
		return StageResult{Evidence:count,Observations:count},err
	}}
}

func NewASNStage() Stage {
	return FuncStage{StageName:"asn", Lookup:func(ctx context.Context,target string,registry *evidence.Registry)(StageResult,error){
		report,err:=(&externalintel.ASNClient{}).LookupIP(ctx,target); if err!=nil{return StageResult{},err}
		registered,err:=externalintel.RegisterASNReport(registry,report); count:=0; if registered {count=1}
		return StageResult{Evidence:count,Observations:count},err
	}}
}
