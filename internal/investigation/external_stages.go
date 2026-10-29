package investigation

import (
	"context"
	"fmt"
	"strings"

	"github.com/itsFuRy007/kem3t/internal/evidence"
	"github.com/itsFuRy007/kem3t/internal/externalintel"
)

// FuncStage adapts a bounded external-intelligence lookup to the shared
// investigation registry without introducing a second persistence path.
type FuncStage struct {
	StageName string
	Lookup func(context.Context, string, *evidence.Registry) (StageResult, error)
}

func (s FuncStage) Name() string { return strings.TrimSpace(s.StageName) }
func (s FuncStage) Run(ctx context.Context, target string, registry *evidence.Registry) (StageResult, error) {
	if ctx == nil { return StageResult{}, fmt.Errorf("context is required") }
	if err := ctx.Err(); err != nil { return StageResult{}, err }
	if registry == nil { return StageResult{}, fmt.Errorf("shared evidence registry is required") }
	if strings.TrimSpace(target) == "" { return StageResult{}, fmt.Errorf("target is required") }
	if s.Lookup == nil { return StageResult{}, fmt.Errorf("lookup function is required") }
	return s.Lookup(ctx, target, registry)
}

func NewCTStage() Stage { return NewCTStageWithClient(nil) }
func NewCTStageWithClient(client *externalintel.CTClient) Stage {
	if client == nil { client = &externalintel.CTClient{} }
	return FuncStage{StageName:"certificate-transparency", Lookup:func(ctx context.Context,target string,registry *evidence.Registry)(StageResult,error){
		report,err:=client.LookupDomain(ctx,target); if err!=nil{return StageResult{},err}
		count,err:=externalintel.RegisterCTReport(registry,report); return StageResult{Evidence:count,Observations:count},err
	}}
}

func NewRDAPDomainStage() Stage { return NewRDAPDomainStageWithClient(nil) }
func NewRDAPDomainStageWithClient(client *externalintel.RDAPClient) Stage {
	if client == nil { client = &externalintel.RDAPClient{} }
	return FuncStage{StageName:"rdap-domain", Lookup:func(ctx context.Context,target string,registry *evidence.Registry)(StageResult,error){
		report,err:=client.LookupDomain(ctx,target); if err!=nil{return StageResult{},err}
		registered,err:=externalintel.RegisterRDAPReport(registry,report); count:=0; if registered {count=1}
		return StageResult{Evidence:count,Observations:count},err
	}}
}

func NewPassiveDNSStage() Stage { return NewPassiveDNSStageWithClient(nil) }
func NewPassiveDNSStageWithClient(client *externalintel.PassiveDNSClient) Stage {
	if client == nil { client = &externalintel.PassiveDNSClient{} }
	return FuncStage{StageName:"passive-dns", Lookup:func(ctx context.Context,target string,registry *evidence.Registry)(StageResult,error){
		report,err:=client.LookupDomain(ctx,target); if err!=nil{return StageResult{},err}
		count,err:=externalintel.RegisterPassiveDNSReport(registry,report); return StageResult{Evidence:count,Observations:count},err
	}}
}

func NewThreatIntelStage() Stage { return NewThreatIntelStageWithClient(nil) }
func NewThreatIntelStageWithClient(client *externalintel.ThreatIntelClient) Stage {
	if client == nil { client = &externalintel.ThreatIntelClient{} }
	return FuncStage{StageName:"threat-intelligence", Lookup:func(ctx context.Context,target string,registry *evidence.Registry)(StageResult,error){
		report,err:=client.Lookup(ctx,target); if err!=nil{return StageResult{},err}
		registered,err:=externalintel.RegisterThreatIntelReport(registry,report); count:=0; if registered {count=1}
		return StageResult{Evidence:count,Observations:count},err
	}}
}

func NewIPRDAPStage() Stage { return NewIPRDAPStageWithClient(nil) }
func NewIPRDAPStageWithClient(client *externalintel.RDAPClient) Stage {
	if client == nil { client = &externalintel.RDAPClient{} }
	return FuncStage{StageName:"rdap-ip", Lookup:func(ctx context.Context,target string,registry *evidence.Registry)(StageResult,error){
		report,err:=client.LookupIP(ctx,target); if err!=nil{return StageResult{},err}
		registered,err:=externalintel.RegisterIPRDAPReport(registry,report); count:=0; if registered {count=1}
		return StageResult{Evidence:count,Observations:count},err
	}}
}

func NewASNStage() Stage { return NewASNStageWithClient(nil) }
func NewASNStageWithClient(client *externalintel.ASNClient) Stage {
	if client == nil { client = &externalintel.ASNClient{} }
	return FuncStage{StageName:"asn", Lookup:func(ctx context.Context,target string,registry *evidence.Registry)(StageResult,error){
		report,err:=client.LookupIP(ctx,target); if err!=nil{return StageResult{},err}
		registered,err:=externalintel.RegisterASNReport(registry,report); count:=0; if registered {count=1}
		return StageResult{Evidence:count,Observations:count},err
	}}
}
