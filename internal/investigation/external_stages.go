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
	Lookup    func(context.Context, string, *evidence.Registry) (StageResult, error)
}

func (s FuncStage) Name() string { return strings.TrimSpace(s.StageName) }
func (s FuncStage) Run(ctx context.Context, target string, registry *evidence.Registry) (StageResult, error) {
	if ctx == nil {
		return StageResult{}, fmt.Errorf("context is required")
	}
	if err := ctx.Err(); err != nil {
		return StageResult{}, err
	}
	if registry == nil {
		return StageResult{}, fmt.Errorf("shared evidence registry is required")
	}
	if strings.TrimSpace(target) == "" {
		return StageResult{}, fmt.Errorf("target is required")
	}
	if s.Lookup == nil {
		return StageResult{}, fmt.Errorf("lookup function is required")
	}
	return s.Lookup(ctx, target, registry)
}

func stageLimitations(limitations []string, provider string, truncated bool) []string {
	result := append([]string(nil), limitations...)
	if truncated {
		result = append(result, provider+" response was truncated; the returned data is a partial provider view.")
	}
	return result
}

func NewCTStage() Stage { return NewCTStageWithClient(nil) }
func NewCTStageWithClient(client *externalintel.CTClient) Stage {
	if client == nil {
		client = &externalintel.CTClient{}
	}
	return FuncStage{StageName: "certificate-transparency", Lookup: func(ctx context.Context, target string, registry *evidence.Registry) (StageResult, error) {
		report, err := client.LookupDomain(ctx, target)
		if err != nil {
			return StageResult{}, err
		}
		count, err := externalintel.RegisterCTReport(registry, report, evidence.ObservationProvenanceFromContext(ctx))
		return StageResult{Evidence: count, Observations: count, Limitations: append([]string(nil), report.Limitations...)}, err
	}}
}

func NewRDAPDomainStage() Stage { return NewRDAPDomainStageWithClient(nil) }
func NewRDAPDomainStageWithClient(client *externalintel.RDAPClient) Stage {
	if client == nil {
		client = &externalintel.RDAPClient{}
	}
	return FuncStage{StageName: "rdap-domain", Lookup: func(ctx context.Context, target string, registry *evidence.Registry) (StageResult, error) {
		report, err := client.LookupDomain(ctx, target)
		if err != nil {
			return StageResult{}, err
		}
		registered, err := externalintel.RegisterRDAPReport(registry, report, evidence.ObservationProvenanceFromContext(ctx))
		count := 0
		if registered {
			count = 1
		}
		return StageResult{Evidence: count, Observations: count, Limitations: append([]string(nil), report.Limitations...)}, err
	}}
}

func NewPassiveDNSStage() Stage { return NewPassiveDNSStageWithClient(nil) }
func NewPassiveDNSStageWithClient(client *externalintel.PassiveDNSClient) Stage {
	if client == nil {
		client = &externalintel.PassiveDNSClient{}
	}
	return FuncStage{StageName: "passive-dns", Lookup: func(ctx context.Context, target string, registry *evidence.Registry) (StageResult, error) {
		report, err := client.LookupDomain(ctx, target)
		if err != nil {
			return StageResult{}, err
		}
		count, err := externalintel.RegisterPassiveDNSReport(registry, report, evidence.ObservationProvenanceFromContext(ctx))
		return StageResult{Evidence: count, Observations: count, Limitations: stageLimitations(report.Limitations, "Passive DNS", report.Truncated)}, err
	}}
}

func NewThreatIntelStage() Stage { return NewThreatIntelStageWithClient(nil) }
func NewThreatIntelStageWithClient(client *externalintel.ThreatIntelClient) Stage {
	if client == nil {
		client = &externalintel.ThreatIntelClient{}
	}
	return FuncStage{StageName: "threat-intelligence", Lookup: func(ctx context.Context, target string, registry *evidence.Registry) (StageResult, error) {
		report, err := client.Lookup(ctx, target)
		if err != nil {
			return StageResult{}, err
		}
		registered, err := externalintel.RegisterThreatIntelReport(registry, report, evidence.ObservationProvenanceFromContext(ctx))
		count := 0
		if registered {
			count = 1
		}
		return StageResult{Evidence: count, Observations: count, Limitations: stageLimitations(report.Limitations, "Threat-intelligence", report.Truncated)}, err
	}}
}

func NewIPRDAPStage() Stage { return NewIPRDAPStageWithClient(nil) }
func NewIPRDAPStageWithClient(client *externalintel.RDAPClient) Stage {
	if client == nil {
		client = &externalintel.RDAPClient{}
	}
	return FuncStage{StageName: "rdap-ip", Lookup: func(ctx context.Context, target string, registry *evidence.Registry) (StageResult, error) {
		report, err := client.LookupIP(ctx, target)
		if err != nil {
			return StageResult{}, err
		}
		registered, err := externalintel.RegisterIPRDAPReport(registry, report, evidence.ObservationProvenanceFromContext(ctx))
		count := 0
		if registered {
			count = 1
		}
		return StageResult{Evidence: count, Observations: count, Limitations: append([]string(nil), report.Limitations...)}, err
	}}
}

func NewASNStage() Stage { return NewASNStageWithClient(nil) }
func NewASNStageWithClient(client *externalintel.ASNClient) Stage {
	if client == nil {
		client = &externalintel.ASNClient{}
	}
	return FuncStage{StageName: "asn", Lookup: func(ctx context.Context, target string, registry *evidence.Registry) (StageResult, error) {
		report, err := client.LookupIP(ctx, target)
		if err != nil {
			return StageResult{}, err
		}
		registered, err := externalintel.RegisterASNReport(registry, report, evidence.ObservationProvenanceFromContext(ctx))
		count := 0
		if registered {
			count = 1
		}
		return StageResult{Evidence: count, Observations: count, Limitations: append([]string(nil), report.Limitations...)}, err
	}}
}

// NewIPRDAPStageForIP queries RDAP for one caller-authorized IP address.
// It is suitable for a planner that has independently checked an explicit
// IP allowlist; DNS discovery alone must not authorize this pivot.
func NewIPRDAPStageForIP(ip string) Stage {
	client := &externalintel.RDAPClient{}
	return FuncStage{StageName: "rdap-ip:" + ip, Lookup: func(ctx context.Context, _ string, registry *evidence.Registry) (StageResult, error) {
		report, err := client.LookupIP(ctx, ip)
		if err != nil {
			return StageResult{}, err
		}
		registered, err := externalintel.RegisterIPRDAPReport(registry, report, evidence.ObservationProvenanceFromContext(ctx))
		count := 0
		if registered {
			count = 1
		}
		return StageResult{Evidence: count, Observations: count, Limitations: append([]string(nil), report.Limitations...)}, err
	}}
}

// NewASNStageForIP queries origin/ASN intelligence for one caller-authorized
// IP address. The planner/caller remains responsible for enforcing scope.
func NewASNStageForIP(ip string) Stage {
	client := &externalintel.ASNClient{}
	return FuncStage{StageName: "asn:" + ip, Lookup: func(ctx context.Context, _ string, registry *evidence.Registry) (StageResult, error) {
		report, err := client.LookupIP(ctx, ip)
		if err != nil {
			return StageResult{}, err
		}
		registered, err := externalintel.RegisterASNReport(registry, report, evidence.ObservationProvenanceFromContext(ctx))
		count := 0
		if registered {
			count = 1
		}
		return StageResult{Evidence: count, Observations: count, Limitations: append([]string(nil), report.Limitations...)}, err
	}}
}
