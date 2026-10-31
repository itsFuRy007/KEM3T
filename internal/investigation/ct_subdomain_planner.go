package investigation

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/itsFuRy007/kem3t/internal/evidence"
)

// CTSubdomainDNSPlanner schedules bounded DNS resolution for names newly
// discovered in Certificate Transparency evidence. It never schedules active
// port/service checks and never leaves the root domain's namespace.
type CTSubdomainDNSPlanner struct {
	MaxSubdomains int
}

func NewCTSubdomainDNSPlanner(maxSubdomains int) *CTSubdomainDNSPlanner {
	if maxSubdomains <= 0 {
		maxSubdomains = 8
	}
	if maxSubdomains > 16 {
		maxSubdomains = 16
	}
	return &CTSubdomainDNSPlanner{MaxSubdomains: maxSubdomains}
}

func (p *CTSubdomainDNSPlanner) Next(ctx context.Context, state PlanningState) ([]Stage, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root := normalizeEntity(state.Target)
	if !evidence.IsValidDomain(root) {
		return nil, nil
	}
	limit := 8
	if p != nil && p.MaxSubdomains > 0 {
		limit = p.MaxSubdomains
	}
	if limit > 16 {
		limit = 16
	}
	known := make(map[string]struct{})
	used := 0
	for _, name := range state.Scheduled {
		if strings.HasPrefix(name, "dns-subdomain:") {
			known[strings.TrimPrefix(name, "dns-subdomain:")] = struct{}{}
			used++
		}
	}
	for _, outcome := range state.Completed {
		if strings.HasPrefix(outcome.Name, "dns-subdomain:") {
			known[strings.TrimPrefix(outcome.Name, "dns-subdomain:")] = struct{}{}
			used++
		}
	}
	candidates := make(map[string]struct{})
	for _, item := range state.NewEvidence {
		if item.Type != evidence.TypeCTDNSName {
			continue
		}
		var details evidence.CTDNSNameDetails
		if err := json.Unmarshal([]byte(item.Value), &details); err != nil {
			return nil, fmt.Errorf("decode CT DNS-name evidence %q: %w", item.ID, err)
		}
		name := normalizeEntity(details.DNSName)
		if name == "" || name == root || !evidence.IsValidDomain(name) || !withinDomainScope(name, root) {
			continue
		}
		if _, exists := known[name]; exists {
			continue
		}
		candidates[name] = struct{}{}
	}
	names := make([]string, 0, len(candidates))
	for name := range candidates {
		names = append(names, name)
	}
	sort.Strings(names)
	remaining := limit - used
	if remaining < 0 {
		remaining = 0
	}
	candidateCount := len(names)
	if candidateCount > remaining {
		names = names[:remaining]
	}
	stages := make([]Stage, 0, len(names))
	for _, name := range names {
		stages = append(stages, NewDNSSubdomainStage(name))
	}
	if omitted := candidateCount - len(names); omitted > 0 && len(stages) > 0 {
		limitation := fmt.Sprintf(
			"CT returned %d additional in-scope names; DNS expansion is capped at %d names per investigation, so %d names were not queried. Selected names are ordered lexicographically.",
			candidateCount+used,
			limit,
			omitted,
		)
		last := stages[len(stages)-1]
		stages[len(stages)-1] = limitedStage{Stage: last, limitation: limitation}
	}
	return stages, nil
}

type limitedStage struct {
	Stage
	limitation string
}

func (s limitedStage) Run(ctx context.Context, target string, registry *evidence.Registry) (StageResult, error) {
	result, err := s.Stage.Run(ctx, target, registry)
	result.Limitations = append(result.Limitations, s.limitation)
	return result, err
}
