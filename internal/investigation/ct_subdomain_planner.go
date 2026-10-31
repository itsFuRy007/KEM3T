package investigation

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/itsFuRy007/kem3t/internal/evidence"
	"github.com/itsFuRy007/kem3t/internal/intelligence"
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
	if reportTarget := normalizeEntity(state.Report.Target); reportTarget != "" && reportTarget != root {
		return nil, fmt.Errorf("planner intelligence report target %q does not match investigation target %q", reportTarget, root)
	}
	priorityByEvidenceID := make(map[string]int)
	for _, hypothesis := range state.Report.Hypotheses {
		priority := 0
		switch hypothesis.Confidence {
		case intelligence.HypothesisConfidenceHigh:
			priority = 3
		case intelligence.HypothesisConfidenceModerate:
			priority = 2
		case intelligence.HypothesisConfidenceLow:
			priority = 1
		}
		for _, evidenceID := range hypothesis.SupportingIDs {
			if priority > priorityByEvidenceID[evidenceID] {
				priorityByEvidenceID[evidenceID] = priority
			}
		}
	}
	limit := 8
	if p != nil && p.MaxSubdomains > 0 {
		limit = p.MaxSubdomains
	}
	if limit > 16 {
		limit = 16
	}
	known := make(map[string]struct{})
	for _, name := range state.Scheduled {
		if strings.HasPrefix(name, "dns-subdomain:") {
			known[strings.TrimPrefix(name, "dns-subdomain:")] = struct{}{}
		}
	}
	for _, outcome := range state.Completed {
		if strings.HasPrefix(outcome.Name, "dns-subdomain:") {
			known[strings.TrimPrefix(outcome.Name, "dns-subdomain:")] = struct{}{}
		}
	}
	used := len(known)
	candidatePriority := make(map[string]int)
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
		if priority := priorityByEvidenceID[item.ID]; priority > candidatePriority[name] {
			candidatePriority[name] = priority
		}
	}
	names := make([]string, 0, len(candidatePriority))
	for name := range candidatePriority {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		if candidatePriority[names[i]] != candidatePriority[names[j]] {
			return candidatePriority[names[i]] > candidatePriority[names[j]]
		}
		return names[i] < names[j]
	})
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
	if omitted := candidateCount - len(names); omitted > 0 && state.Limitations != nil {
		*state.Limitations = append(*state.Limitations, fmt.Sprintf(
			"CT expansion discovered %d new in-scope candidate name(s), but the per-investigation DNS cap is %d and %d candidate name(s) were not queried. Names supported by stronger intelligence hypotheses are prioritized first; remaining ties are ordered lexicographically.",
			candidateCount,
			limit,
			omitted,
		))
	}
	return stages, nil
}
