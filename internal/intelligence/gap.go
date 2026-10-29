package intelligence

import (
	"fmt"
	"sort"
	"strings"
)

// IntelligenceGap describes a specific unresolved question exposed by existing
// evidence. A gap is an investigation lead, never proof that a relationship or
// fact is absent.
type IntelligenceGap struct {
	ID                    string   `json:"id"`
	Kind                  string   `json:"kind"`
	Subject               string   `json:"subject"`
	Unknown               string   `json:"unknown"`
	WhyItMatters          string   `json:"why_it_matters"`
	RequiredEvidence      []string `json:"required_evidence"`
	SuggestedAction       string   `json:"suggested_action"`
	AlternativeExplanations string `json:"alternative_explanations"`
	Priority              string   `json:"priority"`
	References            []string `json:"references"`
}

func (g IntelligenceGap) Validate() error {
	if strings.TrimSpace(g.ID) == "" || strings.TrimSpace(g.Kind) == "" || strings.TrimSpace(g.Subject) == "" {
		return fmt.Errorf("intelligence gap identity and subject are required")
	}
	if strings.TrimSpace(g.Unknown) == "" || strings.TrimSpace(g.WhyItMatters) == "" || strings.TrimSpace(g.SuggestedAction) == "" {
		return fmt.Errorf("intelligence gap question, rationale, and action are required")
	}
	if len(g.RequiredEvidence) == 0 || len(g.References) == 0 {
		return fmt.Errorf("intelligence gap requires evidence types and source references")
	}
	if strings.TrimSpace(g.AlternativeExplanations) == "" {
		return fmt.Errorf("intelligence gap alternatives are required")
	}
	if g.Priority != "HIGH" && g.Priority != "MEDIUM" && g.Priority != "LOW" {
		return fmt.Errorf("intelligence gap priority must be HIGH, MEDIUM, or LOW")
	}
	for _, value := range append(append([]string{}, g.RequiredEvidence...), g.References...) {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("intelligence gap contains an empty evidence type or reference")
		}
	}
	return nil
}

// BuildIntelligenceGaps derives concrete unanswered questions from report
// objects. It does not infer missing facts from absent database records.
func BuildIntelligenceGaps(report IntelligenceReport) ([]IntelligenceGap, error) {
	target := normalizeFindingTarget(report.Target)
	if target == "" {
		return nil, fmt.Errorf("intelligence gap report target is required")
	}
	gaps := make([]IntelligenceGap, 0)
	correlationByID := make(map[string]Correlation, len(report.Correlations))
	for _, c := range report.Correlations {
		correlationByID[c.ID] = c
	}
	add := func(g IntelligenceGap) error {
		if err := g.Validate(); err != nil { return fmt.Errorf("validate gap %q: %w", g.ID, err) }
		g.RequiredEvidence = stableUnique(append([]string(nil), g.RequiredEvidence...))
		g.References = stableUnique(append([]string(nil), g.References...))
		gaps = append(gaps, g)
		return nil
	}

	for _, d := range report.Discoveries {
		refs := []string{"discovery:" + d.ID}
		for _, id := range d.CorrelationIDs {
			refs = append(refs, "correlation:"+id)
			if c, ok := correlationByID[id]; ok { refs = appendPrefixed(refs, "evidence", c.EvidenceIDs) }
		}
		if err := add(IntelligenceGap{
			ID: "gap:independent-confirmation:" + d.ID, Kind: "INDEPENDENT_CONFIRMATION",
			Subject: strings.Join(d.Entities, " <-> "),
			Unknown: "Whether the convergent signals reflect a meaningful relationship beyond shared infrastructure or collection-provider overlap.",
			WhyItMatters: "Different observed dimensions increase investigative value, but do not establish independent corroboration, ownership, or control.",
			RequiredEvidence: []string{"independently sourced network-ownership or organizational records", "direct service-level evidence with collection provenance"},
			SuggestedAction: "Seek an independently sourced ownership or service-level signal; compare its provenance and timestamps with every supporting correlation.",
			AlternativeExplanations: d.AlternativeExplanations, Priority: "MEDIUM", References: refs,
		}); err != nil { return nil, err }
	}

	for _, path := range report.DiscoveryPaths {
		direct := false
		for _, c := range report.Correlations {
			if containsEntity(c.Entities, path.Entities[0]) && containsEntity(c.Entities, path.Entities[2]) { direct = true; break }
		}
		if direct { continue }
		refs := []string{"path:" + path.ID}
		refs = appendPrefixed(refs, "correlation", path.CorrelationIDs)
		for _, id := range path.CorrelationIDs {
			if c, ok := correlationByID[id]; ok { refs = appendPrefixed(refs, "evidence", c.EvidenceIDs) }
		}
		if err := add(IntelligenceGap{
			ID: "gap:direct-edge:" + path.ID, Kind: "UNOBSERVED_DIRECT_EDGE",
			Subject: path.Entities[0] + " <-> " + path.Entities[2],
			Unknown: "No direct endpoint-to-endpoint correlation is present in this report; the observed connection currently exists only as a two-hop path.",
			WhyItMatters: "A direct signal could distinguish an endpoint relationship from two unrelated relationships joined by a shared intermediate entity. Its absence here is limited to this report's collected evidence.",
			RequiredEvidence: []string{"direct DNS, TLS, certificate-transparency, or other supported endpoint-level correlation", "timestamped evidence from a source independent of the two path hops"},
			SuggestedAction: "Investigate the two endpoints directly using authorized collection methods and preserve any new evidence IDs and observation timestamps.",
			AlternativeExplanations: path.AlternativeExplanations, Priority: "MEDIUM", References: refs,
		}); err != nil { return nil, err }
	}

	for _, pivot := range report.DiscoveryPivots {
		refs := []string{"pivot:" + pivot.ID}
		refs = appendPrefixed(refs, "path", pivot.PathIDs)
		for _, path := range report.DiscoveryPaths {
			if gapContainsString(pivot.PathIDs, path.ID) { refs = appendPrefixed(refs, "correlation", path.CorrelationIDs) }
		}
		if err := add(IntelligenceGap{
			ID: "gap:pivot-role:" + pivot.ID, Kind: "PIVOT_ROLE_AMBIGUITY",
			Subject: pivot.Pivot,
			Unknown: "Whether the recurring pivot represents a meaningful infrastructure dependency or a shared provider/service boundary.",
			WhyItMatters: "Resolving the pivot's role can prevent unrelated tenants or services from being treated as one infrastructure operator.",
			RequiredEvidence: []string{"network and hosting ownership context", "independent service fingerprint or organizational record"},
			SuggestedAction: "Identify the pivot's operator and service role independently, then reassess each path against that context.",
			AlternativeExplanations: pivot.AlternativeExplanations, Priority: "MEDIUM", References: refs,
		}); err != nil { return nil, err }
	}

	for _, a := range report.VerificationAssessments {
		if a.Status != VerificationMixed && a.Status != VerificationContradicted { continue }
		refs := []string{"hypothesis:" + a.HypothesisID}
		refs = appendPrefixed(refs, "evidence", a.SupportingEvidenceIDs)
		refs = appendPrefixed(refs, "evidence", a.ContradictingEvidenceIDs)
		refs = appendPrefixed(refs, "evidence", a.ExcludedEvidenceIDs)
		unknown := "Which interpretation remains justified after reconciling the independent supporting and contradicting records."
		if a.Status == VerificationContradicted { unknown = "Whether the original hypothesis should be revised or rejected in light of the independent contradicting evidence." }
		if err := add(IntelligenceGap{
			ID: "gap:verification-conflict:" + a.HypothesisID, Kind: "EVIDENCE_CONFLICT",
			Subject: a.HypothesisID, Unknown: unknown,
			WhyItMatters: "Conflicting evidence must remain visible; collapsing it into one conclusion would hide uncertainty and could misdirect further investigation.",
			RequiredEvidence: []string{"original source records and collection timestamps", "source methodology and provenance for each conflicting record"},
			SuggestedAction: "Review supporting and contradicting records side by side, reconcile source provenance and timestamps, and document any unresolved conflict.",
			AlternativeExplanations: a.Limitations, Priority: "HIGH", References: refs,
		}); err != nil { return nil, err }
	}

	sort.Slice(gaps, func(i, j int) bool { return gaps[i].ID < gaps[j].ID })
	return gaps, nil
}

func gapContainsString(values []string, wanted string) bool {
	for _, value := range values { if value == wanted { return true } }
	return false
}
