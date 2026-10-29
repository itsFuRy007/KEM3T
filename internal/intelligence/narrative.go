package intelligence

import (
	"fmt"
	"sort"
	"strings"
)

// ResearchNarrative is a deterministic, evidence-linked reading guide for an
// investigation. It organizes existing analytical results; it does not create
// new claims or change confidence assessments.
type ResearchNarrative struct {
	Summary     string              `json:"summary"`
	Signals     []NarrativeSignal   `json:"signals"`
	NextSteps   []NarrativeNextStep `json:"next_steps"`
	Limitations []string            `json:"limitations"`
}

// NarrativeSignal is one finding or analytical lead with explicit source links.
type NarrativeSignal struct {
	ID                      string   `json:"id"`
	Kind                    string   `json:"kind"`
	Summary                 string   `json:"summary"`
	Confidence              string   `json:"confidence"`
	AlternativeExplanations string   `json:"alternative_explanations,omitempty"`
	References              []string `json:"references"`
}

// NarrativeNextStep is an actionable verification task linked to the results
// that caused it to be recommended.
type NarrativeNextStep struct {
	ID         string   `json:"id"`
	Action     string   `json:"action"`
	Reason     string   `json:"reason"`
	References []string `json:"references"`
}

func (n ResearchNarrative) Validate() error {
	if strings.TrimSpace(n.Summary) == "" {
		return fmt.Errorf("narrative summary is required")
	}
	seen := make(map[string]struct{}, len(n.Signals)+len(n.NextSteps))
	for _, signal := range n.Signals {
		if strings.TrimSpace(signal.ID) == "" || strings.TrimSpace(signal.Kind) == "" || strings.TrimSpace(signal.Summary) == "" {
			return fmt.Errorf("narrative signal identity and summary are required")
		}
		if len(signal.References) == 0 {
			return fmt.Errorf("narrative signal %q has no source references", signal.ID)
		}
		if _, exists := seen[signal.ID]; exists {
			return fmt.Errorf("duplicate narrative item ID %q", signal.ID)
		}
		seen[signal.ID] = struct{}{}
		for _, ref := range signal.References {
			if strings.TrimSpace(ref) == "" {
				return fmt.Errorf("narrative signal %q contains an empty reference", signal.ID)
			}
		}
	}
	for _, step := range n.NextSteps {
		if strings.TrimSpace(step.ID) == "" || strings.TrimSpace(step.Action) == "" || strings.TrimSpace(step.Reason) == "" {
			return fmt.Errorf("narrative next step identity, action, and reason are required")
		}
		if len(step.References) == 0 {
			return fmt.Errorf("narrative next step %q has no source references", step.ID)
		}
		if _, exists := seen[step.ID]; exists {
			return fmt.Errorf("duplicate narrative item ID %q", step.ID)
		}
		seen[step.ID] = struct{}{}
		for _, ref := range step.References {
			if strings.TrimSpace(ref) == "" {
				return fmt.Errorf("narrative next step %q contains an empty reference", step.ID)
			}
		}
	}
	for _, limitation := range n.Limitations {
		if strings.TrimSpace(limitation) == "" {
			return fmt.Errorf("narrative limitations must not contain empty entries")
		}
	}
	return nil
}

type narrativeStepGroup struct {
	action string
	kind string
	reasons map[string]struct{}
	refs map[string]struct{}
}

// BuildResearchNarrative organizes report results into a stable investigation
// narrative. Every signal and suggested action points back to report objects,
// correlations, paths, or original evidence identifiers.
func BuildResearchNarrative(report IntelligenceReport) (ResearchNarrative, error) {
	target := normalizeFindingTarget(report.Target)
	if target == "" {
		return ResearchNarrative{}, fmt.Errorf("narrative report target is required")
	}

	n := ResearchNarrative{
		Signals: []NarrativeSignal{},
		NextSteps: []NarrativeNextStep{},
		Limitations: []string{
			"This narrative reorganizes existing report results; it does not independently verify them or increase their confidence.",
			"Correlations and multi-hop paths describe observed infrastructure relationships, not proof of common ownership, control, compromise, or vulnerability.",
			"Alternative explanations and contradictory verification evidence must be reviewed before drawing conclusions.",
			"References identify report objects and evidence IDs; consult their original records and observation timestamps before acting.",
		},
	}
	steps := make(map[string]*narrativeStepGroup)
	addSteps := func(kind, sourceID, reason string, actions []string) {
		for _, raw := range actions {
			action := strings.TrimSpace(raw)
			if action == "" {
				continue
			}
			key := kind + "\x00" + action
			group := steps[key]
			if group == nil {
				group = &narrativeStepGroup{action: action, kind: kind, reasons: make(map[string]struct{}), refs: make(map[string]struct{})}
				steps[key] = group
			}
			if strings.TrimSpace(reason) != "" {
				group.reasons[strings.TrimSpace(reason)] = struct{}{}
			}
			group.refs[kind+":"+sourceID] = struct{}{}
		}
	}

	correlationByID := make(map[string]Correlation, len(report.Correlations))
	for _, correlation := range report.Correlations {
		correlationByID[correlation.ID] = correlation
		refs := []string{"correlation:" + correlation.ID}
		refs = appendPrefixed(refs, "evidence", correlation.EvidenceIDs)
		refs = appendPrefixed(refs, "observation", correlation.ObservationIDs)
		n.Signals = append(n.Signals, NarrativeSignal{
			ID: "correlation:" + correlation.ID, Kind: "DIRECT_CORRELATION",
			Summary: correlation.Explanation, Confidence: correlation.Confidence + " (" + correlation.ConfidenceScope + ")",
			AlternativeExplanations: correlation.Limitations, References: stableUnique(refs),
		})
	}

	for _, discovery := range report.Discoveries {
		refs := appendPrefixed([]string{"discovery:" + discovery.ID}, "correlation", discovery.CorrelationIDs)
		for _, id := range discovery.CorrelationIDs {
			if correlation, ok := correlationByID[id]; ok {
				refs = appendPrefixed(refs, "evidence", correlation.EvidenceIDs)
				refs = appendPrefixed(refs, "observation", correlation.ObservationIDs)
			}
		}
		n.Signals = append(n.Signals, NarrativeSignal{
			ID: "discovery:" + discovery.ID, Kind: string(discovery.Type), Summary: discovery.Statement,
			Confidence: discovery.Confidence, AlternativeExplanations: discovery.AlternativeExplanations,
			References: stableUnique(refs),
		})
		addSteps("discovery", discovery.ID, discovery.WhyItMatters, discovery.Verification)
	}

	pathByID := make(map[string]DiscoveryPath, len(report.DiscoveryPaths))
	for _, path := range report.DiscoveryPaths {
		pathByID[path.ID] = path
		refs := appendPrefixed([]string{"path:" + path.ID}, "correlation", path.CorrelationIDs)
		for _, id := range path.CorrelationIDs {
			if correlation, ok := correlationByID[id]; ok {
				refs = appendPrefixed(refs, "evidence", correlation.EvidenceIDs)
				refs = appendPrefixed(refs, "observation", correlation.ObservationIDs)
			}
		}
		n.Signals = append(n.Signals, NarrativeSignal{
			ID: "path:" + path.ID, Kind: "MULTI_HOP_PATH", Summary: path.Statement,
			Confidence: path.Confidence, AlternativeExplanations: path.AlternativeExplanations,
			References: stableUnique(refs),
		})
		addSteps("path", path.ID, path.WhyItMatters, path.Verification)
	}

	for _, pivot := range report.DiscoveryPivots {
		refs := appendPrefixed([]string{"pivot:" + pivot.ID}, "path", pivot.PathIDs)
		for _, pathID := range pivot.PathIDs {
			if path, ok := pathByID[pathID]; ok {
				refs = appendPrefixed(refs, "correlation", path.CorrelationIDs)
			}
		}
		n.Signals = append(n.Signals, NarrativeSignal{
			ID: "pivot:" + pivot.ID, Kind: "RECURRING_PIVOT", Summary: pivot.Statement,
			Confidence: pivot.Confidence, AlternativeExplanations: pivot.AlternativeExplanations,
			References: stableUnique(refs),
		})
		addSteps("pivot", pivot.ID, pivot.WhyItMatters, pivot.Verification)
	}

	for _, hypothesis := range report.Hypotheses {
		refs := appendPrefixed([]string{"hypothesis:" + hypothesis.ID}, "evidence", hypothesis.SupportingIDs)
		n.Signals = append(n.Signals, NarrativeSignal{
			ID: "hypothesis:" + hypothesis.ID, Kind: "HYPOTHESIS", Summary: hypothesis.Statement,
			Confidence: string(hypothesis.Confidence), AlternativeExplanations: hypothesis.Alternative,
			References: stableUnique(refs),
		})
		addSteps("hypothesis", hypothesis.ID, hypothesis.Limitations, hypothesis.Verification)
	}

	for _, finding := range report.Findings {
		refs := []string{}
		for _, event := range finding.Evidence {
			refs = append(refs, "event:"+event.ID)
		}
		if len(refs) == 0 {
			continue
		}
		summary := finding.Fact
		if strings.TrimSpace(finding.Observation) != "" {
			summary += " " + strings.TrimSpace(finding.Observation)
		}
		n.Signals = append(n.Signals, NarrativeSignal{
			ID: "finding:" + strings.Join(stableUnique(append([]string(nil), refs...)), ";"), Kind: "FINDING", Summary: summary,
			Confidence: "SOURCE_PRIORITY:" + string(finding.Priority),
			AlternativeExplanations: finding.PossibleSignificance, References: stableUnique(refs),
		})
		addSteps("finding", finding.Title, "The source finding recommends these checks.", finding.NextSteps)
	}

	for _, assessment := range report.VerificationAssessments {
		refs := []string{"hypothesis:" + assessment.HypothesisID}
		refs = appendPrefixed(refs, "evidence", assessment.SupportingEvidenceIDs)
		refs = appendPrefixed(refs, "evidence", assessment.ContradictingEvidenceIDs)
		refs = appendPrefixed(refs, "evidence", assessment.ExcludedEvidenceIDs)
		n.Signals = append(n.Signals, NarrativeSignal{
			ID: "assessment:" + assessment.HypothesisID, Kind: "VERIFICATION_ASSESSMENT",
			Summary: string(assessment.Status) + ": " + assessment.Explanation,
			Confidence: "ASSESSMENT_STATUS:" + string(assessment.Status),
			AlternativeExplanations: assessment.Limitations, References: stableUnique(refs),
		})
		if assessment.Status == VerificationMixed || assessment.Status == VerificationContradicted {
			addSteps("assessment", assessment.HypothesisID,
				"Independent evidence conflicts with this hypothesis; resolve the contradiction before relying on it.",
				[]string{"Review the supporting and contradicting evidence side by side, compare their provenance and timestamps, and document which interpretation remains justified."})
		}
	}

	for _, gap := range report.IntelligenceGaps {
		refs := append([]string{gap.ID}, gap.References...)
		n.Signals = append(n.Signals, NarrativeSignal{
			ID: gap.ID, Kind: "INTELLIGENCE_GAP",
			Summary: gap.Unknown + " " + gap.WhyItMatters,
			Confidence: "UNRESOLVED_QUESTION:" + gap.Priority,
			AlternativeExplanations: gap.AlternativeExplanations,
			References: stableUnique(refs),
		})
		addSteps("intelligence-gap", gap.ID, gap.WhyItMatters, []string{gap.SuggestedAction})
	}

	sort.Slice(n.Signals, func(i, j int) bool {
		if n.Signals[i].Kind != n.Signals[j].Kind {
			return n.Signals[i].Kind < n.Signals[j].Kind
		}
		return n.Signals[i].ID < n.Signals[j].ID
	})
	keys := make([]string, 0, len(steps))
	for key := range steps {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for i, key := range keys {
		group := steps[key]
		refs := make([]string, 0, len(group.refs))
		for ref := range group.refs {
			refs = append(refs, ref)
		}
		sort.Strings(refs)
		reasons := make([]string, 0, len(group.reasons))
		for reason := range group.reasons {
			reasons = append(reasons, reason)
		}
		sort.Strings(reasons)
		reason := "Derived from " + group.kind + " results."
		if len(reasons) > 0 {
			reason += " " + strings.Join(reasons, " ")
		}
		n.NextSteps = append(n.NextSteps, NarrativeNextStep{
			ID: fmt.Sprintf("next-step:%03d", i+1), Action: group.action,
			Reason: reason, References: refs,
		})
	}

	n.Summary = fmt.Sprintf("Investigation of %s contains %d direct correlations, %d convergent discoveries, %d multi-hop paths, %d recurring pivots, %d hypotheses, %d findings, %d verification assessments, and %d explicit intelligence gaps. These are evidence-linked leads and observations, not automatic conclusions.",
		target, len(report.Correlations), len(report.Discoveries), len(report.DiscoveryPaths),
		len(report.DiscoveryPivots), len(report.Hypotheses), len(report.Findings), len(report.VerificationAssessments), len(report.IntelligenceGaps))
	if len(n.Signals) == 0 {
		n.Summary = "No evidence-backed signals or findings were available for investigation of " + target + "."
	}
	if err := n.Validate(); err != nil {
		return ResearchNarrative{}, fmt.Errorf("validate research narrative: %w", err)
	}
	return n, nil
}

func appendPrefixed(dst []string, prefix string, values []string) []string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			dst = append(dst, prefix+":"+value)
		}
	}
	return dst
}

func stableUnique(values []string) []string {
	sort.Strings(values)
	result := make([]string, 0, len(values))
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}
