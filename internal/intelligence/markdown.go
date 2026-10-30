package intelligence

import (
	"fmt"
	"sort"
	"strings"

	"github.com/itsFuRy007/kem3t/internal/events"
)

// RenderMarkdownReport renders a researcher-oriented dossier from an existing
// IntelligenceReport. It presents derived analysis without creating new claims
// or changing confidence, and keeps report-object and evidence references visible.
func RenderMarkdownReport(report IntelligenceReport) (string, error) {
	target := normalizeFindingTarget(report.Target)
	if target == "" {
		return "", fmt.Errorf("markdown report target is required")
	}
	if strings.TrimSpace(report.Narrative.Summary) != "" {
		if err := report.Narrative.Validate(); err != nil {
			return "", fmt.Errorf("validate report narrative: %w", err)
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# KEM3T Intelligence Dossier\n\n**Target:** %s\n\n", mdCode(target))
	b.WriteString("> This dossier organizes collected observations and derived analysis. Correlations, discoveries, paths, pivots, and hypotheses are investigation leads—not proof of ownership, control, compromise, maliciousness, or vulnerability.\n\n")

	fmt.Fprintf(&b, "## At a glance\n\n- Direct correlations: %d\n- Convergent discoveries: %d\n- Multi-hop paths: %d\n- Recurring pivots: %d\n- Hypotheses: %d\n- Intelligence gaps: %d\n- Researcher next steps: %d\n\n",
		len(report.Correlations), len(report.Discoveries), len(report.DiscoveryPaths), len(report.DiscoveryPivots),
		len(report.Hypotheses), len(report.IntelligenceGaps), len(report.Narrative.NextSteps))

	if strings.TrimSpace(report.Narrative.Summary) != "" {
		b.WriteString("## Executive summary\n\n")
		b.WriteString(mdText(report.Narrative.Summary) + "\n\n")
	}

	if len(report.Narrative.Signals) > 0 {
		b.WriteString("## Key signals\n\n")
		items := append([]NarrativeSignal(nil), report.Narrative.Signals...)
		sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
		for _, item := range items {
			fmt.Fprintf(&b, "### %s — %s\n\n", mdText(item.Kind), mdText(item.Summary))
			if item.Confidence != "" { fmt.Fprintf(&b, "- **Confidence:** %s\n", mdText(item.Confidence)) }
			if item.AlternativeExplanations != "" { fmt.Fprintf(&b, "- **Alternative explanations / limitations:** %s\n", mdText(item.AlternativeExplanations)) }
			writeMarkdownRefs(&b, "References", item.References)
			b.WriteString("\n")
		}
	}

	if len(report.Correlations) > 0 {
		b.WriteString("## Direct correlations\n\n")
		items := append([]Correlation(nil), report.Correlations...)
		sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
		for _, item := range items {
			fmt.Fprintf(&b, "### %s\n\n", mdCode(item.ID))
			fmt.Fprintf(&b, "- **Signal:** %s\n- **Entities:** %s\n- **Shared value:** %s\n- **Confidence scope:** %s\n",
				mdText(string(item.Type)), mdText(strings.Join(item.Entities, ", ")), mdCode(item.SharedValue), mdText(item.Confidence+" ("+item.ConfidenceScope+")"))
			if item.Explanation != "" { fmt.Fprintf(&b, "- **Interpretation:** %s\n", mdText(item.Explanation)) }
			if item.Limitations != "" { fmt.Fprintf(&b, "- **Limitations:** %s\n", mdText(item.Limitations)) }
			writeMarkdownRefs(&b, "Evidence", item.EvidenceIDs)
			writeMarkdownRefs(&b, "Observations", item.ObservationIDs)
			b.WriteString("\n")
		}
	}

	if len(report.Discoveries) > 0 {
		b.WriteString("## Convergent discoveries\n\n")
		items := append([]Discovery(nil), report.Discoveries...)
		sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
		for _, item := range items {
			fmt.Fprintf(&b, "### %s\n\n%s\n\n- **Entities:** %s\n- **Confidence:** %s\n- **Why it matters:** %s\n- **Alternative explanations:** %s\n",
				mdCode(item.ID), mdText(item.Statement), mdText(strings.Join(item.Entities, ", ")), mdText(item.Confidence),
				mdText(item.WhyItMatters), mdText(item.AlternativeExplanations))
			writeMarkdownRefs(&b, "Supporting correlations", item.CorrelationIDs)
			writeMarkdownSteps(&b, "Verification", item.Verification)
			b.WriteString("\n")
		}
	}

	if len(report.DiscoveryPaths) > 0 {
		b.WriteString("## Multi-hop discovery paths\n\n")
		items := append([]DiscoveryPath(nil), report.DiscoveryPaths...)
		sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
		for _, item := range items {
			fmt.Fprintf(&b, "### %s\n\n%s\n\n- **Path:** %s\n- **Confidence:** %s\n- **Why it matters:** %s\n- **Alternative explanations:** %s\n",
				mdCode(item.ID), mdText(item.Statement), mdText(strings.Join(item.Entities, " → ")), mdText(item.Confidence),
				mdText(item.WhyItMatters), mdText(item.AlternativeExplanations))
			writeMarkdownRefs(&b, "Supporting correlations", item.CorrelationIDs)
			writeMarkdownSteps(&b, "Verification", item.Verification)
			b.WriteString("\n")
		}
	}

	if len(report.DiscoveryPivots) > 0 {
		b.WriteString("## Recurring infrastructure pivots\n\n")
		items := append([]DiscoveryPivot(nil), report.DiscoveryPivots...)
		sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
		for _, item := range items {
			fmt.Fprintf(&b, "### %s\n\n%s\n\n- **Pivot:** %s\n- **Connected entities:** %s\n- **Confidence:** %s\n- **Why it matters:** %s\n- **Alternative explanations:** %s\n",
				mdCode(item.ID), mdText(item.Statement), mdCode(item.Pivot), mdText(strings.Join(item.ConnectedEntities, ", ")),
				mdText(item.Confidence), mdText(item.WhyItMatters), mdText(item.AlternativeExplanations))
			writeMarkdownRefs(&b, "Supporting paths", item.PathIDs)
			writeMarkdownSteps(&b, "Verification", item.Verification)
			b.WriteString("\n")
		}
	}

	if len(report.Hypotheses) > 0 {
		b.WriteString("## Hypotheses\n\n")
		items := append([]Hypothesis(nil), report.Hypotheses...)
		sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
		for _, item := range items {
			fmt.Fprintf(&b, "### %s — %s\n\n%s\n\n- **Confidence:** %s (qualitative, not a probability)\n- **Alternative explanations:** %s\n- **Limitations:** %s\n",
				mdCode(item.ID), mdText(item.Title), mdText(item.Statement), mdText(string(item.Confidence)),
				mdText(item.Alternative), mdText(item.Limitations))
			writeMarkdownRefs(&b, "Supporting evidence", item.SupportingIDs)
			writeMarkdownSteps(&b, "Verification", item.Verification)
			b.WriteString("\n")
		}
	}

	if len(report.VerificationAssessments) > 0 {
		b.WriteString("## Verification assessments\n\n")
		items := append([]VerificationAssessment(nil), report.VerificationAssessments...)
		sort.Slice(items, func(i, j int) bool { return items[i].HypothesisID < items[j].HypothesisID })
		for _, item := range items {
			fmt.Fprintf(&b, "### %s — %s\n\n%s\n\n", mdCode(item.HypothesisID), mdText(string(item.Status)), mdText(item.Explanation))
			writeMarkdownRefs(&b, "Supporting evidence", item.SupportingEvidenceIDs)
			writeMarkdownRefs(&b, "Contradicting evidence", item.ContradictingEvidenceIDs)
			writeMarkdownRefs(&b, "Excluded / non-independent evidence", item.ExcludedEvidenceIDs)
			if item.Limitations != "" { fmt.Fprintf(&b, "- **Limitations:** %s\n", mdText(item.Limitations)) }
			b.WriteString("\n")
		}
	}

	if len(report.IntelligenceGaps) > 0 {
		b.WriteString("## Unresolved intelligence gaps\n\n")
		items := append([]IntelligenceGap(nil), report.IntelligenceGaps...)
		sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
		for _, item := range items {
			fmt.Fprintf(&b, "### [%s] %s\n\n**Unknown:** %s\n\n**Why it matters:** %s\n\n**Suggested action:** %s\n\n**Required evidence:** %s\n\n**Alternative explanations:** %s\n",
				mdText(item.Priority), mdText(item.Subject), mdText(item.Unknown), mdText(item.WhyItMatters),
				mdText(item.SuggestedAction), mdText(strings.Join(item.RequiredEvidence, "; ")), mdText(item.AlternativeExplanations))
			writeMarkdownRefs(&b, "References", item.References)
			b.WriteString("\n")
		}
	}

	if len(report.PrioritizedFindings) > 0 {
		b.WriteString("## Prioritized findings\n\n")
		items := append([]PrioritizedFinding(nil), report.PrioritizedFindings...)
		sort.Slice(items, func(i, j int) bool {
			if items[i].Priority != items[j].Priority { return items[i].Priority > items[j].Priority }
			return items[i].Finding.Title < items[j].Finding.Title
		})
		for _, item := range items {
			fmt.Fprintf(&b, "### [%s] %s\n\n**Fact:** %s\n\n", mdText(string(item.Priority)), mdText(item.Finding.Title), mdText(item.Finding.Fact))
			if item.Finding.Observation != "" { fmt.Fprintf(&b, "**Observation:** %s\n\n", mdText(item.Finding.Observation)) }
			if item.Finding.PossibleSignificance != "" { fmt.Fprintf(&b, "**Possible significance:** %s\n\n", mdText(item.Finding.PossibleSignificance)) }
			if item.Reason != "" { fmt.Fprintf(&b, "**Priority rationale:** %s\n\n", mdText(item.Reason)) }
			writeMarkdownRefs(&b, "Source events", eventIDs(item.Finding.Evidence))
			writeMarkdownSteps(&b, "Suggested next steps", item.Finding.NextSteps)
			b.WriteString("\n")
		}
	}

	if len(report.Narrative.NextSteps) > 0 {
		b.WriteString("## Researcher next steps\n\n")
		items := append([]NarrativeNextStep(nil), report.Narrative.NextSteps...)
		sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
		for i, item := range items {
			fmt.Fprintf(&b, "%d. **%s**\n   - Why: %s\n", i+1, mdText(item.Action), mdText(item.Reason))
			if len(item.References) > 0 {
				fmt.Fprintf(&b, "   - References: %s\n", markdownRefValues(item.References))
			}
		}
		b.WriteString("\n")
	}

	if len(report.InvestigationPlan.Items) > 0 {
		b.WriteString("## Adaptive investigation plan\\n\\n")
		fmt.Fprintf(&b, "%s\\n\\n", mdText(report.InvestigationPlan.Summary))
		items := append([]InvestigationTask(nil), report.InvestigationPlan.Items...)
		sort.Slice(items, func(i, j int) bool {
			leftActive := items[i].Status == TaskRecommended || items[i].Status == TaskInconclusive
			rightActive := items[j].Status == TaskRecommended || items[j].Status == TaskInconclusive
			if leftActive != rightActive { return leftActive }
			if items[i].Priority != items[j].Priority { return items[i].Priority > items[j].Priority }
			return items[i].ID < items[j].ID
		})
		for _, item := range items {
			fmt.Fprintf(&b, "### [%s | %s] %s\\n\\n%s\\n\\n", mdText(item.Status), mdText(item.PriorityLabel), mdText(item.Action), mdText(item.Rationale))
			if item.OutcomeNote != "" { fmt.Fprintf(&b, "- **Investigator note:** %s\\n", mdText(item.OutcomeNote)) }
			writeMarkdownRefs(&b, "References", item.References)
			writeMarkdownRefs(&b, "Outcome evidence", item.EvidenceIDs)
			b.WriteString("\\n")
		}
	}
	if len(report.Narrative.Limitations) > 0 {
		b.WriteString("## Interpretation limits\n\n")
		writeMarkdownSteps(&b, "", report.Narrative.Limitations)
		b.WriteString("\n")
	}

	return strings.TrimSpace(b.String()) + "\n", nil
}

func mdText(value string) string {
	value = strings.Join(strings.Fields(value), " ")
	replacer := strings.NewReplacer(
		"\\", "\\\\", "`", "\\`", "*", "\\*", "_", "\\_", "[", "\\[", "]", "\\]",
		"|", "\\|", "#", "\\#", "<", "&lt;", ">", "&gt;",
	)
	return replacer.Replace(value)
}

func mdCode(value string) string {
	value = strings.Join(strings.Fields(value), " ")
	value = strings.ReplaceAll(value, "`", "'")
	return "`" + value + "`"
}

func markdownRefValues(values []string) string {
	items := append([]string(nil), values...)
	sort.Strings(items)
	items = uniqueStrings(items)
	formatted := make([]string, 0, len(items))
	for _, item := range items {
		formatted = append(formatted, mdCode(item))
	}
	return strings.Join(formatted, ", ")
}

func writeMarkdownRefs(b *strings.Builder, label string, values []string) {
	if len(values) == 0 { return }
	items := append([]string(nil), values...)
	sort.Strings(items)
	items = uniqueStrings(items)
	fmt.Fprintf(b, "- **%s:** ", label)
	for i, item := range items {
		if i > 0 { b.WriteString(", ") }
		b.WriteString(mdCode(item))
	}
	b.WriteString("\n")
}

func writeMarkdownSteps(b *strings.Builder, label string, values []string) {
	if len(values) == 0 { return }
	if label != "" { fmt.Fprintf(b, "- **%s:**\n", label) }
	for _, value := range values {
		if label == "" { fmt.Fprintf(b, "- %s\n", mdText(value)) } else { fmt.Fprintf(b, "  - %s\n", mdText(value)) }
	}
}

func eventIDs(events []events.Event) []string {
	ids := make([]string, 0, len(events))
	for _, event := range events {
		if strings.TrimSpace(event.ID) != "" { ids = append(ids, event.ID) }
	}
	sort.Strings(ids)
	return uniqueStrings(ids)
}
