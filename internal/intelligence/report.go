package intelligence

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"

	"github.com/itsFuRy007/kem3t/internal/evidence"
)

// IntelligenceReport combines evidence-backed findings and the higher-order
// discoveries derived from their target-scoped correlations.
type IntelligenceReport struct {
	Target                  string                   `json:"target"`
	ReferenceRunID          string                   `json:"reference_run_id,omitempty"`
	ReferenceRunStatus      string                   `json:"reference_run_status,omitempty"`
	Findings                []Finding                `json:"findings"`
	ServiceSurfaces         []ServiceSurface         `json:"service_surfaces"`
	Correlations            []Correlation            `json:"correlations"`
	Discoveries             []Discovery              `json:"discoveries"`
	DiscoveryPaths          []DiscoveryPath          `json:"discovery_paths"`
	DiscoveryPivots         []DiscoveryPivot         `json:"discovery_pivots"`
	IntelligenceGaps        []IntelligenceGap        `json:"intelligence_gaps"`
	Hypotheses              []Hypothesis             `json:"hypotheses"`
	VerificationAssessments []VerificationAssessment `json:"verification_assessments"`
	PrioritizedFindings     []PrioritizedFinding     `json:"prioritized_findings"`
	Narrative               ResearchNarrative        `json:"narrative"`
	InvestigationPlan       InvestigationPlan        `json:"investigation_plan"`
}

// ReportEngine coordinates target-scoped correlation, discovery, hypothesis,
// verification, and prioritization engines.
type ReportEngine struct {
	Correlation    *CorrelationEngine
	Discovery      *DiscoveryEngine
	Hypothesis     *HypothesisEngine
	Prioritization *PrioritizationEngine
}

func (e *ReportEngine) Build(target string, findings []Finding, registry *evidence.Registry) (IntelligenceReport, error) {
	return e.BuildWithVerification(target, findings, registry, nil)
}

// BuildWithVerification assembles one coherent report. Every higher-order
// discovery is derived from the same target-scoped correlation set.
func (e *ReportEngine) BuildWithVerification(
	target string,
	findings []Finding,
	registry *evidence.Registry,
	verification map[string][]VerificationEvidence,
) (IntelligenceReport, error) {
	return e.BuildWithInvestigationFeedback(target, findings, registry, verification, nil, nil)
}

func (e *ReportEngine) BuildWithInvestigationFeedback(
	target string,
	findings []Finding,
	registry *evidence.Registry,
	verification map[string][]VerificationEvidence,
	previousPlan *InvestigationPlan,
	feedback []InvestigationFeedback,
) (IntelligenceReport, error) {
	target = normalizeFindingTarget(target)
	if target == "" {
		return IntelligenceReport{}, fmt.Errorf("report target is required")
	}
	if registry == nil {
		return IntelligenceReport{}, fmt.Errorf("evidence registry is required")
	}

	correlationEngine := e.Correlation
	if correlationEngine == nil {
		correlationEngine = &CorrelationEngine{}
	}
	discoveryEngine := e.Discovery
	if discoveryEngine == nil {
		discoveryEngine = &DiscoveryEngine{}
	}
	hypothesisEngine := e.Hypothesis
	if hypothesisEngine == nil {
		hypothesisEngine = &HypothesisEngine{}
	}
	prioritizationEngine := e.Prioritization
	if prioritizationEngine == nil {
		prioritizationEngine = &PrioritizationEngine{}
	}

	correlationLimitations := make([]string, 0)
	correlations, err := correlationEngine.CorrelateForTarget(registry, target)
	if err != nil {
		// A malformed historical record for another target must not make the
		// requested target's entire report unavailable. Retry using only evidence
		// whose entity is inside the requested target namespace.
		scopedEvidence, scopedObservations := targetScopedCorrelationRecords(target, registry)
		correlations, err = correlationEngine.CorrelateEvidenceForTarget(scopedEvidence, scopedObservations, target)
		if err != nil {
			return IntelligenceReport{}, fmt.Errorf("correlate evidence for target %q: %w", target, err)
		}
		correlationLimitations = append(correlationLimitations,
			"Target correlations were restricted to in-scope evidence because unrelated historical records failed validation; relationships to external entities may therefore be absent.")
	}
	// Multi-hop discovery needs second-hop relationships around direct pivots.
	// If unrelated historical data prevents building the global graph, preserve
	// the direct target report and disclose that multi-hop coverage was reduced.
	allCorrelations, err := correlationEngine.Correlate(registry)
	if err != nil {
		allCorrelations = correlations
		correlationLimitations = append(correlationLimitations,
			"Multi-hop discovery was limited because the global historical correlation set could not be validated; only direct target correlations were used.")
	}
	discoveries, err := discoveryEngine.Discover(correlations, target)
	if err != nil {
		return IntelligenceReport{}, fmt.Errorf("discover higher-order relationships: %w", err)
	}
	discoveryPaths, err := discoveryEngine.DiscoverPaths(allCorrelations, target)
	if err != nil {
		return IntelligenceReport{}, fmt.Errorf("discover multi-hop relationships: %w", err)
	}
	discoveryPivots, err := discoveryEngine.DiscoverPivots(discoveryPaths, target)
	if err != nil {
		return IntelligenceReport{}, fmt.Errorf("discover recurring pivots: %w", err)
	}
	hypotheses, err := hypothesisEngine.Generate(correlations)
	if err != nil {
		return IntelligenceReport{}, fmt.Errorf("generate hypotheses: %w", err)
	}
	referenceRunID := ""
	referenceRunStatus := ""
	runs, runErr := registry.CollectionRuns(target)
	if runErr != nil {
		return IntelligenceReport{}, fmt.Errorf("load target collection runs: %w", runErr)
	}
	if len(runs) > 0 {
		referenceRunID = runs[0].ID
		referenceRunStatus = string(runs[0].Status)
	}
	serviceSurfaces, err := BuildServiceSurfaces(target, registry.AllEvidence(), registry.AllObservations(), referenceRunID)
	if err != nil {
		return IntelligenceReport{}, fmt.Errorf("build endpoint service surfaces: %w", err)
	}
	serviceHypotheses, err := GenerateServiceHypotheses(serviceSurfaces)
	if err != nil {
		return IntelligenceReport{}, fmt.Errorf("generate service hypotheses: %w", err)
	}
	hypotheses = append(hypotheses, serviceHypotheses...)
	sort.Slice(hypotheses, func(i, j int) bool { return hypotheses[i].ID < hypotheses[j].ID })

	scopedFindings := make([]Finding, 0, len(findings))
	for i, finding := range findings {
		if err := finding.Validate(); err != nil {
			return IntelligenceReport{}, fmt.Errorf("finding %d is invalid: %w", i, err)
		}
		inScope, err := findingWithinTargetScope(finding, target)
		if err != nil {
			return IntelligenceReport{}, fmt.Errorf("scope finding %q: %w", finding.Title, err)
		}
		if inScope {
			scopedFindings = append(scopedFindings, finding)
		}
	}
	prioritized, err := prioritizationEngine.Prioritize(scopedFindings)
	if err != nil {
		return IntelligenceReport{}, fmt.Errorf("prioritize findings: %w", err)
	}

	hypothesisIDs := make(map[string]struct{}, len(hypotheses))
	for _, hypothesis := range hypotheses {
		hypothesisIDs[hypothesis.ID] = struct{}{}
	}
	for hypothesisID := range verification {
		if _, exists := hypothesisIDs[hypothesisID]; !exists {
			return IntelligenceReport{}, fmt.Errorf("verification supplied for unknown or out-of-scope hypothesis %q", hypothesisID)
		}
	}
	assessments := make([]VerificationAssessment, 0, len(hypotheses))
	for _, hypothesis := range hypotheses {
		assessment, err := hypothesisEngine.Assess(hypothesis, verification[hypothesis.ID])
		if err != nil {
			return IntelligenceReport{}, fmt.Errorf("assess hypothesis %q: %w", hypothesis.ID, err)
		}
		assessments = append(assessments, assessment)
	}

	report := IntelligenceReport{
		Target:                  strings.TrimSpace(target),
		ReferenceRunID:          referenceRunID,
		ReferenceRunStatus:      referenceRunStatus,
		Findings:                append([]Finding{}, scopedFindings...),
		ServiceSurfaces:         append([]ServiceSurface{}, serviceSurfaces...),
		Correlations:            append([]Correlation{}, correlations...),
		Discoveries:             append([]Discovery{}, discoveries...),
		DiscoveryPaths:          append([]DiscoveryPath{}, discoveryPaths...),
		DiscoveryPivots:         append([]DiscoveryPivot{}, discoveryPivots...),
		Hypotheses:              append([]Hypothesis{}, hypotheses...),
		VerificationAssessments: append([]VerificationAssessment{}, assessments...),
		PrioritizedFindings:     append([]PrioritizedFinding{}, prioritized...),
		IntelligenceGaps:        []IntelligenceGap{},
	}
	gaps, err := BuildIntelligenceGaps(report)
	if err != nil {
		return IntelligenceReport{}, fmt.Errorf("detect intelligence gaps: %w", err)
	}
	report.IntelligenceGaps = gaps
	narrative, err := BuildResearchNarrative(report)
	if err != nil {
		return IntelligenceReport{}, fmt.Errorf("build researcher narrative: %w", err)
	}
	report.Narrative = narrative
	for _, limitation := range correlationLimitations {
		report.Narrative.Limitations = appendUniqueReportLimitation(report.Narrative.Limitations, limitation)
	}
	plan, err := BuildAdaptiveInvestigationPlan(report, previousPlan, feedback)
	if err != nil {
		return IntelligenceReport{}, fmt.Errorf("build adaptive investigation plan: %w", err)
	}
	report.InvestigationPlan = plan
	return report, nil
}

func appendUniqueReportLimitation(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func targetScopedCorrelationRecords(target string, registry *evidence.Registry) ([]evidence.Evidence, []evidence.Observation) {
	allEvidence := registry.AllEvidence()
	selected := make([]evidence.Evidence, 0, len(allEvidence))
	selectedIDs := make(map[string]struct{})
	for _, item := range allEvidence {
		entity := normalizeFindingTarget(item.EntityID)
		if entity == "" || !serviceTargetInScope(entity, target) {
			continue
		}
		selected = append(selected, item)
		selectedIDs[item.ID] = struct{}{}
	}
	allObservations := registry.AllObservations()
	observations := make([]evidence.Observation, 0)
	for _, observation := range allObservations {
		if _, ok := selectedIDs[observation.EvidenceID]; ok {
			observations = append(observations, observation)
		}
	}
	return selected, observations
}

// normalizeFindingTarget accepts hostnames, IP addresses, host:port values,
// and URLs while keeping report scope anchored to the actual host.
func normalizeFindingTarget(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if parsed, err := url.Parse(value); err == nil && parsed.Hostname() != "" {
		value = parsed.Hostname()
	} else if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	return normalizeCorrelationEntity(value)
}

// findingWithinTargetScope excludes unrelated findings and refuses to include a
// mixed-scope aggregate whose summary may contain facts from outside the report.
func findingWithinTargetScope(finding Finding, target string) (bool, error) {
	if len(finding.Evidence) == 0 {
		return false, fmt.Errorf("finding has no evidence")
	}
	inScope := 0
	for _, event := range finding.Evidence {
		eventTarget := normalizeFindingTarget(event.Target)
		if eventTarget == "" {
			return false, fmt.Errorf("evidence event %q has an empty target", event.ID)
		}
		if eventTarget == target || (net.ParseIP(target) == nil && strings.HasSuffix(eventTarget, "."+target)) {
			inScope++
		}
	}
	if inScope == 0 {
		return false, nil
	}
	if inScope != len(finding.Evidence) {
		return false, fmt.Errorf("finding contains evidence both inside and outside target %q; split the finding before reporting", target)
	}
	return true, nil
}
