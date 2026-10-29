package intelligence

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/itsFuRy007/kem3t/internal/evidence"
)

// IntelligenceReport combines findings, correlations, hypotheses, verification
// assessments, and transparent investigation priorities.
type IntelligenceReport struct {
	Target              string               `json:"target"`
	Findings            []Finding            `json:"findings"`
	Correlations        []Correlation        `json:"correlations"`
	Hypotheses              []Hypothesis              `json:"hypotheses"`
	VerificationAssessments []VerificationAssessment `json:"verification_assessments"`
	PrioritizedFindings     []PrioritizedFinding      `json:"prioritized_findings"`
}

// ReportEngine coordinates the intelligence analysis engines.
type ReportEngine struct {
	Correlation    *CorrelationEngine
	Hypothesis     *HypothesisEngine
	Prioritization *PrioritizationEngine
}

// Build creates a target-scoped report without externally supplied verification
// evidence. Generated hypotheses remain explicitly UNVERIFIED.
func (e *ReportEngine) Build(
	target string,
	findings []Finding,
	registry *evidence.Registry,
) (IntelligenceReport, error) {
	return e.BuildWithVerification(target, findings, registry, nil)
}

// BuildWithVerification builds the report and assesses each generated hypothesis
// using investigator-classified verification evidence keyed by hypothesis ID.
// Evidence not supplied for a hypothesis leaves it UNVERIFIED. Unknown keys are
// rejected to prevent misspelled IDs from silently dropping verification data.
func (e *ReportEngine) BuildWithVerification(
	target string,
	findings []Finding,
	registry *evidence.Registry,
	verification map[string][]VerificationEvidence,
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

	hypothesisEngine := e.Hypothesis
	if hypothesisEngine == nil {
		hypothesisEngine = &HypothesisEngine{}
	}

	prioritizationEngine := e.Prioritization
	if prioritizationEngine == nil {
		prioritizationEngine = &PrioritizationEngine{}
	}

	correlations, err := correlationEngine.CorrelateForTarget(registry, target)
	if err != nil {
		return IntelligenceReport{}, fmt.Errorf("correlate evidence for target %q: %w", target, err)
	}

	hypotheses, err := hypothesisEngine.Generate(correlations)
	if err != nil {
		return IntelligenceReport{}, fmt.Errorf("generate hypotheses: %w", err)
	}

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

	// Reject verification entries that cannot be attached to a hypothesis in
	// this target-scoped report; silently ignoring them would hide caller errors.
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

	// Normalize empty collections to JSON arrays rather than null.
	reportFindings := append([]Finding{}, scopedFindings...)
	reportCorrelations := append([]Correlation{}, correlations...)
	reportHypotheses := append([]Hypothesis{}, hypotheses...)
	reportAssessments := append([]VerificationAssessment{}, assessments...)
	reportPrioritized := append([]PrioritizedFinding{}, prioritized...)

	return IntelligenceReport{
		Target:                  strings.TrimSpace(target),
		Findings:                reportFindings,
		Correlations:            reportCorrelations,
		Hypotheses:              reportHypotheses,
		VerificationAssessments: reportAssessments,
		PrioritizedFindings:     reportPrioritized,
	}, nil
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
// A domain scope includes the exact hostname and its true subdomains, but not
// lookalikes such as example.com.attacker.test.
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
