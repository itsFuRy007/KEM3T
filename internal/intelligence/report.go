package intelligence

import (
	"fmt"
	"strings"

	"github.com/itsFuRy007/kem3t/internal/evidence"
)

// IntelligenceReport combines findings, correlations, hypotheses,
// and transparent investigation priorities.
type IntelligenceReport struct {
	Target              string               `json:"target"`
	Findings            []Finding            `json:"findings"`
	Correlations        []Correlation        `json:"correlations"`
	Hypotheses          []Hypothesis         `json:"hypotheses"`
	PrioritizedFindings []PrioritizedFinding `json:"prioritized_findings"`
}

// ReportEngine coordinates the intelligence analysis engines.
type ReportEngine struct {
	Correlation    *CorrelationEngine
	Hypothesis     *HypothesisEngine
	Prioritization *PrioritizationEngine
}

// Build creates a target-scoped intelligence report from validated findings
// and the evidence registry. Related entities may appear as context, but
// unrelated correlations from other targets are excluded.
func (e *ReportEngine) Build(
	target string,
	findings []Finding,
	registry *evidence.Registry,
) (IntelligenceReport, error) {
	target = normalizeCorrelationEntity(target)
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

	prioritized, err := prioritizationEngine.Prioritize(findings)
	if err != nil {
		return IntelligenceReport{}, fmt.Errorf("prioritize findings: %w", err)
	}

	// Normalize empty collections to JSON arrays rather than null.
	reportFindings := append([]Finding{}, findings...)
	reportCorrelations := append([]Correlation{}, correlations...)
	reportHypotheses := append([]Hypothesis{}, hypotheses...)
	reportPrioritized := append([]PrioritizedFinding{}, prioritized...)

	return IntelligenceReport{
		Target:              strings.TrimSpace(target),
		Findings:            reportFindings,
		Correlations:        reportCorrelations,
		Hypotheses:          reportHypotheses,
		PrioritizedFindings: reportPrioritized,
	}, nil
}
