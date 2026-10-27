package intelligence

import (
	"fmt"
	"sort"
	"strings"
)

// PrioritizedFinding combines a finding with its investigation priority
// and a transparent explanation for that priority.
type PrioritizedFinding struct {
	Finding  Finding  `json:"finding"`
	Priority Priority `json:"priority"`
	Reason   string   `json:"reason"`
}

// PrioritizationEngine assigns investigation priorities to findings.
type PrioritizationEngine struct{}

// Prioritize validates and ranks findings deterministically.
// Existing finding priorities are preserved; this engine does not infer
// vulnerabilities from hostnames or DNS addresses alone.
func (e *PrioritizationEngine) Prioritize(
	findings []Finding,
) ([]PrioritizedFinding, error) {
	results := make([]PrioritizedFinding, 0, len(findings))

	for i, finding := range findings {
		if err := finding.Validate(); err != nil {
			return nil, fmt.Errorf("finding %d is invalid: %w", i, err)
		}

		reason := ""
		switch finding.Priority {
		case PriorityHigh:
			reason = "The source finding already marks this item as high priority; verify its supporting evidence and context."
		case PriorityInterest:
			reason = "The source finding identifies an item worth further investigation; its significance is not confirmed."
		case PriorityInfo:
			reason = "The finding records an observation without establishing a confirmed security issue."
		case PriorityLow:
			reason = "The source finding assigns low investigation priority."
		default:
			return nil, fmt.Errorf(
				"finding %d has unsupported priority %q",
				i,
				finding.Priority,
			)
		}

		results = append(results, PrioritizedFinding{
			Finding:  finding,
			Priority: finding.Priority,
			Reason:   reason,
		})
	}

	sort.SliceStable(results, func(i, j int) bool {
		leftRank := priorityRank(results[i].Priority)
		rightRank := priorityRank(results[j].Priority)

		if leftRank != rightRank {
			return leftRank > rightRank
		}

		leftTitle := strings.ToLower(results[i].Finding.Title)
		rightTitle := strings.ToLower(results[j].Finding.Title)
		if leftTitle != rightTitle {
			return leftTitle < rightTitle
		}

		return results[i].Finding.Fact < results[j].Finding.Fact
	})

	return results, nil
}

func priorityRank(priority Priority) int {
	switch priority {
	case PriorityHigh:
		return 4
	case PriorityInterest:
		return 3
	case PriorityInfo:
		return 2
	case PriorityLow:
		return 1
	default:
		return 0
	}
}
