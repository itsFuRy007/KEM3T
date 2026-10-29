package intelligence

import (
	"encoding/json"
	"sort"
)

// ExportSchemaVersion identifies the canonical structured investigation export contract.
const ExportSchemaVersion = "1"

// InvestigationExport is the stable, machine-readable boundary for Phase 8 exports.
// It deliberately references existing report data instead of inventing a second
// analytical model. Presentation-specific formats should be built from this shape.
type InvestigationExport struct {
	SchemaVersion string            `json:"schema_version"`
	Investigation ExportInvestigation `json:"investigation"`
	Report        *IntelligenceReport `json:"report"`
}

type ExportInvestigation struct {
	Target string `json:"target"`
}

// MarshalJSON produces deterministic JSON for the canonical export boundary.
func (e InvestigationExport) MarshalJSON() ([]byte, error) {
	type alias InvestigationExport
	return json.Marshal(alias(e))
}

// NewInvestigationExport wraps an existing report without changing its analytical meaning.
func NewInvestigationExport(target string, report *IntelligenceReport) InvestigationExport {
	return InvestigationExport{
		SchemaVersion: ExportSchemaVersion,
		Investigation: ExportInvestigation{Target: target},
		Report:        report,
	}
}

// StableStringSlice returns a sorted copy for callers building deterministic exports.
func StableStringSlice(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}
