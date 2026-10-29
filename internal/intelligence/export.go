package intelligence

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// ExportSchemaVersion identifies the canonical structured investigation export contract.
const ExportSchemaVersion = "1"

// InvestigationExport is the stable, machine-readable boundary for Phase 8 exports.
// The existing report remains authoritative; this envelope adds explicit scope and
// a versioned contract without duplicating or reinterpreting analytical records.
type InvestigationExport struct {
	SchemaVersion string              `json:"schema_version"`
	Investigation ExportInvestigation `json:"investigation"`
	Report        *IntelligenceReport `json:"report"`
}

type ExportInvestigation struct {
	Target string `json:"target"`
}

// Validate rejects incomplete exports and mismatched scope before data leaves KEM3T.
func (e InvestigationExport) Validate() error {
	if e.SchemaVersion != ExportSchemaVersion {
		return fmt.Errorf("unsupported export schema version %q", e.SchemaVersion)
	}
	target := normalizeFindingTarget(e.Investigation.Target)
	if target == "" {
		return fmt.Errorf("export investigation target is required")
	}
	if e.Report == nil {
		return fmt.Errorf("export report is required")
	}
	reportTarget := normalizeFindingTarget(e.Report.Target)
	if reportTarget == "" {
		return fmt.Errorf("export report target is required")
	}
	if target != reportTarget {
		return fmt.Errorf("export scope %q does not match report target %q", target, reportTarget)
	}
	return nil
}

// MarshalJSON validates the scope boundary before serializing the export.
func (e InvestigationExport) MarshalJSON() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	type alias InvestigationExport
	return json.Marshal(alias(e))
}

// NewInvestigationExport wraps an existing report without changing its analytical meaning.
func NewInvestigationExport(target string, report *IntelligenceReport) InvestigationExport {
	return InvestigationExport{
		SchemaVersion: ExportSchemaVersion,
		Investigation: ExportInvestigation{Target: strings.TrimSpace(target)},
		Report:        report,
	}
}

// StableStringSlice returns a sorted copy for callers building deterministic exports.
func StableStringSlice(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}
