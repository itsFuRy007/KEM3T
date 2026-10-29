package intelligence

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"

	"github.com/itsFuRy007/kem3t/internal/changes"
	"github.com/itsFuRy007/kem3t/internal/snapshots"
)

// ExportSchemaVersion identifies the canonical structured investigation export contract.
const ExportSchemaVersion = "1"

// InvestigationExport is the stable, machine-readable boundary for Phase 8 exports.
// The existing report remains authoritative; collection context records how and when
// the report's underlying DNS observations were collected.
type InvestigationExport struct {
	SchemaVersion string              `json:"schema_version"`
	Investigation ExportInvestigation `json:"investigation"`
	Collection    *ExportCollection   `json:"collection,omitempty"`
	Report        *IntelligenceReport `json:"report"`
}

type ExportInvestigation struct {
	Target string `json:"target"`
}

// ExportCollection preserves the temporal context for one DNS collection.
type ExportCollection struct {
	BaselineCreated  bool                   `json:"baseline_created"`
	CurrentSnapshot  snapshots.Snapshot     `json:"current_snapshot"`
	PreviousSnapshot *snapshots.Snapshot    `json:"previous_snapshot,omitempty"`
	Changes          []ExportChange         `json:"changes"`
	History          *ExportDNSHistory      `json:"history,omitempty"`
}

// ExportChange describes a difference between two observed snapshots.
type ExportChange struct {
	Target  string             `json:"target"`
	Type    changes.ChangeType `json:"type"`
	Address string             `json:"address"`
}

// ExportDNSHistory uses explicit JSON names and clarifies that removed addresses
// were absent from the newer snapshot, not proven absent from global infrastructure.
type ExportDNSHistory struct {
	Target                   string   `json:"target"`
	Added                    []string `json:"added_between_snapshots"`
	Removed                  []string `json:"removed_between_snapshots"`
	Unchanged                []string `json:"unchanged_between_snapshots"`
	PreviousObservedCount    int      `json:"previous_observed_count"`
	CurrentObservedCount     int      `json:"current_observed_count"`
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
	if e.Collection != nil {
		if err := e.Collection.Validate(target); err != nil {
			return fmt.Errorf("validate export collection: %w", err)
		}
	}
	return nil
}

// Validate checks snapshot integrity, chronology, and target isolation.
func (c ExportCollection) Validate(target string) error {
	if err := c.CurrentSnapshot.Validate(); err != nil {
		return fmt.Errorf("current snapshot: %w", err)
	}
	if normalizeFindingTarget(c.CurrentSnapshot.Target) != target {
		return fmt.Errorf("current snapshot target does not match investigation scope %q", target)
	}
	if c.BaselineCreated && c.PreviousSnapshot != nil {
		return fmt.Errorf("baseline collection cannot include a previous snapshot")
	}
	if c.PreviousSnapshot == nil {
		if len(c.Changes) != 0 || c.History != nil {
			return fmt.Errorf("temporal comparison requires a previous snapshot")
		}
		if !c.BaselineCreated {
			return fmt.Errorf("collection without a previous snapshot must be marked as baseline")
		}
	} else {
		if c.BaselineCreated {
			return fmt.Errorf("collection cannot be both baseline and comparison")
		}
		if err := c.PreviousSnapshot.Validate(); err != nil {
			return fmt.Errorf("previous snapshot: %w", err)
		}
		if normalizeFindingTarget(c.PreviousSnapshot.Target) != target {
			return fmt.Errorf("previous snapshot target does not match investigation scope %q", target)
		}
		if c.PreviousSnapshot.Collected.After(c.CurrentSnapshot.Collected) {
			return fmt.Errorf("previous snapshot is newer than current snapshot")
		}
		if c.History == nil {
			return fmt.Errorf("comparison collection requires DNS history")
		}
		if c.History.Target != target {
			return fmt.Errorf("DNS history target does not match investigation scope %q", target)
		}
		if c.History.PreviousObservedCount != len(c.PreviousSnapshot.Addresses) ||
			c.History.CurrentObservedCount != len(c.CurrentSnapshot.Addresses) {
			return fmt.Errorf("DNS history counts do not match snapshot address counts")
		}
	}
	for i, change := range c.Changes {
		if normalizeFindingTarget(change.Target) != target {
			return fmt.Errorf("change %d target does not match investigation scope %q", i, target)
		}
		if change.Type != changes.AddressAdded && change.Type != changes.AddressRemoved {
			return fmt.Errorf("change %d has unsupported type %q", i, change.Type)
		}
		if net.ParseIP(change.Address) == nil {
			return fmt.Errorf("change %d has invalid IP address %q", i, change.Address)
		}
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
		Investigation: ExportInvestigation{Target: normalizeFindingTarget(target)},
		Report:        report,
	}
}

// NewDNSInvestigationExport adds validated collection and temporal context to a DNS report.
func NewDNSInvestigationExport(
	target string,
	report *IntelligenceReport,
	current snapshots.Snapshot,
	previous *snapshots.Snapshot,
	detectedChanges []changes.Change,
	history *DNSHistoryComparison,
	baselineCreated bool,
) InvestigationExport {
	export := NewInvestigationExport(target, report)
	collection := &ExportCollection{
		BaselineCreated:  baselineCreated,
		CurrentSnapshot:  current,
		PreviousSnapshot: previous,
		Changes:          make([]ExportChange, 0, len(detectedChanges)),
	}
	for _, item := range detectedChanges {
		collection.Changes = append(collection.Changes, ExportChange{
			Target:  item.Target,
			Type:    item.Type,
			Address: item.Address,
		})
	}
	sort.Slice(collection.Changes, func(i, j int) bool {
		if collection.Changes[i].Address != collection.Changes[j].Address {
			return collection.Changes[i].Address < collection.Changes[j].Address
		}
		return collection.Changes[i].Type < collection.Changes[j].Type
	})
	if history != nil {
		collection.History = &ExportDNSHistory{
			Target:                history.Target,
			Added:                 StableStringSlice(history.Added),
			Removed:               StableStringSlice(history.Removed),
			Unchanged:             StableStringSlice(history.Unchanged),
			PreviousObservedCount: history.PreviousCount,
			CurrentObservedCount:  history.CurrentCount,
		}
	}
	export.Collection = collection
	return export
}

// StableStringSlice returns a sorted copy for callers building deterministic exports.
func StableStringSlice(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}
