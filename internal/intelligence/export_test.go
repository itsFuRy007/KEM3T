package intelligence

import (
	"encoding/json"
	"testing"
)

func TestNewInvestigationExport(t *testing.T) {
	report := &IntelligenceReport{}
	export := NewInvestigationExport("example.com", report)

	if export.SchemaVersion != ExportSchemaVersion {
		t.Fatalf("schema version = %q, want %q", export.SchemaVersion, ExportSchemaVersion)
	}
	if export.Investigation.Target != "example.com" {
		t.Fatalf("target = %q, want example.com", export.Investigation.Target)
	}
	if export.Report != report {
		t.Fatal("report pointer was not preserved")
	}
}

func TestInvestigationExportJSONContract(t *testing.T) {
	export := NewInvestigationExport("example.com", &IntelligenceReport{})
	data, err := json.Marshal(export)
	if err != nil {
		t.Fatalf("marshal export: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal export: %v", err)
	}
	if decoded["schema_version"] != ExportSchemaVersion {
		t.Fatalf("schema_version = %v, want %q", decoded["schema_version"], ExportSchemaVersion)
	}
	investigation, ok := decoded["investigation"].(map[string]any)
	if !ok {
		t.Fatalf("investigation section has unexpected type: %T", decoded["investigation"])
	}
	if investigation["target"] != "example.com" {
		t.Fatalf("target = %v, want example.com", investigation["target"])
	}
}

func TestStableStringSliceDoesNotMutateInput(t *testing.T) {
	input := []string{"b", "a", "c"}
	got := StableStringSlice(input)
	want := []string{"a", "b", "c"}

	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if input[0] != "b" || input[1] != "a" || input[2] != "c" {
		t.Fatalf("input was mutated: %#v", input)
	}
}
