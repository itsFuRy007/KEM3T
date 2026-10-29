package evidence

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func BenchmarkSQLiteSaveEvidence(b *testing.B) {
	store, err := OpenSQLiteStore(":memory:")
	if err != nil {
		b.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e := Evidence{
			ID: fmt.Sprintf("bench-evidence-%d", i), EntityID: "example.com",
			Type: TypeDNSAddress, Value: "192.0.2.10",
		}
		if err := store.SaveEvidence(ctx, e); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSQLiteSaveEvidenceAndObservation(b *testing.B) {
	store, err := OpenSQLiteStore(":memory:")
	if err != nil {
		b.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	observedAt := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e := Evidence{
			ID: fmt.Sprintf("bench-evidence-%d", i), EntityID: "example.com",
			Type: TypeDNSAddress, Value: "192.0.2.10",
		}
		if err := store.SaveEvidence(ctx, e); err != nil {
			b.Fatal(err)
		}
		o := Observation{
			ID: fmt.Sprintf("bench-observation-%d", i), EvidenceID: e.ID,
			Source: "benchmark", ObservedAt: observedAt,
			EventIDs: []string{fmt.Sprintf("event-%d", i)},
		}
		if err := store.SaveObservation(ctx, o); err != nil {
			b.Fatal(err)
		}
	}
}
