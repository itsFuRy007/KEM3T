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

func BenchmarkSQLiteLoadAll(b *testing.B) {
	for _, count := range []int{100, 1000, 5000} {
		b.Run(fmt.Sprintf("records_%d", count), func(b *testing.B) {
			store, err := OpenSQLiteStore(":memory:")
			if err != nil {
				b.Fatal(err)
			}
			defer store.Close()

			ctx := context.Background()
			observedAt := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
			for i := 0; i < count; i++ {
				e := Evidence{
					ID: fmt.Sprintf("load-evidence-%06d", i), EntityID: "example.com",
					Type: TypeDNSAddress, Value: "192.0.2.10",
				}
				if err := store.SaveEvidence(ctx, e); err != nil {
					b.Fatal(err)
				}
				o := Observation{
					ID: fmt.Sprintf("load-observation-%06d", i), EvidenceID: e.ID,
					Source: "benchmark", ObservedAt: observedAt,
					EventIDs: []string{"benchmark-event"},
				}
				if err := store.SaveObservation(ctx, o); err != nil {
					b.Fatal(err)
				}
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				evidence, observations, err := store.LoadAll(ctx)
				if err != nil {
					b.Fatal(err)
				}
				if len(evidence) != count || len(observations) != count {
					b.Fatalf("LoadAll returned %d evidence and %d observations; want %d each", len(evidence), len(observations), count)
				}
			}
		})
	}
}

func BenchmarkSQLiteLoadCollectionRuns(b *testing.B) {
	for _, count := range []int{100, 1000, 5000} {
		b.Run(fmt.Sprintf("runs_%d", count), func(b *testing.B) {
			store, err := OpenSQLiteStore(":memory:")
			if err != nil {
				b.Fatal(err)
			}
			defer store.Close()

			ctx := context.Background()
			startedAt := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
			for i := 0; i < count; i++ {
				start := startedAt.Add(time.Duration(i) * time.Second)
				run := CollectionRun{
					ID: fmt.Sprintf("load-run-%06d", i), Target: fmt.Sprintf("host-%06d.example.com", i),
					StartedAt: start, FinishedAt: start.Add(time.Second),
					Status: CollectionRunCompleted, EventCount: 3, AddressCount: 2,
				}
				if err := store.SaveCollectionRun(ctx, run); err != nil {
					b.Fatal(err)
				}
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				runs, err := store.LoadCollectionRuns(ctx, "")
				if err != nil {
					b.Fatal(err)
				}
				if len(runs) != count {
					b.Fatalf("LoadCollectionRuns returned %d runs; want %d", len(runs), count)
				}
			}
		})
	}
}

