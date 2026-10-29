package batch

import (
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"
)

func benchmarkDNSOutcomes(targetCount, addressesPerTarget int) []DNSOutcome {
	outcomes := make([]DNSOutcome, 0, targetCount)
	for i := 0; i < targetCount; i++ {
		target := fmt.Sprintf("host-%05d.example.com", i)
		addresses := make([]string, 0, addressesPerTarget)
		for j := 0; j < addressesPerTarget; j++ {
			// A repeatable address pool creates both unique and shared-IP cases.
			addresses = append(addresses, net.IPv4(198, 51, byte((i+j)%250), byte((i*7+j)%250+1)).String())
		}
		outcomes = append(outcomes, DNSOutcome{
			Target: target, Addresses: addresses,
			CollectedAt: time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC),
			EvidenceStore: fmt.Sprintf("/evidence/%05d.db", i),
		})
	}
	return outcomes
}

func BenchmarkBuildDNSInvestigationGraph(b *testing.B) {
	for _, targets := range []int{100, 1000, 5000} {
		b.Run(fmt.Sprintf("targets_%d", targets), func(b *testing.B) {
			outcomes := benchmarkDNSOutcomes(targets, 3)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = BuildDNSInvestigationGraph(outcomes, time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC))
			}
		})
	}
}

func BenchmarkBuildDNSGraphChanges(b *testing.B) {
	for _, targets := range []int{100, 1000, 5000} {
		b.Run(fmt.Sprintf("targets_%d", targets), func(b *testing.B) {
			outcomes := benchmarkDNSOutcomes(targets, 3)
			previous := BuildDNSInvestigationGraph(outcomes, time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC))
			current := BuildDNSInvestigationGraph(outcomes, time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = BuildDNSGraphChanges(&previous, current)
			}
		})
	}
}

func BenchmarkMarshalDNSInvestigationGraph(b *testing.B) {
	outcomes := benchmarkDNSOutcomes(1000, 3)
	graph := BuildDNSInvestigationGraph(outcomes, time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC))
	b.ReportAllocs()
	b.SetBytes(int64(len(mustMarshalGraph(b, graph))))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := json.Marshal(graph); err != nil {
			b.Fatal(err)
		}
	}
}

func mustMarshalGraph(b *testing.B, graph DNSInvestigationGraph) []byte {
	b.Helper()
	data, err := json.Marshal(graph)
	if err != nil {
		b.Fatal(err)
	}
	return data
}
