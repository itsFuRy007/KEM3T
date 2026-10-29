package scale

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunPreservesInputOrderAndPerItemErrors(t *testing.T) {
	inputs := []int{4, 1, 3, 2}
	wantErr := errors.New("one target failed")
	results, err := Run(context.Background(), inputs, 3, func(_ context.Context, value int) (string, error) {
		time.Sleep(time.Duration(value%3) * time.Millisecond)
		if value == 3 { return "", wantErr }
		return fmt.Sprintf("target-%d", value), nil
	})
	if err != nil { t.Fatal(err) }
	if len(results) != len(inputs) { t.Fatalf("got %d results, want %d", len(results), len(inputs)) }
	for i, result := range results {
		if result.Index != i || result.Input != inputs[i] { t.Fatalf("result %d lost deterministic input ordering: %+v", i, result) }
		if inputs[i] == 3 && !errors.Is(result.Err, wantErr) { t.Fatalf("expected isolated target error, got %v", result.Err) }
		if inputs[i] != 3 && result.Err != nil { t.Fatalf("unexpected error for %d: %v", inputs[i], result.Err) }
	}
}

func TestRunNeverExceedsWorkerLimit(t *testing.T) {
	var active, peak atomic.Int32
	inputs := make([]int, 40)
	for i := range inputs { inputs[i] = i }
	_, err := Run(context.Background(), inputs, 4, func(_ context.Context, value int) (int, error) {
		now := active.Add(1)
		for { old := peak.Load(); if now <= old || peak.CompareAndSwap(old, now) { break } }
		time.Sleep(time.Millisecond)
		active.Add(-1)
		return value, nil
	})
	if err != nil { t.Fatal(err) }
	if got := peak.Load(); got > 4 { t.Fatalf("peak concurrency %d exceeds worker limit 4", got) }
	if got := peak.Load(); got != 4 { t.Fatalf("expected worker pool to reach 4 concurrent tasks, got %d", got) }
}

func TestRunCancellationMarksUnstartedItems(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := atomic.Int32{}
	results, err := Run(ctx, []int{1, 2, 3}, 2, func(_ context.Context, value int) (int, error) { called.Add(1); return value, nil })
	if err != nil { t.Fatal(err) }
	if called.Load() != 0 { t.Fatal("work started despite canceled context") }
	for _, result := range results { if !errors.Is(result.Err, context.Canceled) { t.Fatalf("expected cancellation result, got %v", result.Err) } }
}

func TestRunEmptyInput(t *testing.T) {
	results, err := Run(context.Background(), []int{}, 2, func(_ context.Context, value int) (int, error) { return value, nil })
	if err != nil || !reflect.DeepEqual(results, []Result[int, int]{}) { t.Fatalf("got results=%v err=%v", results, err) }
}

func TestRunRejectsInvalidConfiguration(t *testing.T) {
	fn := func(_ context.Context, value int) (int, error) { return value, nil }
	cases := map[string]struct { ctx context.Context; workers int; work func(context.Context, int) (int, error) }{
		"nil context": {nil, 1, fn}, "zero workers": {context.Background(), 0, fn}, "nil function": {context.Background(), 1, nil},
	}
	for name, tc := range cases { t.Run(name, func(t *testing.T) { _, err := Run(tc.ctx, []int{1}, tc.workers, tc.work); if err == nil { t.Fatal("expected configuration error") } }) }
}

func BenchmarkRunBoundedWorkerPool(b *testing.B) {
	inputs := make([]int, 256)
	for i := range inputs { inputs[i] = i }
	work := func(_ context.Context, value int) (int, error) { return value * 2, nil }
	b.ReportAllocs()
	for i := 0; i < b.N; i++ { if _, err := Run(context.Background(), inputs, 8, work); err != nil { b.Fatal(err) } }
}
