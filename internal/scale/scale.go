// Package scale provides bounded, cancellation-aware primitives for running
// independent infrastructure investigations without unbounded goroutine growth.
package scale

import (
	"context"
	"fmt"
	"sync"
)

type Result[T any, R any] struct {
	Index int
	Input T
	Value R
	Err   error
}

// Run applies fn to inputs with at most workers calls running at once. Results
// retain input order regardless of completion order. Configuration errors are
// returned directly; per-item investigation errors are stored in Result.Err.
// Cancellation prevents queued items from starting. Started functions should
// observe ctx themselves.
func Run[T any, R any](ctx context.Context, inputs []T, workers int, fn func(context.Context, T) (R, error)) ([]Result[T, R], error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}
	if workers < 1 {
		return nil, fmt.Errorf("worker count must be at least one")
	}
	if fn == nil {
		return nil, fmt.Errorf("work function is required")
	}
	results := make([]Result[T, R], len(inputs))
	if len(inputs) == 0 {
		return results, nil
	}
	if workers > len(inputs) {
		workers = len(inputs)
	}

	type job struct {
		index int
		input T
	}
	jobs := make(chan job)
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			for item := range jobs {
				result := Result[T, R]{Index: item.index, Input: item.input}
				if err := ctx.Err(); err != nil {
					result.Err = err
				} else {
					result.Value, result.Err = fn(ctx, item.input)
				}
				results[item.index] = result
			}
		}()
	}
	for i, input := range inputs {
		select {
		case jobs <- job{index: i, input: input}:
		case <-ctx.Done():
			for j := i; j < len(inputs); j++ {
				results[j] = Result[T, R]{Index: j, Input: inputs[j], Err: ctx.Err()}
			}
			close(jobs)
			wg.Wait()
			return results, nil
		}
	}
	close(jobs)
	wg.Wait()
	return results, nil
}
