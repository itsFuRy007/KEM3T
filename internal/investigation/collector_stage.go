package investigation

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/itsFuRy007/kem3t/internal/collectors"
	"github.com/itsFuRy007/kem3t/internal/events"
	"github.com/itsFuRy007/kem3t/internal/evidence"
)

type eventCollector interface {
	Run(context.Context, chan<- events.Event) error
}

// CollectorStage adapts an existing event collector to the shared registry.
// It owns event conversion and registration, but never opens or closes storage.
type CollectorStage struct {
	StageName string
	Collector eventCollector
	Convert   func(events.Event) (evidence.Evidence, evidence.Observation, error)
	Accept    func(events.Event) bool
}

func (s *CollectorStage) Name() string { return strings.TrimSpace(s.StageName) }

func (s *CollectorStage) Run(ctx context.Context, target string, registry *evidence.Registry) (StageResult, error) {
	if ctx == nil { return StageResult{}, fmt.Errorf("context is required") }
	if registry == nil { return StageResult{}, fmt.Errorf("shared evidence registry is required") }
	if s == nil || s.Collector == nil { return StageResult{}, fmt.Errorf("collector is required") }
	if s.Convert == nil { return StageResult{}, fmt.Errorf("event converter is required") }
	if strings.TrimSpace(target) == "" { return StageResult{}, fmt.Errorf("target is required") }

	stageCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	eventCh := make(chan events.Event)
	done := make(chan error, 1)
	go func() {
		err := s.Collector.Run(stageCtx, eventCh)
		close(eventCh)
		done <- err
	}()

	result := StageResult{}
	var registrationErr error
	for event := range eventCh {
		if err := stageCtx.Err(); err != nil { registrationErr = err; break }
		if err := event.Validate(); err != nil {
			registrationErr = fmt.Errorf("collector %q emitted invalid event: %w", s.Name(), err)
			cancel()
			break
		}
		if !strings.EqualFold(strings.TrimSuffix(strings.TrimSpace(event.Target), "."), strings.TrimSuffix(strings.TrimSpace(target), ".")) {
			registrationErr = fmt.Errorf("collector %q emitted out-of-scope target %q", s.Name(), event.Target)
			cancel()
			break
		}
		if s.Accept != nil && !s.Accept(event) { continue }
		item, observation, err := s.Convert(event)
		if err != nil {
			registrationErr = fmt.Errorf("convert %s event: %w", s.Name(), err)
			cancel()
			break
		}
		if err := registry.AddEvidence(item); err != nil && !errors.Is(err, evidence.ErrEvidenceExists) {
			registrationErr = fmt.Errorf("register %s evidence: %w", s.Name(), err)
			cancel()
			break
		}
		if err := registry.AddObservation(observation); err != nil && !errors.Is(err, evidence.ErrObservationExists) {
			registrationErr = fmt.Errorf("register %s observation: %w", s.Name(), err)
			cancel()
			break
		}
		result.Events++
		result.Evidence++
		result.Observations++
	}
	collectorErr := <-done
	if registrationErr != nil { return result, registrationErr }
	if err := stageCtx.Err(); err != nil { return result, err }
	if collectorErr != nil { return result, fmt.Errorf("%s collector: %w", s.Name(), collectorErr) }
	return result, nil
}

// NewDNSStage wires the existing DNS collector into a shared investigation.
// DNS resolution is passive with respect to the target and does not authorize
// active TCP/TLS/HTTP checks against addresses discovered by DNS.
func NewDNSStage(target string) *CollectorStage {
	return &CollectorStage{
		StageName: "dns",
		Collector: &collectors.DNS{Target: target},
		Accept: func(event events.Event) bool { return event.Type == events.EventDNSRecordFound },
		Convert: evidence.FromDNSEvent,
	}
}
