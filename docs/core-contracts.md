# KEM3T Core Contracts

This document records the current extension contracts between collection, investigation, evidence, and analysis components. It is a compatibility guide for contributors; it does not promise that every internal package is a public Go API.

## Design invariants

1. **Evidence is the source of truth.** Graph edges, correlations, discoveries, narratives, and plans are derived views. They must retain references to the evidence and observations that support them.
2. **Observation is not attribution.** A shared address, certificate, provider, ASN, or pivot is a lead. It must not silently become an ownership, control, vulnerability, compromise, or maliciousness claim.
3. **Scope is explicit.** A stage may collect only within the scope supplied by its caller. Discovering a hostname or IP does not authorize active checks against it.
4. **Cancellation is cooperative.** Long-running work must accept and check the caller's context, and waits must be interruptible.
5. **Partial success is preserved.** A failed source must not erase evidence already contributed by successful sources. Failures and source limitations remain visible.
6. **Determinism matters.** Derived output should use stable identifiers and deterministic ordering where the underlying facts permit it.
7. **Persistence changes require evidence.** Keep schema, index, caching, and batching changes only when a representative benchmark demonstrates a meaningful benefit without weakening durability or correctness.

## Investigation extension points

### `investigation.Stage`

A stage is one bounded unit of collection or enrichment:

```go
type Stage interface {
    Name() string
    Run(context.Context, string, *evidence.Registry) (StageResult, error)
}
```

Contract:

- `Name` must be non-empty and unique within one investigation run. Names are operational identities used for duplicate-stage protection and reporting; do not make them depend on timestamps or random values.
- `Run` receives the caller's context, the normalized investigation target, and the shared registry. It must not open, replace, or close that registry.
- A stage must not widen the caller's authorized scope. In particular, passive discovery does not grant permission for active TCP, TLS, or HTTP collection.
- A stage should return counts and source limitations in `StageResult`; the registry remains the authoritative store for the actual records.
- Return an error when the stage cannot complete its responsibility. If it registered useful records before failing, leave those records intact and report the failure; the orchestrator preserves partial success.
- Respect cancellation in network requests, worker waits, channel sends, and retry/backoff delays.
- Do not mutate records after registration. Evidence and observations are validated and stored by the registry.

### `investigation.Planner`

A planner may schedule additional bounded stages after a stage completes:

```go
type Planner interface {
    Next(context.Context, PlanningState) ([]Stage, error)
}
```

Contract:

- Planning is driven by newly collected evidence and the current investigation state, not by untrusted instructions embedded in provider data.
- Returned stages must be non-nil, named, unique in the run, bounded, and within the caller's explicit authorization scope.
- The engine enforces a maximum stage count. A planner must still avoid redundant work and explain its selection through predictable stage identities.
- A planner error is visible as a partial investigation failure; already collected evidence is retained.
- Treat `PlanningState` as a snapshot for decision-making. Do not retain it as mutable shared state or modify its slices.
- A completed task or investigator feedback is not proof that the underlying hypothesis is true.

## Collection contracts

### Collector event stream

Existing collectors expose a bounded event-stream shape consumed by the investigation adapter:

```go
Run(context.Context, chan<- events.Event) error
```

Collectors must:

- Validate events before emission.
- Close the output channel when the run ends.
- Stop sending when the context is canceled.
- Return meaningful errors instead of encoding failures as successful empty output.
- Emit observations about what was actually measured; do not infer software identity, ownership, or vulnerability from a port number or response header.

The investigation adapter validates each event, checks its target against the requested scope, converts it to evidence plus an observation, and registers both in the shared registry.

### `collectors.DNSResolver`

DNS resolver injection is intentionally narrow:

```go
type DNSResolver interface {
    LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}
```

Implementations should honor context cancellation and return resolver results without inventing addresses. Production defaults to Go's `net.DefaultResolver`; tests and controlled environments can inject deterministic implementations.

## Evidence and observation contracts

- `evidence.Evidence` is the durable normalized fact record. Its identity must be stable for the same logical fact under the same identity scheme.
- `evidence.Observation` records when and from which source evidence was observed, including original event references. Multiple observations may support one evidence record over time.
- Every observation must reference an existing evidence ID. Duplicate IDs and invalid records are errors, not silently overwritten.
- Use `Registry.AddBatch` when a set of evidence and observations must commit atomically. It validates before mutation and, for persistent registries, commits the SQLite transaction before changing in-memory state.
- Treat values returned from registry read methods as snapshots. Do not use internal maps or assume returned slices are live views.
- The registry owns its persistence lifecycle. The caller that opens a persistent registry is responsible for closing it exactly once when all users are finished. A stage must never close it.
- The current persistence implementation is SQLite-backed. Do not add a storage interface or alternate backend until a real second implementation or test seam justifies the extra contract.

## Derived analysis contracts

- Normalization may reject malformed or unsupported events, but it must preserve rejection reasons so callers can distinguish absence from rejected input.
- Graph construction must reject broken provenance references and produce deterministic node/edge ordering.
- Correlations must identify their signal dimension and retain evidence/observation references plus interpretation limits.
- Multi-hop paths must model the intermediate pivot explicitly; they do not establish a direct relationship between the endpoints.
- Recurring pivots require repeated paths, multiple connected entities, and multiple signal types. They remain low-confidence investigation leads.
- Narratives and plans must point back to findings, gaps, paths, or other report objects. Suggested actions must not be represented as completed work until investigator feedback is supplied.
- Qualitative confidence and priority are not probabilities.

## Compatibility policy

- Prefer additive fields and additive methods over changing the meaning or type of existing fields.
- Preserve existing CLI flags, JSON field names, and serialized meanings unless a versioned migration is explicitly designed and documented.
- When changing an interface method, first identify every in-repository implementation and call site, add tests for old and new behavior, and document the migration.
- Do not expose implementation-only interfaces as stable extension APIs without a concrete supported use case.
- New collectors should integrate through the existing event/evidence/observation path unless a documented limitation requires a new contract.

## Validation expected for contract changes

Before merging a change that affects a core contract, run:

```bash
gofmt -l .
go test -count=1 ./...
go test -race -p 1 -count=1 ./...
go vet ./...
go build ./...
go mod verify
git diff --check
```

Add focused tests for invalid input, duplicate identity, cancellation, partial failure, scope boundaries, deterministic output, and persistence rollback where applicable. A green unit test suite does not replace authorized real-world validation or a security review.
