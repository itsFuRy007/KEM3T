# Phase 7 Storage Optimization Audit

## Decision

No additional SQLite schema or index change is retained for Phase 7.

KEM3T already keeps the storage changes that have demonstrated a concrete purpose:

- `observations(evidence_id, observed_at, id)` supports evidence-scoped observation history ordering.
- `collection_runs(target, started_at DESC, id DESC)` supports target-scoped newest-first collection-run history.

## Measured experiment

The proposed chronological observation index `(observed_at, id)` was benchmarked against the existing schema at the 5,000-record scale.

| Variant | `LoadAll` read time | Result |
| --- | ---: | --- |
| Baseline | ~18.0 ms | retained |
| `(observed_at, id)` index | ~17.9 ms | rejected |

The observed difference is effectively noise for the benchmark workload, while the additional persistent index would add write and storage overhead. The experiment was therefore intentionally not merged.

## Why no further speculative index is added

`LoadAll` is a full-history operation. Adding another ordering index without a demonstrated workload benefit would increase persistent storage and write maintenance without changing the application's observable behavior enough to justify it.

`LoadCollectionRuns` already has the target-scoped index required by its filtered history path. A new global chronological index would likewise be speculative until a measured workload demonstrates a meaningful improvement.

SQLite durability settings are also left unchanged: KEM3T stores evidence and observations, so trading durability for write throughput is not an acceptable optimization without an explicit product requirement.

## Phase 7 conclusion

The measurement-first policy is satisfied: storage changes are retained only when their benefit is demonstrated, and the failed chronological-index experiment remains excluded from the production schema.

Future storage optimization should start with a new measured workload rather than adding indexes speculatively.
