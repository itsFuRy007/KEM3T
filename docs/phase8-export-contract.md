# Phase 8 — Structured Investigation Export Contract

KEM3T exports a versioned JSON envelope around its existing target-scoped intelligence report. DNS exports also preserve the collection and temporal context that produced the report.

## JSON envelope

- `schema_version` — mandatory export contract version (`1`).
- `investigation.target` — normalized target scope for this export.
- `collection` — DNS collection context, when supplied.
- `report` — the existing `IntelligenceReport`, including findings, correlations, discoveries, hypotheses, verification assessments, and prioritized findings.

The report remains authoritative. The envelope does not duplicate or reinterpret analytical records.

## DNS collection context

The optional `collection` object contains:

- `baseline_created` — whether this run created the first stored baseline.
- `current_snapshot` — target, UTC collection timestamp, and normalized observed addresses.
- `previous_snapshot` — the prior snapshot when a comparison was possible.
- `changes` — target-scoped address additions/removals between those two snapshots.
- `history` — explicit counts and address sets for added, removed, and unchanged observations.

History uses `added_between_snapshots`, `removed_between_snapshots`, and `unchanged_between_snapshots`. A removed address means it was not present in the newer collection; it does not prove the address or service disappeared from global infrastructure.

## Validation guarantees

- Export target, report target, and every included snapshot/change/history target must match.
- Snapshots must pass their own integrity validation.
- A baseline cannot claim a previous snapshot or temporal comparison.
- A comparison requires both snapshots and matching history counts.
- A previous snapshot cannot be newer than the current snapshot.
- Unsupported schema versions, missing reports, invalid IP addresses, and mismatched scopes are rejected before serialization.
- Existing evidence and observation references remain attached to report records.
- Confidence, alternatives, limitations, and verification steps remain part of the report.
- Timestamps retain their source precision and UTC offset.
- JSON is written to a temporary file in the destination directory and atomically renamed only after the complete payload has been written and synced.
- Export files are created with owner-only permissions where supported.

## CLI

Use DNS mode with `-export-json`:

```sh
kem3t -mode dns -target example.com -export-json ./reports/example.com.json
```

The destination directory is created when needed. The option remains DNS-mode-only in this increment.

## Compatibility

Consumers must inspect `schema_version`. Additive optional fields may be introduced without changing existing semantics; changes to meaning or required structure require a new schema version.

## Non-goals

This increment does not define PDF layout, terminal colors, a web UI, or provider-specific raw response formats. Presentation concerns must not become the canonical investigation model.
