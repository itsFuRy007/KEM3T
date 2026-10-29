# Phase 8 — Structured Investigation Export Contract

The first export format is a versioned JSON envelope around KEM3T's existing target-scoped intelligence report.

## JSON envelope

- `schema_version` — mandatory export contract version (`1`).
- `investigation.target` — normalized target scope for this export.
- `report` — the existing `IntelligenceReport`, including its findings, correlations, discoveries, hypotheses, verification assessments, and prioritized findings.

The report remains authoritative. The envelope does not duplicate evidence, invent a second analytical model, or upgrade hypotheses into conclusions.

## Required properties

- The export target and report target must both be present and resolve to the same normalized scope.
- Unsupported schema versions, missing reports, and mismatched scopes are rejected before serialization.
- Existing evidence and observation references remain attached to their report records.
- Confidence, alternatives, limitations, and verification steps remain part of the report.
- Timestamps retain their source precision and are not silently converted to local time.
- A missing observation is not represented as proof of global disappearance.
- JSON is written to a temporary file in the destination directory and atomically renamed only after the complete payload has been written and synced.
- Export files are created with owner-only permissions where supported.

## CLI

Use DNS mode with `-export-json` to write the report:

```sh
kem3t -mode dns -target example.com -export-json ./reports/example.com.json
```

The destination directory is created when needed. The option is DNS-mode-only in this first increment.

## Compatibility

Consumers must inspect `schema_version`. Additive optional fields may be introduced without changing existing semantics; changes to meaning or required structure require a new schema version.

## Non-goals

This increment does not define PDF layout, terminal colors, a web UI, or provider-specific raw response formats. Those presentation concerns must not become the canonical investigation model.
