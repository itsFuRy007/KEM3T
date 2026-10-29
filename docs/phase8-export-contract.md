# Phase 8 — Structured Investigation Export Contract

The Phase 8 export contract is designed around one principle: exported data must preserve enough structure to continue an investigation outside the CLI without turning analytical interpretation into a verdict.

## Contract shape

A future structured export should contain these top-level sections:

- `schema_version` — explicit contract version.
- `investigation` — target scope and investigation metadata.
- `entities` — deduplicated entities participating in the investigation.
- `relationships` — evidence-backed graph relationships.
- `observations` — timestamped observations with provenance references.
- `discoveries` — higher-order discoveries such as convergences, paths, and recurring pivots.
- `hypotheses` — hypotheses with confidence, alternatives, and verification requirements.
- `changes` — historical changes tied to observed snapshots.

## Required properties

- IDs are stable within an export and are used for references instead of duplicating large objects.
- Collections use deterministic ordering.
- Empty collections are represented explicitly when the schema requires them.
- Timestamps retain their source precision and are not silently converted to local time.
- Scope is represented explicitly.
- Evidence references are preserved rather than flattened into presentation strings.
- Confidence is represented as analytical confidence, never as a claim of ownership, compromise, or maliciousness.

## Compatibility

The schema version is mandatory so consumers can reject or migrate incompatible exports deliberately. New optional fields may be added without changing the meaning of existing fields; semantic changes require a new schema version.

## Non-goals

This contract does not define a web UI, PDF layout, terminal colors, or provider-specific raw response formats. Those are presentation concerns and must not become the canonical investigation model.
