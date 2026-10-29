# Phase 8 — Investigation Workflow

Phase 8 focuses on turning KEM3T's existing collection, provenance, history, graph, and intelligence capabilities into a coherent investigation workflow.

## Initial workflow

1. **Scope** — define the authorized target set.
2. **Collect** — gather bounded observations from available providers.
3. **Correlate** — connect entities only through evidence-backed relationships.
4. **Discover** — surface convergences, paths, pivots, and temporal changes.
5. **Assess** — attach confidence, alternatives, and supporting/contradicting evidence.
6. **Verify** — produce concrete next checks instead of treating hypotheses as conclusions.
7. **Export** — preserve structured investigation state for downstream tooling.

The workflow coordinates existing capabilities; evidence and observation records remain authoritative.

## Principles

- **Scope isolation:** cross-target relationships are leads, not aggregate findings.
- **Evidence traceability:** discoveries remain traceable to correlations, observations, and evidence.
- **Temporal honesty:** a missing observation is not proof of global disappearance.
- **Uncertainty preservation:** confidence, alternatives, and verification requirements stay attached to results.
- **Determinism:** equivalent inputs produce stable ordering for diffable, testable output.

## Implementation boundary

The first implementation increment establishes a structured investigation result boundary and reuses the existing `IntelligenceReport` rather than creating a parallel analytical model. Presentation-specific formats and CLI orchestration should build on this boundary.
