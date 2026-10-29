# Phase 8 — Investigation Workflow

Phase 8 turns KEM3T's existing collection, provenance, history, graph, and intelligence capabilities into a coherent investigation workflow.

## Workflow

1. **Scope** — define the authorized target set.
2. **Collect** — gather bounded observations from available providers.
3. **Correlate** — connect entities only through evidence-backed relationships.
4. **Discover** — surface convergences, paths, pivots, and temporal changes.
5. **Assess** — attach confidence, alternatives, and supporting/contradicting evidence.
6. **Verify** — produce concrete next checks instead of treating hypotheses as conclusions.
7. **Export** — preserve structured investigation state for downstream tooling.

Existing evidence and observation records remain authoritative; the workflow does not create a second source of truth.

## Principles

- Cross-target relationships are investigation leads, not aggregate findings.
- Discoveries remain traceable to correlations, observations, and evidence.
- Missing observations are never presented as proof of global disappearance.
- Confidence, alternatives, and verification requirements remain attached to results.
- Equivalent inputs should produce stable ordering for diffable, testable output.

## Implementation boundary

The first increment establishes a structured investigation result boundary that reuses the existing `IntelligenceReport`. Presentation-specific formats and CLI orchestration should build on that boundary rather than creating parallel analytical models.
