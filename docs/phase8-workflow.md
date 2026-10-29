# Phase 8 — Investigation Workflow

Phase 8 focuses on turning KEM3T's existing collection, provenance, history, graph, and intelligence capabilities into a coherent investigation workflow.

## Goals

- Preserve evidence provenance from collection through discovery and reporting.
- Make the investigation state explicit rather than forcing users to mentally connect separate CLI commands.
- Keep target scope explicit at every stage.
- Make uncertainty, alternative explanations, and verification requirements visible.
- Prefer structured machine-readable output as the foundation for future reports and integrations.
- Avoid hiding analytical limitations behind presentation features.

## Initial workflow model

An investigation is conceptually:

1. **Scope** — define the authorized target set.
2. **Collect** — gather bounded observations from available providers.
3. **Correlate** — connect entities only through evidence-backed relationships.
4. **Discover** — surface convergences, paths, pivots, and temporal changes.
5. **Assess** — attach confidence, alternatives, and supporting/contradicting evidence.
6. **Verify** — produce concrete next checks instead of treating hypotheses as conclusions.
7. **Export** — preserve the structured investigation state for downstream tooling.

The workflow is a coordination model, not a new source of truth. Existing evidence and observation records remain authoritative.

## Phase 8 principles

### Scope isolation
Every investigation result must remain attributable to its requested target scope. Cross-target relationships may be surfaced as leads, but they must not silently become aggregate findings.

### Evidence traceability
A user must be able to move from a discovery to its relationship/correlation, then to the observation and evidence that support it.

### Temporal honesty
A change means that KEM3T observed a difference between collected snapshots. It does not prove that an asset globally appeared, disappeared, or changed outside the observed collection window.

### Uncertainty preservation
Low-confidence discoveries remain low-confidence. Alternative explanations and verification steps are part of the result, not optional prose added later.

### Determinism
Equivalent inputs should produce stable ordering so CLI output and future exports are diffable and testable.

## Initial implementation boundary

The first Phase 8 increment should establish the structured investigation result boundary before adding presentation-specific formats. It should reuse existing `IntelligenceReport`, evidence, observation, history, and discovery models rather than creating a parallel data model.

Future Phase 8 increments can build CLI workflow orchestration and structured export formats on top of this boundary.
