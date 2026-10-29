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

## Implemented foundation

- Versioned JSON export envelope with explicit investigation scope.
- DNS exports include the current snapshot, optional previous snapshot, baseline state, detected changes, and history comparison.
- Export validation cross-checks target scope, snapshot chronology, observed address sets, and detected changes before serialization.
- Snapshot-relative removals are named explicitly; they are not claims of global infrastructure disappearance.
- CLI writes complete exports atomically with owner-only file permissions.

## Remaining Phase 8 direction

The current export work establishes a reliable boundary for one DNS investigation. The next increments should make the workflow consistent across collection modes, represent multi-target investigations without collapsing target scope, and provide a researcher-oriented summary that links every suggested next step to its supporting evidence.

Presentation-specific formats must build on this boundary rather than creating parallel analytical models.
