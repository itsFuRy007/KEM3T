<div align="center">

# KEM3T

### NETWORK INTELLIGENCE & INFRASTRUCTURE ANALYSIS

![Go](https://img.shields.io/badge/Go-00ADD8?style=for-the-badge&logo=go&logoColor=white)
![Networking](https://img.shields.io/badge/Networking-Infrastructure-blue?style=for-the-badge)
![Security](https://img.shields.io/badge/Information-Security-red?style=for-the-badge)

*Discover. Analyze. Correlate. Investigate.*

</div>

---

## Overview

KEM3T is a research-oriented networking and information security project for collecting infrastructure observations, preserving evidence, mapping relationships, and supporting explainable investigation.

The goal is to move from isolated scan results toward a traceable picture of infrastructure over time. Correlations and hypotheses are investigative leads—not proof—and should be independently verified.

## Implemented capabilities

- **Historical infrastructure analysis:** persist evidence-backed snapshots for completed DNS, TCP, TLS, and HTTP collection runs; compare like-for-like runs, build a chronological timeline, and flag high-change-volume runs for review.
- **TCP discovery:** check a configurable port range and feed open-port observations into evidence and graph output.
- **TLS inspection:** collect certificate and connection metadata, including subject, issuer, TLS version, verification status, and SHA-256 fingerprint.
- **HTTP/HTTPS observation:** collect response status, final URL, redirect count, selected headers, page title, body-truncation state, and available TLS verification metadata.
- **Evidence and provenance:** register and validate evidence, track collection runs and observations, and persist records.
- **Normalized observations and service model:** convert DNS, TCP, TLS, and HTTP/HTTPS collector events into a shared representation while retaining source, event IDs, timestamps, attributes, and evidence references. Service aggregation combines observations for the same target and port without guessing an application from the port number alone.
- **Infrastructure graph and investigation pivots:** represent observed domains, IPs, TCP ports, HTTP services, network services, and TLS certificates with evidence-backed relationships; traverse deterministic one-hop pivots and inspect relationship provenance without inventing facts.
- **Provider-aware request controls:** external HTTP GETs share a per-provider request-start gate, retry transient transport failures and selected 429/5xx responses, honor bounded `Retry-After` delays, and stop waiting promptly when the investigation is canceled.
- **External infrastructure intelligence:** collect Certificate Transparency (CT), domain RDAP registration metadata, IP RDAP network-range context, origin-ASN mappings, historical passive DNS, and OTX community pulse references. Normalize observations, retain source attribution and retrieval history, and connect CT certificates, registrar/nameserver relationships, IP allocation ranges, ASN/prefix relationships, historical hostname-to-IP mappings, and threat-report references to the evidence-backed graph. External records are investigative leads—not proof of ownership, current hosting, maliciousness, or compromise.
- **Evidence-traceable intelligence workflow:** scope correlations and findings to the requested target, correlate shared live DNS addresses, shared TLS certificate fingerprints, shared Certificate Transparency record IDs across target scopes, and shared historical passive-DNS addresses. Keep historical DNS relationships distinct from current resolution, normalize comparable entities and values, retain evidence and observation references, and expose the exact scope of qualitative confidence. Generate hypotheses with explicit alternatives, limitations, and actionable verification steps. The verification API accepts investigator-classified independent evidence, preserves both supporting and contradicting facts, reports mixed outcomes instead of hiding conflicts, and excludes reused/non-independent evidence from assessment. Qualitative confidence is not silently converted into a probability or verdict.
- **Batch DNS investigations:** validate and deduplicate target lists, run DNS investigations through a bounded worker pool, isolate each target's history/evidence store, preserve input-order output, and report partial failures without discarding successful results.
- **Unified investigation orchestration:** run DNS and external-intelligence stages against one shared evidence registry, then build one evidence-backed graph, target-scoped intelligence report, and mixed-source history snapshot. A bounded adaptive planner can schedule follow-up stages from the evidence already collected. Partial source failures remain visible without discarding successful results.
- **CLI:** run demo, DNS, TCP, TLS, HTTP, unified investigation, history, batch DNS, CT, domain RDAP, IP RDAP, origin ASN, passive DNS, and threat-intelligence modes.

### HTTP/HTTPS safety boundaries

The HTTP collector is deliberately bounded: it inspects only a limited in-memory response-body prefix (up to 1 MiB) for a page title, does not persist response bodies, limits redirects to five, and rejects redirects to a different hostname. In auto mode, an unschemed target is tried over HTTPS first, then HTTP if the HTTPS request fails.

Headers such as Server or X-Powered-By are observations, not reliable proof of software identity or a vulnerability.

## Architecture

~~~text
Target
  → Collection
  → Normalized observations and service aggregation
  → Evidence and provenance
  → Evidence-backed infrastructure graph relationships
  → Correlation and hypotheses
  → Verification and investigation
  → Historical comparison and reports
~~~

The repository separates collection, evidence, graph, intelligence, and orchestration so that new collectors and relationship types can be added incrementally.

## Requirements

- Go **1.26.10**, as declared in go.mod
- Network access for live collection modes
- A target you are authorized to investigate

## Getting started

~~~bash
git clone https://github.com/itsFuRy007/kem3t.git
cd kem3t
go build ./...
go run ./cmd/kem3t -h
~~~

### Examples

Run one unified investigation. DNS, CT, and RDAP use the shared evidence registry; OTX passive-DNS and threat context are added when `OTX_API_KEY` is configured:

~~~bash
go run ./cmd/kem3t -mode investigate -target example.com
~~~

Active TCP/TLS/HTTP checks are deliberately disabled by default. Enable them only when you are authorized to assess the supplied target; the TCP range applies only to that target and is never expanded to DNS-discovered addresses:

~~~bash
go run ./cmd/kem3t -mode investigate -target example.com -enable-active -start-port 1 -end-port 1024 -port 443 -http-scheme auto
~~~

Run the demonstration pipeline:

~~~bash
go run ./cmd/kem3t -mode demo
~~~

Collect DNS observations and compare them with the previous snapshot:

~~~bash
go run ./cmd/kem3t -mode dns -target example.com
~~~

Inspect TCP ports (the default range is 1–1024):

~~~bash
go run ./cmd/kem3t -mode tcp -target example.com -start-port 1 -end-port 1024
~~~

Inspect TLS certificate information:

~~~bash
go run ./cmd/kem3t -mode tls -target example.com -port 443
~~~

Observe an HTTP(S) service:

~~~bash
go run ./cmd/kem3t -mode http -target https://example.com
go run ./cmd/kem3t -mode http -target example.com -http-scheme auto
go run ./cmd/kem3t -mode http -target 127.0.0.1 -http-scheme http -http-port 8080
~~~

Review stored collection-run history:

~~~bash
go run ./cmd/kem3t -mode history
go run ./cmd/kem3t -mode history -target example.com
~~~

Persist an adaptive investigation plan between DNS runs:

~~~bash
go run ./cmd/kem3t -mode dns -target example.com -plan-state .kem3t/plan-state.json -export-json ./reports/example.com.json
~~~

The plan-state file stores the previous plan and an initially empty `feedback` array. After reviewing the printed plan, add investigator feedback using a task ID from that plan. For example, mark an action complete only when you can attach the evidence IDs that support the work:

~~~json
{
  "feedback": [
    {
      "item_id": "task:REPLACE_WITH_PRINTED_ID",
      "outcome": "COMPLETED",
      "evidence_ids": ["your-existing-evidence-id"]
    }
  ]
}
~~~

Accepted outcomes are `COMPLETED` (requires evidence IDs), `INCONCLUSIVE`, `BLOCKED`, and `NOT_APPLICABLE` (each requires a note). Run the same command again; KEM3T will apply the feedback, retain task history, and rebuild the plan against the newly collected report. The state file is written atomically with owner-only permissions. Feedback is investigator-supplied and is not independently verified by KEM3T.

Run bounded DNS investigations from a target file (one hostname/IP per line; blank lines and `#` comments are ignored):

~~~bash
go run ./cmd/kem3t -mode batch-dns -targets-file targets.txt -workers 4
~~~

Batch DNS evidence and snapshots are isolated per canonical target under `.kem3t/snapshots/batch-dns/`. Output follows target-file order. A machine-readable `report.json` summarizes successful/failed targets and surfaces IP addresses observed for multiple target scopes, with per-target collection times and evidence-store paths. Shared IPs are investigation leads—not proof of common ownership or control. Per-target failures are reported without suppressing successful results; the command exits non-zero if any target failed. Use only targets you own or are authorized to assess.

### External intelligence examples

Inspect public Certificate Transparency records and persist their evidence/graph relationships:

~~~bash
go run ./cmd/kem3t -mode ct -target example.com
~~~

Inspect domain registration metadata, registrar labels, and nameservers:

~~~bash
go run ./cmd/kem3t -mode rdap -target example.com
~~~

Inspect the registry-reported IP allocation range for a public address:

~~~bash
go run ./cmd/kem3t -mode iprdap -target 8.8.8.8
~~~

Resolve an IP's origin ASN and enrich it with ASN RDAP:

~~~bash
go run ./cmd/kem3t -mode asn -target 8.8.8.8
~~~

Query historical passive DNS and community pulse context from AlienVault OTX:

~~~bash
go run ./cmd/kem3t -mode pdns -target example.com
go run ./cmd/kem3t -mode threat -target example.com
~~~

OTX endpoints are anonymously accessible subject to provider rate limits. Setting OTX_API_KEY in the environment can improve available quota; KEM3T sends it only as the provider request header and does not print it. The passive-DNS and threat modes use the same provider family, so their results must not be treated as independent corroboration.


DNS snapshots, generalized run snapshots, and the evidence database use .kem3t/snapshots by default. Generalized snapshots are stored under .kem3t/snapshots/history and are captured after successful collection; history mode also reconstructs snapshots for older completed runs. Override the root directory with -snapshot-dir <directory>. Run go run ./cmd/kem3t -h for all flags.

## Project structure

- cmd/kem3t/ — CLI entry point
- internal/collectors/ — demo, DNS, TCP, TLS, and HTTP collectors
- internal/events/ — collection events
- internal/observations/ — normalized collector observations and conservative service model
- internal/evidence/ — evidence validation and persistence
- internal/graph/ — infrastructure graph entities and relationships
- internal/externalintel/ — CT, domain/IP RDAP, origin ASN, passive DNS, and threat-intelligence clients
- internal/changes/ — DNS-specific change detection
- internal/snapshots/ — DNS snapshot handling
- internal/history/ — generalized run snapshots, cross-run comparisons, timelines, and anomaly review signals
- internal/pipeline/ — existing collector-specific collection and analysis pipelines
- internal/investigation/ — shared-registry, multi-source investigation orchestration and bounded adaptive stage planning
- internal/scale/ — bounded, cancellation-aware scheduling primitives for large investigation batches
- internal/batch/ — validated target lists and isolated batch DNS orchestration
- internal/intelligence/ — correlation, hypotheses, prioritization, and reports
- internal/integration/ — integration tests

## Validation

Run these checks before proposing a change:

~~~bash
gofmt -l .
go test -count=1 ./...
go test -race -p 1 -count=1 ./...
go vet ./...
go build ./...
go mod verify
git diff --check
~~~

The race-detector command uses -p 1 to run package tests serially, which has been more reliable in the current development environment. The CI workflow currently runs the full test suite, go vet, and build checks; formatting is reviewed separately with gofmt.

## Development roadmap

The roadmap tracks implemented foundations and remaining validation work; checked items do not imply release readiness.

### Foundation
- [x] Collection events, core pipeline, evidence registration, validation, and persistence
- [x] Initial evidence-backed infrastructure graph and pipeline integration
- [ ] Finalize and document stable core interfaces

### Deep collection
- [x] DNS, TCP, TLS, and bounded HTTP/HTTPS collection
- [x] Shared normalized observations and unified discovered-service model
- [x] Evidence-backed service relationships and collector integration tests
- [x] DNS/TLS edge-case coverage and cross-collector normalization

### Infrastructure graph
- [x] Evidence-backed entities, relationships, and provenance
- [x] Cross-collector infrastructure relationships and deterministic pivots
- [x] Entity lookup and copy-safe evidence/observation provenance

### History
- [x] Evidence-backed snapshots and collection-run history
- [x] Chronological timelines, change comparison, and provenance
- [x] High-change-volume review signals with conservative interpretation

### Intelligence
- [x] Target-scoped correlations, hypotheses, alternatives, and verification
- [x] Convergent discoveries, multi-hop paths, and recurring infrastructure pivots
- [x] Researcher narratives with evidence-linked signals and next steps
- [x] Evidence-gap detection and explicit unresolved questions
- [x] Adaptive investigation planning with ranked actions and investigator feedback
- [x] Preserve conflicting verification evidence and qualitative confidence limits

### External intelligence
- [x] Certificate Transparency and domain/IP RDAP
- [x] Origin ASN and network-prefix context
- [x] Historical passive DNS and community threat-report references
- [x] Persist external observations and connect them to evidence-backed graph relationships
- [x] Preserve provider attribution, timestamps, truncation, and interpretation limits

### Scale
- [x] Bounded, cancellation-aware worker pools and target-list scheduling
- [x] Provider-aware request limits, retries, and backoff
- [x] Performance benchmarks and measured graph-allocation optimization
- [ ] Further storage optimization (retain only changes with demonstrated benefit)

### Usability and investigation workflow
- [x] CLI collection modes and console graph/intelligence output
- [x] Versioned, scope-validated JSON investigation exports with temporal context
- [x] DNS workflow from collection through evidence, report, adaptive plan, and export
- [ ] Unified end-to-end investigation workflow across all collectors and external-intelligence sources
- [ ] Researcher-facing plan feedback workflow refinements and richer report formats

### Hardening
- [x] Unit and integration tests for implemented workflows
- [x] Initial HTTP collection bounds and redirect scope checks
- [ ] Broader malformed-input and failure-mode testing
- [ ] Fuzzing, race-focused regression coverage, and measured performance testing
- [ ] Security review and reproducible release checks

### Real-world validation
- [ ] Test against authorized real-world environments
- [ ] Gather feedback and document limitations
- [ ] Fix edge cases and optimize measured bottlenecks
- [ ] Prepare a release after validation

## Responsible use

Use KEM3T only for infrastructure you own or are authorized to assess. Collection results can be incomplete or change with time; a missing observation does not by itself prove that an asset has disappeared. Correlations and hypotheses are not proof of ownership, compromise, or malicious activity.

## License

KEM3T is licensed under the [MIT License](LICENSE).
