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
- **External infrastructure intelligence:** collect Certificate Transparency (CT), domain RDAP registration metadata, IP RDAP network-range context, origin-ASN mappings, historical passive DNS, and OTX community pulse references. Normalize observations, retain source attribution and retrieval history, and connect CT certificates, registrar/nameserver relationships, IP allocation ranges, ASN/prefix relationships, historical hostname-to-IP mappings, and threat-report references to the evidence-backed graph. External records are investigative leads—not proof of ownership, current hosting, maliciousness, or compromise.
- **Evidence-traceable intelligence workflow:** scope correlations and findings to the requested target, correlate shared live DNS addresses, shared TLS certificate fingerprints, shared Certificate Transparency record IDs across target scopes, and shared historical passive-DNS addresses. Keep historical DNS relationships distinct from current resolution, normalize comparable entities and values, retain evidence and observation references, and expose the exact scope of qualitative confidence. Generate hypotheses with explicit alternatives, limitations, and actionable verification steps. The verification API accepts investigator-classified independent evidence, preserves both supporting and contradicting facts, reports mixed outcomes instead of hiding conflicts, and excludes reused/non-independent evidence from assessment. Qualitative confidence is not silently converted into a probability or verdict.
- **CLI:** run demo, DNS, TCP, TLS, HTTP, history, CT, domain RDAP, IP RDAP, origin ASN, passive DNS, and threat-intelligence modes.

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
- internal/pipeline/ — collection and analysis orchestration
- internal/scale/ — bounded, cancellation-aware scheduling primitives for large investigation batches
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

The project is under active development. Checkboxes below distinguish implemented foundations from remaining work; they are not a release-readiness claim.

### Phase 1 — Foundation
- [x] Collection events and core pipeline foundation
- [x] Evidence registration, validation, and persistence
- [x] Initial graph construction and pipeline integration
- [ ] Finalize and document stable core interfaces

### Phase 2 — Deep Collection
- [x] DNS collection and historical snapshots
- [x] TCP port discovery
- [x] TLS certificate inspection
- [x] Initial bounded HTTP/HTTPS service observation
- [x] **Step 1 (foundation):** Add a shared normalized observation shape for DNS, TCP, TLS, and HTTP/HTTPS events
- [x] **Step 2 (foundation):** Add a unified discovered-service model with target, port, transport, evidence references, source, timestamp, and observed indicators
- [x] **Step 3:** Integrate normalized service identification into DNS, TCP, TLS, and HTTP collection pipelines using observed behavior and evidence, not port numbers alone
- [x] **Step 4:** Connect evidence-backed unified service records to the Infrastructure Graph
- [x] **Step 5:** Add integration coverage for Collector → normalized observation → Evidence → Graph
- [x] Expand DNS/TLS edge-case coverage and cross-collector normalization beyond the initial shared model

### Phase 3 — Infrastructure Graph
- [x] Initial entities, relationships, and provenance links
- [x] Evidence-backed host-to-network-service relationships for normalized service observations
- [x] Expand entity and relationship types across DNS, TCP ports, HTTP services, network services, and TLS certificates
- [x] Add deterministic investigation pivots across domains, IPs, TCP ports, HTTP/network services, and certificates
- [x] Add entity/relationship lookup and copy-safe evidence/observation provenance access

### Phase 4 — History
- [x] DNS snapshots and change comparison
- [x] Collection-run history
- [x] Generalize evidence-backed snapshots and change tracking across DNS, TCP, TLS, and HTTP runs
- [x] Persist snapshots safely and deterministically for completed collection runs
- [x] Build chronological timelines with added/removed/updated changes and evidence provenance
- [x] Detect high-change-volume review signals without presenting heuristics as proof

### Phase 5 — Intelligence
- [x] Initial correlation rules
- [x] Hypothesis generation and alternative explanations
- [x] Verification steps and rule-based prioritization
- [x] Initial intelligence reports
- [x] Scope both findings and correlations to the requested target; reject mixed-scope aggregate findings
- [x] Correlate shared DNS addresses and shared TLS certificate fingerprints with evidence/observation provenance
- [x] Make confidence scope explicit and keep shared-infrastructure hypotheses conservatively low-confidence
- [x] Validate provenance links and expose supporting evidence/observation references in reports
- [x] Add actionable verification criteria, alternatives, and structured independent support/contradiction assessment

### Phase 6 — External Intelligence
- [x] Certificate Transparency (CT) lookup with scope validation, bounded responses, deduplication, and explicit caveats
- [x] Persist CT evidence and timestamped observations; expose CT search-result and certificate-name relationships in the provenance graph
- [x] Correlate shared CT certificate record IDs across distinct target scopes with evidence references and explicit non-ownership caveats
- [x] Domain RDAP via IANA bootstrap with minimized metadata, registration lifecycle events, and privacy-conscious contact-data exclusion
- [x] Persist RDAP facts and timestamped observations; connect registrar and nameserver relationships to the evidence-backed graph
- [x] Origin-ASN lookup through Team Cymru origin DNS via DNS-over-HTTPS, enriched with IANA-bootstrapped ASN RDAP
- [x] Persist ASN findings with mapping/RDAP source attribution and connect IP → ASN → prefix relationships in the evidence graph
- [x] IP RDAP network-range enrichment via IANA IPv4/IPv6 bootstrap, validated allocation bounds, and evidence-backed IP → registered-range graph edges
- [x] ASN and network ownership context via origin-ASN mapping, authoritative ASN RDAP, and IP allocation-range RDAP
- [x] OTX passive-DNS collection with target-scope filtering, A/AAAA validation, historical timestamps, optional API-key support, and truncation signaling
- [x] Persist passive-DNS facts and time-aware observations; distinguish historical DNS relationships from live DNS edges in the graph
- [x] Correlate historical passive-DNS address overlap across target scopes without presenting it as current resolution or independent source corroboration
- [x] OTX community pulse context for domains/public IPs with evidence-backed pulse links and explicit non-verdict interpretation
- [x] Preserve pulse-count/returned-record differences and note that OTX passive DNS and pulse context are one provider family, not independent corroboration

### Phase 7 — Scale
- [x] Bounded HTTP body inspection and redirect handling
- [x] Configurable TCP port range
- [x] Bounded worker-pool primitive with cancellation-aware scheduling, per-target error isolation, and deterministic result ordering
- [ ] Shared provider-aware rate limits and backoff
- [ ] Target lists and large-scope scheduling
- [ ] Performance benchmarks and storage optimization

### Phase 8 — Usability
- [x] CLI modes for demo, DNS, TCP, TLS, HTTP, history, CT, domain RDAP, IP RDAP, ASN, passive DNS, and threat intelligence
- [x] Console output for graph and intelligence results
- [ ] Structured exports and report formats
- [ ] End-to-end investigation workflow and usability improvements

### Phase 9 — Hardening
- [x] Unit and integration tests for implemented workflows
- [x] Initial HTTP collection bounds and redirect scope checks
- [ ] Broader failure-mode and malformed-input testing
- [ ] Fuzzing, benchmarks, and regression coverage
- [ ] Security review and reproducible release checks

### Phase 10 — Real-world validation
- [ ] Test against authorized real-world environments
- [ ] Gather feedback and document limitations
- [ ] Fix edge cases and optimize measured bottlenecks
- [ ] Prepare a release after validation

## Responsible use

Use KEM3T only for infrastructure you own or are authorized to assess. Collection results can be incomplete or change with time; a missing observation does not by itself prove that an asset has disappeared. Correlations and hypotheses are not proof of ownership, compromise, or malicious activity.

## License

KEM3T is licensed under the [MIT License](LICENSE).
