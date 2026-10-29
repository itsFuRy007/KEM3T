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

- **DNS collection and history:** collect DNS observations, save snapshots, and compare subsequent results for address changes.
- **TCP discovery:** check a configurable port range and feed open-port observations into evidence and graph output.
- **TLS inspection:** collect certificate and connection metadata, including subject, issuer, TLS version, verification status, and SHA-256 fingerprint.
- **HTTP/HTTPS observation:** collect response status, final URL, redirect count, selected headers, page title, body-truncation state, and available TLS verification metadata.
- **Evidence and provenance:** register and validate evidence, track collection runs and observations, and persist records.
- **Normalized observations and service model:** convert DNS, TCP, TLS, and HTTP/HTTPS collector events into a shared representation while retaining source, event IDs, timestamps, attributes, and evidence references. Service aggregation combines observations for the same target and port without guessing an application from the port number alone.
- **Infrastructure graph:** represent observed entities and relationships produced by supported collection pipelines, including evidence-backed host-to-network-service relationships when service evidence is available.
- **Initial intelligence workflow:** correlate observations, generate evidence-linked hypotheses with alternatives and verification steps, prioritize findings, and produce an intelligence report.
- **CLI:** run demo, DNS, TCP, TLS, HTTP, and history modes.

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

DNS snapshots and the evidence database use .kem3t/snapshots by default. Override the directory with -snapshot-dir <directory>. Run go run ./cmd/kem3t -h for all flags.

## Project structure

- cmd/kem3t/ — CLI entry point
- internal/collectors/ — demo, DNS, TCP, TLS, and HTTP collectors
- internal/events/ — collection events
- internal/observations/ — normalized collector observations and conservative service model
- internal/evidence/ — evidence validation and persistence
- internal/graph/ — infrastructure graph entities and relationships
- internal/changes/ — change detection
- internal/snapshots/ — DNS snapshot handling
- internal/pipeline/ — collection and analysis orchestration
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
- [ ] Expand DNS/TLS edge-case coverage and cross-collector normalization beyond the initial shared model

### Phase 3 — Infrastructure Graph
- [x] Initial entities, relationships, and provenance links
- [x] Evidence-backed host-to-network-service relationships for normalized service observations
- [ ] Expand entity and relationship types
- [ ] Add investigation pivots between domains, IPs, services, and certificates

### Phase 4 — History
- [x] DNS snapshots and change comparison
- [x] Collection-run history
- [ ] Generalize snapshots and change tracking across collection types
- [ ] Timeline views and anomaly detection

### Phase 5 — Intelligence
- [x] Initial correlation rules
- [x] Hypothesis generation and alternative explanations
- [x] Verification steps and rule-based prioritization
- [x] Initial intelligence reports
- [ ] Improve confidence calibration, traceability, and verification quality

### Phase 6 — External Intelligence
- [ ] Certificate Transparency (CT)
- [ ] RDAP/WHOIS
- [ ] ASN and network ownership context
- [ ] Passive DNS
- [ ] Threat-intelligence integrations

### Phase 7 — Scale
- [x] Bounded HTTP body inspection and redirect handling
- [x] Configurable TCP port range
- [ ] Shared concurrency controls and rate limits
- [ ] Target lists and large-scope scheduling
- [ ] Performance benchmarks and storage optimization

### Phase 8 — Usability
- [x] CLI modes for demo, DNS, TCP, TLS, HTTP, and history
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
