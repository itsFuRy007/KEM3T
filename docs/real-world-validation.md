# Real-World Validation Plan

## Purpose

This plan defines a repeatable, evidence-led validation process for KEM3T before release. It evaluates collection reliability and whether the investigation engine produces accurate, explainable, appropriately scoped discoveries—not simply whether commands complete successfully.

Validation is limited to infrastructure that the project maintainers own or have explicit permission to assess. A publicly reachable service is not, by itself, permission to test it.

## Validation principles

1. **Authorization before collection.** Record the owner, authorization basis, permitted targets, permitted methods, time window, and contact/stop procedure before any active test.
2. **Ground truth before execution.** Document expected assets and relationships independently before running KEM3T. Do not derive expected answers from KEM3T output.
3. **Evidence before attribution.** A relationship is not accepted merely because two assets share an IP, certificate, ASN, provider, or historical record.
4. **Unknown is not false.** Mark facts that cannot be independently verified as unknown and exclude them from precision/recall denominators.
5. **Repeatability.** Preserve the exact KEM3T commit, Go toolchain, command, configuration, target scope, run time, and sanitized outputs.
6. **Safe scope.** Active TCP/TLS/HTTP checks remain opt-in and limited to explicitly authorized targets. Discovered subdomains and IPs do not expand authorization.
7. **No unsupported certainty.** Reports must distinguish observations, correlations, hypotheses, and investigator-verified conclusions.

## Test stages

### Stage 0 — Authorization and test inventory

Create one test record per environment with:

- Environment ID and short description.
- Asset owner and authorization reference (do not publish private authorization documents).
- Exact in-scope domains, IPs, and ports.
- Allowed collection modes: DNS, CT/RDAP, passive DNS/OTX, TCP, TLS, HTTP.
- Explicitly excluded assets and methods.
- Test window, rate limits, contact, and stop conditions.
- Data handling and retention requirements.

Do not run active collection until this record is approved.

### Stage 1 — Controlled baseline

Start with a small environment whose configuration and relationships are known independently. Prefer a local lab or a dedicated domain and services controlled by the project maintainer.

Include representative cases where available:

- DNS: A/AAAA, CNAME, MX, NS, TXT, multiple addresses, absent records, and changing answers.
- Network/service: known open and closed ports on explicitly authorized hosts.
- TLS: valid certificate, certificate metadata, verification failure, and certificate rotation where controllable.
- HTTP: status codes, redirects, bounded response bodies, missing title, and cross-host redirect rejection.
- Scope: an in-scope root with a known subdomain and a deliberately out-of-scope sibling or unrelated host.
- History: two or more snapshots with a known change and a known unchanged asset.

The baseline should prove what KEM3T can and cannot observe under controlled conditions before testing less predictable external environments.

### Stage 1a — Automated loopback baseline

The repository now includes a deterministic local fixture at [docs/validation-lab/README.md](validation-lab/README.md), a runner at `scripts/validation-lab/run.py`, and an independent expected-facts dataset at [docs/validation-lab/ground-truth.json](validation-lab/ground-truth.json).

Run it from the repository root:

```bash
python3 scripts/validation-lab/run.py
```

The runner binds only to `127.0.0.1`, creates HTTP and self-signed TLS services, and checks one known-open and one released/expected-closed TCP port. It records exact commands, output hashes, dynamic ports, toolchain metadata, and per-case results under the ignored `.kem3t/validation-runs/local-baseline/` directory.

This is a controlled network/service baseline, not a complete validation of DNS, CT/RDAP, ASN attribution, passive DNS, external threat intelligence, multi-host correlations, or real-world infrastructure. The self-signed certificate is expected to be extracted but not trusted. A mismatch must be recorded as a fixture deviation or KEM3T defect; do not edit the expected facts merely to make a run pass.


### Stage 2 — Authorized real-world environments

After the controlled baseline, test a small number of owner-approved environments with different configurations, such as:

- A simple domain with direct DNS records and one HTTPS service.
- A domain using a CDN or reverse proxy.
- A domain with multiple subdomains and independently operated services.
- An environment with multiple IPs, changing DNS, or IPv4/IPv6 differences.

Use passive collection first. Enable active TCP/TLS/HTTP collection only for exact approved targets and ports. Do not scan third-party shared infrastructure merely because DNS or an external provider returned its address.

For each run, record source availability, rate limiting, timeouts, partial failures, collection duration, and whether repeated runs produce explainable differences.

### Stage 3 — Ground-truth intelligence evaluation

Build a benchmark corpus from controlled assets and independently verified relationships. Each expected relationship must identify:

- Source entity and destination entity.
- Relationship type and direction.
- Scope and validity interval, where relevant.
- Independent source(s) used to establish the expected fact.
- Verification status: confirmed, contradicted, or unknown.
- Important caveats (shared hosting, CDN, provider-wide ASN, historical-only evidence, etc.).

Evaluate KEM3T output against this corpus using normalized entity identifiers and relationship types. Keep the ground-truth file separate from the run output to avoid circular evaluation.

## Metrics and interpretation

| Metric | Definition | Important caveat |
| --- | --- | --- |
| Relationship precision | Correct emitted relationships / all emitted relationships that can be adjudicated | Unsupported or contradicted claims count as false positives; unknown cases are reported separately |
| Relationship recall | Correct emitted expected relationships / all independently confirmed expected relationships that were observable in the test window | Do not count unavailable or unobservable facts as misses |
| False-positive rate | Unsupported or contradicted emitted relationships / adjudicable emitted relationships | Report counts and examples, not only a percentage |
| Evidence coverage | Emitted relationships with traceable supporting evidence / all emitted relationships | Evidence presence does not automatically prove the interpretation |
| Path validity | Multi-hop paths whose every edge is independently supported / all adjudicable emitted paths | A valid path does not prove common ownership or control |
| Explanation quality | Whether a researcher can identify evidence, relevance, alternatives, limitations, and next verification steps | Use a documented reviewer rubric |
| Abstention quality | Whether KEM3T leaves a claim unresolved when evidence is insufficient | Unsupported attribution is worse than a clearly stated unknown |

Do not set arbitrary release thresholds before the first pilot. Establish a baseline, review errors, then agree on explicit thresholds and document why they are appropriate.

## Required qualitative review

For each significant discovery, reviewers should answer:

1. Was the expected relationship discovered?
2. Is every relationship edge supported by traceable evidence?
3. Does the evidence support the exact interpretation, or only a weaker correlation?
4. Could shared hosting, CDN infrastructure, a common provider, stale passive DNS, or another alternative explain the observation?
5. Does a multi-hop path remain valid when each edge is inspected independently?
6. Does the report explain why the discovery matters and what to verify next?
7. When evidence is insufficient or conflicting, does KEM3T state that limitation rather than inventing a conclusion?

Record both positive and negative examples. Do not hide false positives or conflicting evidence.

## Run record

For every validation run, preserve a sanitized record containing:

- Validation case ID and environment ID.
- KEM3T source commit and version.
- Go toolchain version, OS, and architecture.
- Exact command and non-secret configuration.
- Start/end timestamps and target scope.
- Collector/provider availability and partial failures.
- Output artifact names and SHA-256 checksums.
- Ground-truth version used for comparison.
- Expected, observed, missed, false-positive, and unknown relationships.
- Reviewer notes, issue links, and remediation status.

Never commit API keys, credentials, private authorization documents, or sensitive target data. Redact personal data and secrets before publishing examples.

## Exit criteria for this phase

Real-world validation is complete only when:

- The authorization and scope records exist for every tested environment.
- The controlled baseline is repeatable and its expected observations are documented.
- At least one approved real-world environment has been tested without scope expansion.
- Partial failures and provider limitations are recorded rather than silently discarded.
- Findings are reproducible from the recorded commit, command, and sanitized artifacts.
- All material correctness and scope-control issues are filed for remediation.

Completion of this phase does not by itself establish intelligence quality or release readiness; those require the separate ground-truth and release-engineering gates in the roadmap.

## Initial execution checklist

- [ ] Run the automated loopback baseline and preserve its run record.
- [ ] Select an additional controlled lab or dedicated domain under project-owner control for DNS/history and broader relationship tests.
- [ ] Complete the authorization and scope record.
- [ ] Write expected DNS, service, TLS, HTTP, and history facts independently before running KEM3T.
- [ ] Run passive collection and inspect the evidence-backed report.
- [ ] Enable active checks only for explicitly authorized hosts and ports.
- [ ] Compare observed output with the independent expected facts.
- [ ] Save sanitized run metadata and record defects as GitHub issues.
