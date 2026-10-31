# Security Review and Release Gates

## Scope

This is a repository-level security baseline for KEM3T, not a penetration-test report, formal code audit, or guarantee that the project is vulnerability-free. The review focuses on the boundaries where untrusted network/provider data enters the application, where investigation scope is enforced, and where evidence and exports are persisted.

## Security properties reviewed

### Collection and authorization boundaries

- Active TCP, TLS, and HTTP collection in unified investigation mode is opt-in.
- Discovered subdomains and IP addresses do not automatically authorize active checks.
- Adaptive DNS follow-up is bounded and restricted to the root domain's namespace.
- HTTP collection bounds response-body inspection and redirect count, enforces same-host redirects within the originally authorized port set (or the default 80/443 set for an unschemed auto target), rejects credential-bearing and HTTPS-downgrade redirects, and redacts query values from persisted URLs and Location headers.
- HTTP evidence validation requires both the original and final URL hosts to match the evidence target and rejects URLs containing credentials.
- CLI output replaces terminal control and Unicode formatting characters in untrusted display values before printing.
- External provider requests use HTTPS endpoints, bounded response sizes, request timeouts, cancellation-aware retry/backoff, and HTTPS-preserving redirect checks even with caller-supplied HTTP clients. OTX requests carrying an API key are restricted to the original HTTPS host.

### Evidence and interpretation boundaries

- Evidence and observation records are validated before registration.
- Observations retain source, timestamp, event references, and evidence linkage.
- Graph relationships, correlations, multi-hop paths, recurring pivots, and threat-intelligence references are investigative leads, not ownership, compromise, vulnerability, or maliciousness verdicts.
- Reports preserve alternative explanations, limitations, and qualitative confidence rather than presenting confidence as probability.
- Export validation checks target scope and temporal consistency before writing output.

### Persistence and local data

- SQLite foreign-key enforcement is enabled.
- Evidence and observation batch writes use a transaction and roll back together on failure.
- JSON plan state and report exports use atomic replacement and owner-only file permissions.
- The default .kem3t/ data directory is excluded from version control.

### Secrets and provider data

- The OTX API key is read from the process environment and sent only in the provider request header; OTX redirects cannot forward it to another host.
- API keys and raw HTTP response bodies are not intended to be included in reports or persisted as evidence.
- Provider data is untrusted input; malformed or out-of-scope records must be rejected or excluded without widening target scope.

## Automated release gates

The CI workflow runs:

1. Unit and integration tests.
2. Race-detector tests.
3. A bounded fuzz smoke test over event, observation, evidence, and report boundaries.
4. Performance benchmark smoke tests.
5. Go vulnerability analysis with a pinned govulncheck release.
6. Module graph consistency and checksum verification.
7. Formatting, vet, and build checks.
8. Two clean, trimpath-enabled CLI builds whose outputs must be byte-identical.
9. The controlled loopback validation lab for known-open/closed TCP, HTTP metadata, and TLS certificate extraction.

The tag-triggered release workflow repeats the validation gates on the exact tagged source before building and publishing release artifacts.

The loopback lab is a narrow controlled baseline. It does not validate external provider coverage, public infrastructure attribution, multi-host relationships, or real-world intelligence quality.

A successful vulnerability scan means no known, reachable Go vulnerability was reported for that analyzed source/build configuration at scan time. It does not cover every operating-system package, runtime environment, configuration, or vulnerability class.

## Release procedure

Before publishing a release:

- Run the full CI workflow on the exact release commit.
- Review all vulnerability-scan findings; document accepted risk and upgrade constraints rather than suppressing findings silently.
- Verify the module graph and checksums.
- Build the CLI twice with the documented reproducible flags and compare the artifacts.
- Record the Go toolchain version, source commit, target OS/architecture, and artifact SHA-256.
- Test the produced artifact in an authorized environment.
- Publish checksums and release notes that state supported platforms, known limitations, and the scope of validation.

### Additional regression coverage

- CT lookup requests the exact apex and the wildcard subdomain namespace separately; both requests share a bounded context.
- ASN origin records preserve distinct prefixes even when multiple routes map to the same ASN.
- Investigation output includes discovery paths, recurring pivots, verification evidence, service surfaces, and graph/report provenance.
- Stage-level errors and provider limitations are carried into the final research narrative so exported reports do not silently omit incomplete collection.

These are code-level protections and deterministic tests. They do not replace independent validation of live provider data or authorized real-world environments.

## Remaining limitations

- Automated static vulnerability analysis is not a substitute for manual review or authorized real-world testing.
- The project has not yet completed an independent penetration test or formal security audit.
- Network/provider behavior can change; a clean scan cannot prove that a target is safe or that collected infrastructure facts are complete.
- Reproducibility is currently checked for two builds on the same CI runner and toolchain. Cross-platform bit-for-bit reproducibility is a separate release-engineering task.
