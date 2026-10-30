# Security Review and Release Gates

## Scope

This is a repository-level security baseline for KEM3T, not a penetration-test report, formal code audit, or guarantee that the project is vulnerability-free. The review focuses on the boundaries where untrusted network/provider data enters the application, where investigation scope is enforced, and where evidence and exports are persisted.

## Security properties reviewed

### Collection and authorization boundaries

- Active TCP, TLS, and HTTP collection in unified investigation mode is opt-in.
- Discovered subdomains and IP addresses do not automatically authorize active checks.
- Adaptive DNS follow-up is bounded and restricted to the root domain's namespace.
- HTTP collection bounds response-body inspection, redirect count, and redirect hostname scope.
- External provider requests use HTTPS endpoints, bounded response sizes, request timeouts, and cancellation-aware retry/backoff.

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

- The OTX API key is read from the process environment and sent only in the provider request header.
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

## Remaining limitations

- Automated static vulnerability analysis is not a substitute for manual review or authorized real-world testing.
- The project has not yet completed an independent penetration test or formal security audit.
- Network/provider behavior can change; a clean scan cannot prove that a target is safe or that collected infrastructure facts are complete.
- Reproducibility is currently checked for two builds on the same CI runner and toolchain. Cross-platform bit-for-bit reproducibility is a separate release-engineering task.
