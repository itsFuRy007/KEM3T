# Controlled Local Validation Lab

This lab is the first executable baseline for KEM3T's pre-release validation. It creates its own services, records expected facts independently, runs KEM3T only against IPv4 loopback, and saves reproducible logs plus SHA-256 digests.

## Safety boundary

- The harness binds every service to `127.0.0.1`.
- KEM3T receives only the exact loopback address and fixture ports.
- The harness does not perform DNS, CT, RDAP, ASN, passive-DNS, or threat-intelligence requests.
- Do not change the target to a public hostname or IP. Public/real-world testing requires a separate written authorization and scope record.
- The TLS certificate and private key are generated for this run. The private key is written under the output directory; do not publish it.

## Requirements

- Go version required by the repository's `go.mod`.
- Python 3.10 or newer.
- OpenSSL 1.1.1 or newer (the script uses `openssl req -addext`).
- Linux, macOS, or another environment that supports binding local TCP sockets.

## Run

From the repository root:

```bash
python3 scripts/validation-lab/run.py
```

To choose a different ignored output directory:

```bash
python3 scripts/validation-lab/run.py --output-dir .kem3t/validation-runs/local-baseline-$(date +%Y%m%d-%H%M%S)
```

The runner builds the CLI once, starts an HTTP fixture and a TLS fixture on loopback, reserves then releases a closed-port candidate, and runs four isolated cases:

1. TCP open: the HTTP fixture listener must be classified OPEN.
2. TCP closed: the released port is expected to be classified CLOSED.
3. HTTP: KEM3T must observe status 200 and the fixture title.
4. TLS: KEM3T must extract a certificate fingerprint and report `Verified: false` for the self-signed certificate.

A successful run exits with status 0. Any command failure or missing expected output token makes the run fail.

## Outputs

The default output directory is `.kem3t/validation-runs/local-baseline/` and contains:

- `kem3t`: the exact CLI binary used by the run.
- `run.json`: commit-independent run metadata, exact commands, dynamic ports, case results, and artifact hashes.
- `*/output.log`: stdout/stderr for each KEM3T case.
- `*/snapshots/`: per-case local evidence and history data.
- `fixture-cert.pem` and `fixture-key.pem`: generated local TLS fixture material.
- `build.log` and `certificate-generation.log`: setup logs.

The output directory is under `.kem3t/`, which is excluded from version control. Before sharing a run, remove the private key and review every artifact for sensitive data. Keep the original local run intact for reproducibility.

## Independent ground truth

The expected facts are defined in [ground-truth.json](ground-truth.json). They are based on how the harness constructs its listeners and responses, not on KEM3T output. Dynamic ports are represented by roles (`<http_open>`, `<tls_open>`, and `<closed>`) and are resolved in `run.json`.

The fixture establishes only local observations. It does not validate public DNS, ownership, ASN/provider attribution, CT/RDAP coverage, passive DNS, threat intelligence, cross-host correlations, or multi-hop graph paths. Those remain separate validation workstreams.

## Interpretation rules

- OPEN means a TCP connection succeeded at collection time; it is not a vulnerability verdict.
- CLOSED is expected only for the port released by the fixture. A race with another local process is possible; record a deviation rather than changing the expected result after seeing KEM3T output.
- The HTTP title/header identify the test fixture only; they do not prove production software identity.
- The self-signed certificate should be extractable but untrusted.
- A missing result is a collection limitation or test failure to investigate, not permission to infer the opposite fact.

## Run record

Keep `run.json`, logs, the KEM3T commit, Go version, and the ground-truth dataset version together. Do not publish the generated private key. Do not change the ground-truth file to make a failed run pass; update it only when the fixture's independently verified behavior intentionally changes.
