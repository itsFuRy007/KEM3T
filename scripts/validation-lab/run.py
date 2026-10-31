#!/usr/bin/env python3
"""Run KEM3T against a deterministic, loopback-only validation lab."""

from __future__ import annotations

import argparse
import hashlib
import http.server
import json
import os
import platform
import shutil
import socket
import ssl
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TARGET = "127.0.0.1"
TITLE = "KEM3T Validation Lab"


class LabHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = (
            "<!doctype html><html><head><title>"
            + TITLE
            + "</title></head><body><h1>Controlled local fixture</h1></body></html>"
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-KEM3T-Lab", "controlled-fixture")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def reserve_closed_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((TARGET, 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_case(
    binary: Path,
    output_dir: Path,
    name: str,
    arguments: list[str],
    expected: list[str],
) -> dict[str, object]:
    case_dir = output_dir / name
    case_dir.mkdir(parents=True, exist_ok=True)
    command = [
        str(binary),
        *arguments,
        "-snapshot-dir",
        str(case_dir / "snapshots"),
    ]
    completed = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=90,
    )
    log_path = case_dir / "output.log"
    log_path.write_text(completed.stdout, encoding="utf-8")
    missing = [token for token in expected if token not in completed.stdout]
    passed = completed.returncode == 0 and not missing
    return {
        "name": name,
        "command": command,
        "exit_code": completed.returncode,
        "passed": passed,
        "expected_tokens": expected,
        "missing_tokens": missing,
        "output_file": str(log_path.relative_to(output_dir)),
        "output_sha256": sha256_file(log_path),
    }


def run_test_case(
    output_dir: Path,
    name: str,
    arguments: list[str],
    expected: list[str],
) -> dict[str, object]:
    case_dir = output_dir / name
    case_dir.mkdir(parents=True, exist_ok=True)
    command = ["go", "test", "-v", *arguments]
    completed = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=180,
    )
    log_path = case_dir / "output.log"
    log_path.write_text(completed.stdout, encoding="utf-8")
    missing = [token for token in expected if token not in completed.stdout]
    passed = completed.returncode == 0 and not missing
    return {
        "name": name,
        "command": command,
        "exit_code": completed.returncode,
        "passed": passed,
        "expected_tokens": expected,
        "missing_tokens": missing,
        "output_file": str(log_path.relative_to(output_dir)),
        "output_sha256": sha256_file(log_path),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        default=".kem3t/validation-runs/local-baseline",
        help="directory for sanitized logs and run metadata",
    )
    args = parser.parse_args()

    if shutil.which("go") is None:
        parser.error("Go is required and must be available on PATH")
    if shutil.which("openssl") is None:
        parser.error("OpenSSL is required to create the local self-signed TLS fixture")

    output_dir = (ROOT / args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    binary = output_dir / ("kem3t.exe" if os.name == "nt" else "kem3t")

    build = subprocess.run(
        ["go", "build", "-trimpath", "-buildvcs=false", "-o", str(binary), "./cmd/kem3t"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=180,
    )
    (output_dir / "build.log").write_text(build.stdout, encoding="utf-8")
    if build.returncode != 0:
        print(build.stdout, file=sys.stderr)
        return build.returncode

    http_server = http.server.ThreadingHTTPServer((TARGET, 0), LabHandler)
    http_port = int(http_server.server_address[1])
    http_thread = threading.Thread(target=http_server.serve_forever, daemon=True)
    http_thread.start()

    tls_server: http.server.ThreadingHTTPServer | None = None
    tls_thread: threading.Thread | None = None
    try:
        key_path = output_dir / "fixture-key.pem"
        cert_path = output_dir / "fixture-cert.pem"
        cert_command = [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key_path), "-out", str(cert_path),
            "-days", "2", "-nodes", "-subj", "/CN=127.0.0.1",
            "-addext", "subjectAltName=IP:127.0.0.1",
        ]
        cert_result = subprocess.run(
            cert_command,
            cwd=output_dir,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=60,
        )
        (output_dir / "certificate-generation.log").write_text(
            cert_result.stdout, encoding="utf-8"
        )
        if cert_result.returncode != 0:
            print(cert_result.stdout, file=sys.stderr)
            return cert_result.returncode

        tls_server = http.server.ThreadingHTTPServer((TARGET, 0), LabHandler)
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        tls_server.socket = tls_context.wrap_socket(tls_server.socket, server_side=True)
        tls_port = int(tls_server.server_address[1])
        tls_thread = threading.Thread(target=tls_server.serve_forever, daemon=True)
        tls_thread.start()

        closed_port = reserve_closed_port()
        while closed_port in {http_port, tls_port}:
            closed_port = reserve_closed_port()

        started_at = datetime.now(timezone.utc).isoformat()
        cases = [
            run_case(
                binary, output_dir, "tcp-open",
                ["-mode", "tcp", "-target", TARGET,
                 "-start-port", str(http_port), "-end-port", str(http_port)],
                [f"[OPEN] {http_port}/tcp", "TCP states: OPEN=1",
                 "Open TCP port observed", "[INTELLIGENCE REPORT]"],
            ),
            run_case(
                binary, output_dir, "tcp-closed",
                ["-mode", "tcp", "-target", TARGET,
                 "-start-port", str(closed_port), "-end-port", str(closed_port)],
                [f"[CLOSED] {closed_port}/tcp", "CLOSED=1"],
            ),
            run_case(
                binary, output_dir, "http",
                ["-mode", "http", "-target", TARGET,
                 "-http-scheme", "http", "-http-port", str(http_port)],
                ["[HTTP SERVICE]", "Status: 200", f"Title: {TITLE}"],
            ),
            run_case(
                binary, output_dir, "tls",
                ["-mode", "tls", "-target", TARGET, "-port", str(tls_port)],
                ["[TLS CERTIFICATE]", "Target: 127.0.0.1",
                 "Verified: false", "SHA-256:"],
            ),
            run_test_case(
                output_dir, "unified-investigation",
                ["./internal/integration", "-run", "^TestUnifiedInvestigationEngineCombinesTCPHTTPAndTLS$", "-count=1"],
                ["TestUnifiedInvestigationEngineCombinesTCPHTTPAndTLS", "PASS"],
            ),
        ]

        ground_truth_path = ROOT / "docs/validation-lab/ground-truth.json"
        source_commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            check=False, timeout=15,
        ).stdout.strip()
        worktree_status = subprocess.run(
            ["git", "status", "--porcelain"], cwd=ROOT, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            check=False, timeout=15,
        ).stdout.strip()
        summary = {
            "schema_version": 1,
            "environment": "local-loopback-only",
            "source_commit": source_commit,
            "worktree_dirty": bool(worktree_status),
            "target": TARGET,
            "started_at": started_at,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "go_version": subprocess.run(
                ["go", "version"], cwd=ROOT, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                check=False, timeout=15,
            ).stdout.strip(),
            "binary_sha256": sha256_file(binary),
            "ports": {
                "http_open": http_port,
                "tls_open": tls_port,
                "closed": closed_port,
            },
            "authorization": "The fixture and all targets are created locally by this process.",
            "scope": [TARGET],
            "ground_truth": "docs/validation-lab/ground-truth.json",
            "ground_truth_sha256": sha256_file(ground_truth_path),
            "cases": cases,
            "passed": sum(1 for case in cases if case["passed"]),
            "failed": sum(1 for case in cases if not case["passed"]),
        }
        summary_path = output_dir / "run.json"
        summary_path.write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0 if summary["failed"] == 0 else 1
    finally:
        http_server.shutdown()
        http_server.server_close()
        if tls_server is not None:
            if tls_thread is not None:
                tls_server.shutdown()
                tls_thread.join(timeout=2)
            tls_server.server_close()
        http_thread.join(timeout=2)


if __name__ == "__main__":
    raise SystemExit(main())
