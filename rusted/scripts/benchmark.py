#!/usr/bin/env python3
"""Reproducible Linux Rust-server footprint probe (never claims physical A53).

Run this on a native Linux ARM64 host using the SAME musl ELF shipped
to aarch64_cortex-a53. The metrics describe Linux userspace RAM/RSS;
CPU-time numbers depend on the host and are not A53 benchmarks.
"""
import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def memory(pid):
    status = Path(f"/proc/{pid}/status").read_text()
    values = {}
    for label in ("VmRSS", "VmHWM", "VmSize", "VmData"):
        for line in status.splitlines():
            if line.startswith(label + ":"):
                values[label + "_kib"] = int(line.split()[1])
                break
    return values


def request(base, path, *, method="GET", body=None, token=None):
    headers = {}
    if token:
        headers["Authorization"] = "Bearer " + token
    data = None if body is None else json.dumps(body).encode()
    if data is not None:
        headers["Content-Type"] = "application/json"
    start = time.perf_counter()
    req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=15) as response:
        raw = response.read()
        if response.status >= 300:
            raise RuntimeError(f"HTTP {response.status}: {raw[:300]}")
    return raw, (time.perf_counter() - start) * 1000


def run(binary, count=1000, port=38649):
    binary = Path(binary).resolve()
    if not binary.is_file():
        raise FileNotFoundError(binary)
    with tempfile.TemporaryDirectory(prefix="subboost-footprint-") as temp:
        root = Path(temp)
        database = root / "profiles.sqlite"
        token_file = root / "admin.token"
        env = dict(os.environ, SUBBOOST_DB=str(database),
                   SUBBOOST_TOKEN_FILE=str(token_file),
                   SUBBOOST_BIND=f"127.0.0.1:{port}")
        with subprocess.Popen([str(binary)], env=env, cwd=root,
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.PIPE) as proc:
            base = f"http://127.0.0.1:{port}"
            try:
                for _ in range(150):
                    if proc.poll() is not None:
                        raise RuntimeError(f"Server exited: {proc.stderr.read().decode()[:500]}")
                    try:
                        request(base, "/api/health/live")
                        break
                    except (OSError, urllib.error.HTTPError):
                        time.sleep(0.1)
                else:
                    raise RuntimeError("Rust server was not ready after 15 seconds")
                token = token_file.read_text().strip()
                idle = memory(proc.pid)
                nodes = "\n".join(
                    "  - {name: Test-%04d, type: ss, server: example.net, port: 8388,"
                    " cipher: aes-128-gcm, password: test}" % i for i in range(count)
                )
                body = {"name": "A53 benchmark", "source_urls": [],
                        "manual_yaml": "proxies:\n" + nodes + "\n",
                        "rules_text": "DOMAIN-SUFFIX,example.org,DIRECT\nMATCH,Proxy"}
                raw, _ = request(base, "/api/subscriptions", method="POST", body=body, token=token)
                subscription = json.loads(raw)
                times = []
                lengths = []
                for _ in range(25):
                    response, elapsed = request(
                        base,
                        f"/api/subscriptions/{subscription['token']}/config.yaml?target=clash-rs")
                    assert b"MATCH,Proxy" in response, "Missing generated rule"
                    lengths.append(len(response))
                    times.append(elapsed)
                loaded = memory(proc.pid)
                sorted_times = sorted(times)
                data = {
                    "architecture": platform.machine(),
                    "kernel": platform.release(),
                    "binary_bytes": binary.stat().st_size,
                    "node_count": count,
                    "response_bytes": min(lengths),
                    "idle": idle, "loaded": loaded,
                    "latency_ms": {
                        "median": round(sorted_times[len(times)//2], 2),
                        "p95": round(sorted_times[int(len(times)*0.95)], 2),
                        "max": round(max(times), 2),
                    },
                    "sqlite_bytes": sum(p.stat().st_size for p in root.glob("profiles.sqlite*")),
                    "note": "Native ARM64 runner != physical Cortex-A53. RSS includes no proxy core.",
                }
                return data
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--nodes", type=int, default=1000)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    if not 1 <= args.nodes <= 3000:
        parser.error("--nodes must be 1..3000")
    result = run(args.binary, count=args.nodes)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
