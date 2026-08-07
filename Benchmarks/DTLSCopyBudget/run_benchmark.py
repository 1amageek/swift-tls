#!/usr/bin/env python3
"""Measure canonical DTLS facade send/receive copy and allocation budgets."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import statistics
import subprocess
import tempfile
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLCHAIN_ID = "org.swift.64202607231a"
SWIFT_COMMIT = "ef761e567dc94ee"
DEVELOPER_DIR = pathlib.Path("/Applications/Xcode-beta.app/Contents/Developer")
PAYLOAD_SIZES = (1, 1_200, 16_384)
OPERATIONS = ("send", "receive")
OPERATION_BUDGETS = {
    "send": {
        "allocationCalls": 4,
        "fixedAllocationBytes": 179,
        "maximumFixedBulkCopyBytes": 1_064,
    },
    "receive": {
        "allocationCalls": 3,
        "fixedAllocationBytes": 109,
        "maximumFixedBulkCopyBytes": 1_064,
    },
}
MEMORY_ITERATIONS = (16, 64)
TIMING_ITERATIONS = 128
TIMING_WARMUP = 8
TIMING_SAMPLES = 9
COUNTER_NAMES = (
    "mallocCalls",
    "mallocBytes",
    "callocCalls",
    "callocBytes",
    "reallocCalls",
    "reallocBytes",
    "alignedCalls",
    "alignedBytes",
    "freeCalls",
    "memcpyCalls",
    "memcpyBytes",
    "memmoveCalls",
    "memmoveBytes",
)


class BenchmarkFailure(RuntimeError):
    pass


def run(
    command: list[str],
    *,
    cwd: pathlib.Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int = 900,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise BenchmarkFailure(
            f"command failed ({result.returncode}): {' '.join(command)}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def parse_allocation_output(output: str) -> tuple[dict[str, int], int]:
    allocation_line = next(
        (line for line in output.splitlines() if line.startswith("ALLOCATION_RESULT,")),
        None,
    )
    checksum_line = next(
        (line for line in output.splitlines() if line.startswith("MEMORY_CHECKSUM,")),
        None,
    )
    if allocation_line is None or checksum_line is None:
        raise BenchmarkFailure(f"missing allocation result:\n{output}")
    values = [int(value) for value in allocation_line.split(",")[1:]]
    if len(values) != len(COUNTER_NAMES):
        raise BenchmarkFailure(f"unexpected counter count: {allocation_line}")
    return dict(zip(COUNTER_NAMES, values, strict=True)), int(checksum_line.split(",")[1])


def parse_timing_output(output: str) -> tuple[int, int]:
    result_line = next(
        (line for line in output.splitlines() if line.startswith("RESULT,")),
        None,
    )
    if result_line is None:
        raise BenchmarkFailure(f"missing timing result:\n{output}")
    _, nanoseconds, checksum = result_line.split(",")
    return int(nanoseconds), int(checksum)


def per_operation(
    low: dict[str, int],
    high: dict[str, int],
) -> dict[str, float]:
    operation_delta = MEMORY_ITERATIONS[1] - MEMORY_ITERATIONS[0]
    return {
        name: (high[name] - low[name]) / operation_delta
        for name in COUNTER_NAMES
    }


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--formal", action="store_true")
    parser.add_argument("--output", type=pathlib.Path)
    arguments = parser.parse_args()
    if not arguments.formal:
        raise BenchmarkFailure("--formal is required")
    if os.environ.get("TOOLCHAINS") != TOOLCHAIN_ID:
        raise BenchmarkFailure(f"TOOLCHAINS must equal {TOOLCHAIN_ID}")
    if not DEVELOPER_DIR.is_dir():
        raise BenchmarkFailure(f"missing developer directory: {DEVELOPER_DIR}")

    base_env = {
        "DEVELOPER_DIR": str(DEVELOPER_DIR),
        "HOME": os.environ["HOME"],
        "LANG": "C",
        "LC_ALL": "C",
        "LOGNAME": os.environ.get("LOGNAME", ""),
        "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "SWIFT_TLS_ENABLE_BENCHMARKS": "1",
        "TOOLCHAINS": TOOLCHAIN_ID,
        "USER": os.environ.get("USER", ""),
    }
    xcrun = pathlib.Path("/usr/bin/xcrun")
    swift = pathlib.Path(
        run(
            [str(xcrun), "--toolchain", TOOLCHAIN_ID, "--find", "swift"],
            env=base_env,
        ).stdout.strip()
    )
    clang = pathlib.Path(
        run(
            [str(xcrun), "--toolchain", TOOLCHAIN_ID, "--find", "clang"],
            env=base_env,
        ).stdout.strip()
    )
    swift_version = run([str(swift), "--version"], env=base_env).stdout
    if SWIFT_COMMIT not in swift_version:
        raise BenchmarkFailure("unexpected Swift compiler commit")

    sdk = pathlib.Path(
        run(
            [str(xcrun), "--sdk", "macosx", "--show-sdk-path"],
            env=base_env,
        ).stdout.strip()
    )
    base_env["SDKROOT"] = str(sdk)

    build_parent = ROOT / ".build" / "benchmark-dtls-copy-budget"
    build_parent.mkdir(parents=True, exist_ok=True)
    scratch = build_parent / "swift-build"
    with tempfile.TemporaryDirectory(prefix="run-", dir=build_parent) as temporary:
        run_root = pathlib.Path(temporary)
        run(
            [
                str(swift),
                "build",
                "--scratch-path",
                str(scratch),
                "--configuration",
                "release",
                "--jobs",
                "2",
                "--product",
                "swift-tls-dtls-copy-budget-benchmark",
            ],
            cwd=ROOT,
            env=base_env,
        )
        worker = scratch / "arm64-apple-macosx" / "release" / "swift-tls-dtls-copy-budget-benchmark"
        if not worker.is_file():
            candidates = list(scratch.glob("**/release/swift-tls-dtls-copy-budget-benchmark"))
            if len(candidates) != 1:
                raise BenchmarkFailure("benchmark worker was not produced")
            worker = candidates[0]

        probe_source = ROOT / "Benchmarks/DTLSCopyBudget/AllocationProbe/DTLSAllocationProbe.c"
        contract_source = ROOT / "Benchmarks/DTLSCopyBudget/AllocationProbe/AllocationProbeContract.c"
        probe = run_root / "libTLSDTLSAllocationProbe.dylib"
        contract = run_root / "allocation-probe-contract"
        compile_flags = [
            str(clang),
            "-O2",
            "-std=c11",
            "-fno-builtin",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-arch",
            "arm64",
            "-mmacosx-version-min=26.0",
            "-isysroot",
            str(sdk),
        ]
        run(compile_flags + ["-dynamiclib", str(probe_source), "-o", str(probe)])
        run(compile_flags + [str(contract_source), "-o", str(contract)])

        injected_env = dict(base_env)
        injected_env["DYLD_INSERT_LIBRARIES"] = str(probe)
        contract_output = run([str(contract)], env=injected_env).stdout
        contract_counters, _ = parse_allocation_output(
            contract_output.replace("PROBE_CHECKSUM", "MEMORY_CHECKSUM")
        )
        expected_contract = {
            "mallocCalls": 1,
            "mallocBytes": 17,
            "callocCalls": 1,
            "callocBytes": 38,
            "reallocCalls": 1,
            "reallocBytes": 41,
            "alignedCalls": 1,
            "alignedBytes": 128,
            "freeCalls": 4,
            "memcpyCalls": 0,
            "memcpyBytes": 0,
            "memmoveCalls": 2,
            "memmoveBytes": 20,
        }
        if contract_counters != expected_contract:
            raise BenchmarkFailure(f"allocation probe self-test failed: {contract_counters!r}")

        memory_results: dict[str, dict[str, Any]] = {}
        timing_results: dict[str, dict[str, Any]] = {}
        derived_results: dict[str, dict[str, float]] = {}
        failures: list[str] = []
        for operation in OPERATIONS:
            budget = OPERATION_BUDGETS[operation]
            operation_memory: dict[str, Any] = {}
            operation_timing: dict[str, Any] = {}
            for payload_size in PAYLOAD_SIZES:
                raw_measurements: dict[str, dict[str, int]] = {}
                checksums: set[int] = set()
                for iterations in MEMORY_ITERATIONS:
                    output = run(
                        [
                            str(worker),
                            "--memory",
                            operation,
                            str(payload_size),
                            str(iterations),
                        ],
                        env=injected_env,
                    ).stdout
                    counters, checksum = parse_allocation_output(output)
                    raw_measurements[str(iterations)] = counters
                    checksums.add(checksum // iterations)
                if len(checksums) != 1:
                    failures.append(
                        f"{operation} payload {payload_size}: unstable memory checksum"
                    )
                derived = per_operation(
                    raw_measurements[str(MEMORY_ITERATIONS[0])],
                    raw_measurements[str(MEMORY_ITERATIONS[1])],
                )
                bulk_copy_bytes = derived["memcpyBytes"] + derived["memmoveBytes"]
                allocation_calls = (
                    derived["mallocCalls"]
                    + derived["callocCalls"]
                    + derived["reallocCalls"]
                    + derived["alignedCalls"]
                )
                allocation_bytes = (
                    derived["mallocBytes"]
                    + derived["callocBytes"]
                    + derived["reallocBytes"]
                    + derived["alignedBytes"]
                )
                if derived["freeCalls"] != allocation_calls:
                    failures.append(
                        f"{operation} payload {payload_size}: allocation/free imbalance "
                        f"{allocation_calls} vs {derived['freeCalls']}"
                    )
                operation_memory[str(payload_size)] = {
                    "raw": raw_measurements,
                    "perOperation": derived,
                    "allocationCalls": allocation_calls,
                    "allocationBytes": allocation_bytes,
                    "dynamicBulkCopyBytes": bulk_copy_bytes,
                }
                expected_allocation_calls = budget["allocationCalls"]
                expected_allocation_bytes = (
                    payload_size + budget["fixedAllocationBytes"]
                )
                if allocation_calls != expected_allocation_calls:
                    failures.append(
                        f"{operation} payload {payload_size}: expected "
                        f"{expected_allocation_calls} allocations/op, observed {allocation_calls}"
                    )
                if allocation_bytes != expected_allocation_bytes:
                    failures.append(
                        f"{operation} payload {payload_size}: expected "
                        f"{expected_allocation_bytes} allocated bytes/op, "
                        f"observed {allocation_bytes}"
                    )
                if derived["callocCalls"] != 0 or derived["reallocCalls"] != 0:
                    failures.append(
                        f"{operation} payload {payload_size}: calloc/realloc are outside the budget"
                    )

                samples: list[float] = []
                timing_checksums: set[int] = set()
                for _ in range(TIMING_SAMPLES):
                    output = run(
                        [
                            str(worker),
                            operation,
                            str(payload_size),
                            str(TIMING_ITERATIONS),
                            str(TIMING_WARMUP),
                        ],
                        env=base_env,
                    ).stdout
                    nanoseconds, checksum = parse_timing_output(output)
                    samples.append(nanoseconds / TIMING_ITERATIONS)
                    timing_checksums.add(checksum)
                if len(timing_checksums) != 1:
                    failures.append(
                        f"{operation} payload {payload_size}: unstable timing checksum"
                    )
                operation_timing[str(payload_size)] = {
                    "samples": samples,
                    "medianNanosecondsPerOperation": statistics.median(samples),
                    "p95NanosecondsPerOperation": sorted(samples)[-1],
                }

            small = operation_memory["1200"]["allocationBytes"]
            large = operation_memory["16384"]["allocationBytes"]
            owner_byte_slope = (large - small) / (16_384 - 1_200)
            if not 0.95 <= owner_byte_slope <= 1.05:
                failures.append(
                    f"{operation} allocation-byte slope must represent one output owner "
                    f"(0.95...1.05), observed {owner_byte_slope}"
                )
            small_bulk_copy = operation_memory["1200"]["dynamicBulkCopyBytes"]
            large_bulk_copy = operation_memory["16384"]["dynamicBulkCopyBytes"]
            bulk_copy_payload_slope = (
                (large_bulk_copy - small_bulk_copy) / (16_384 - 1_200)
            )
            if bulk_copy_payload_slope > 0.01:
                failures.append(
                    f"{operation} dynamic bulk-copy bytes must not scale with payload, "
                    f"observed slope {bulk_copy_payload_slope}"
                )
            if max(
                result["dynamicBulkCopyBytes"] for result in operation_memory.values()
            ) > budget["maximumFixedBulkCopyBytes"]:
                failures.append(
                    f"{operation} fixed internal bulk-copy budget exceeded "
                    f"{budget['maximumFixedBulkCopyBytes']} bytes/op"
                )
            memory_results[operation] = operation_memory
            timing_results[operation] = operation_timing
            derived_results[operation] = {
                "outputOwnerByteSlope": owner_byte_slope,
                "dynamicBulkCopyPayloadByteSlope": bulk_copy_payload_slope,
            }

        source_commit = run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, env=base_env
        ).stdout.strip()
        dirty = bool(
            run(["git", "status", "--porcelain"], cwd=ROOT, env=base_env).stdout.strip()
        )
        artifact = {
            "schemaVersion": 2,
            "createdAt": dt.datetime.now(dt.timezone.utc).isoformat(),
            "source": {
                "commit": source_commit,
                "workingTreeDirty": dirty,
            },
            "toolchain": {
                "identifier": TOOLCHAIN_ID,
                "compilerCommit": SWIFT_COMMIT,
                "swiftVersion": swift_version.strip(),
            },
            "worker": {
                "sha256": sha256(worker),
            },
            "probe": {
                "sha256": sha256(probe),
                "contract": contract_counters,
            },
            "workload": {
                "operations": ["DTLSClient.send", "DTLSServer.receive"],
                "payloadSizes": list(PAYLOAD_SIZES),
                "memoryIterations": list(MEMORY_ITERATIONS),
                "timingIterations": TIMING_ITERATIONS,
                "timingWarmup": TIMING_WARMUP,
                "timingSamples": TIMING_SAMPLES,
            },
            "memory": memory_results,
            "timing": timing_results,
            "budgets": OPERATION_BUDGETS,
            "derived": derived_results,
            "gate": {
                "passed": not failures,
                "failures": failures,
            },
        }
        output_path = arguments.output
        if output_path is None:
            stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            output_path = ROOT / "Benchmarks/DTLSCopyBudget/Results" / f"{stamp}-native-dtls-copy-budget.json"
        if not output_path.is_absolute():
            output_path = ROOT / output_path
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
        print(output_path)
        if failures:
            for failure in failures:
                print(f"FAIL: {failure}")
            return 1
        print("PASS: DTLS send and receive each retain one payload-sized output owner")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
