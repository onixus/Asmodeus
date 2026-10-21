#!/usr/bin/env python3
"""Real-process local fixture acceptance; no external sensors or services.

Verifies actual loopback receipts, paired controls, exclusive attempts, export
ownership, graceful SIGINT and truthful SIGKILL residue. Never cleans up an
attempt not created by this script. Run after cargo build --workspace.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
BIN = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")) / "debug" / "asmodeus"
CANARY = Path("/tmp/asmodeus-canary/local-procedures")


def main():
    owned = []
    processes = []
    evidence = []
    suites = []
    prefix = "smoke-" + uuid.uuid4().hex[:16]

    def args(slot, variant="positive", timeout=10000):
        attempt = f"{prefix}-{len(owned)}"
        owned.append(attempt)
        return attempt, [str(BIN), "procedure-local", "--procedure", slot,
                         "--variant", variant, "--attempt-id", attempt,
                         "--timeout-ms", str(timeout)]

    def invoke(command, successful=True):
        result = subprocess.run(command, capture_output=True, text=True, timeout=15)
        assert (result.returncode == 0) == successful, (result.returncode, result.stdout, result.stderr)
        return result

    def check_manifest(doc, attempt, expected_status):
        assert doc["attempt_id"] == attempt
        assert doc["status"] == expected_status, doc
        assert doc["mode"] == "LOCAL_FIXTURE"
        assert doc["signature_status"] == "UNSIGNED"
        assert doc["protection_result"] == "INCONCLUSIVE"
        assert doc["corpus_sha256"] == hashlib.sha256(
            (ROOT / "crates/asmodeus-dsl/fixtures/procedure-corpus-v1.json").read_bytes()
        ).hexdigest()
        assert doc["stopped_unix_ms"] >= doc["started_unix_ms"]
        assert doc["cleanup"]["outcome"] == "VERIFIED", doc
        assert doc["cleanup"]["crash_cleanup"] == "NOT_VERIFIED"
        assert not (CANARY / attempt).exists(), doc
        ledger = CANARY / f"{attempt}.ownership.json"
        assert ledger.is_file()
        assert json.loads(ledger.read_text())["crash_cleanup"] == "NOT_VERIFIED"
        for receipt in doc["receipts"]:
            assert receipt["receiver"].startswith("127.0.0.1:")
            assert receipt["bytes"] > 0
            assert len(receipt["sha256"]) == 64
        evidence.append(doc)

    def start_and_signal(signum):
        attempt, command = args("http-beacon")
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        processes.append(process)
        ledger = CANARY / f"{attempt}.ownership.json"
        deadline = time.monotonic() + 5
        while True:
            try:
                reserved = json.loads(ledger.read_text())
                if reserved.get("crash_cleanup") == "NOT_VERIFIED":
                    break
            except (FileNotFoundError, json.JSONDecodeError):
                pass
            assert process.poll() is None, process.communicate()
            assert time.monotonic() < deadline, "ownership record was not created"
            time.sleep(0.002)
        process.send_signal(signum)
        stdout, stderr = process.communicate(timeout=5)
        assert process.returncode != 0, (stdout, stderr)
        if signum == signal.SIGINT:
            check_manifest(json.loads(stdout), attempt, "CANCELLED")
        else:
            assert json.loads(ledger.read_text())["crash_cleanup"] == "NOT_VERIFIED"
            # Same ID must fail even if the previous attempt died abruptly.
            invoke(command, successful=False)
        return attempt

    def suite_command(label, timeout=10000):
        suite_id = f"{prefix}-{label}"
        owned.extend(f"{suite_id}-{index}-{variant}" for index in range(6)
                     for variant in ("positive", "benign"))
        return suite_id, [str(BIN), "procedure-local-suite", "--suite-id", suite_id,
                          "--timeout-ms", str(timeout)]

    def check_suite(doc, gate):
        assert doc["fixture_gate"] == gate, doc
        assert doc["protection_result"] == "INCONCLUSIVE"
        assert doc["signature_status"] == "UNSIGNED"
        assert doc["slot_denominator"] == 6
        assert doc["variant_denominator"] == 12
        assert len(doc["entries"]) == 12
        assert doc["corpus_sha256"] == hashlib.sha256(
            (ROOT / "crates/asmodeus-dsl/fixtures/procedure-corpus-v1.json").read_bytes()
        ).hexdigest()
        assert len({entry["attempt_id"] for entry in doc["entries"]}) == 12
        assert len({entry["procedure_id"] for entry in doc["entries"]}) == 6
        for entry in doc["entries"]:
            if entry["evidence"] is not None:
                check_manifest(entry["evidence"], entry["attempt_id"], entry["evidence"]["status"])
        suites.append(doc)

    try:
        with tempfile.TemporaryDirectory(prefix="asmodeus-procedures-") as directory:
            output = Path(directory) / "attempt.json"
            for slot in ("http-beacon", "dns-pattern", "synthetic-transfer"):
                paired = []
                for variant in ("positive", "benign-control"):
                    attempt, command = args(slot, variant)
                    destination = output if not output.exists() else Path(directory) / f"{attempt}.json"
                    doc = json.loads(invoke(command + ["--output", str(destination)]).stdout)
                    assert json.loads(destination.read_text()) == doc
                    check_manifest(doc, attempt, "EXECUTED")
                    paired.append(doc)
                    before = (CANARY / f"{attempt}.ownership.json").read_bytes()
                    invoke(command, successful=False)
                    assert (CANARY / f"{attempt}.ownership.json").read_bytes() == before
                if slot in ("http-beacon", "dns-pattern"):
                    assert len(paired[0]["receipts"]) == 4
                    assert len(paired[1]["receipts"]) == 1
                else:
                    assert sum(r["bytes"] for r in paired[0]["receipts"]) > sum(r["bytes"] for r in paired[1]["receipts"])

            attempt, command = args("http-beacon")
            saved = output.read_bytes()
            invoke(command + ["--output", str(output)], successful=False)
            assert output.read_bytes() == saved
            assert not (CANARY / f"{attempt}.ownership.json").exists()

            attempt, command = args("container-exec")
            unsupported = json.loads(invoke(command, successful=False).stdout)
            check_manifest(unsupported, attempt, "UNSUPPORTED")
            assert unsupported["receipts"] == []

            attempt, command = args("http-beacon", timeout=1)
            timed_out = json.loads(invoke(command, successful=False).stdout)
            check_manifest(timed_out, attempt, "FAILED")

            if os.name == "posix":
                start_and_signal(signal.SIGINT)
                start_and_signal(signal.SIGKILL)

            suite_id, command = suite_command("suite")
            # Export rejection must happen before any attempt is reserved.
            saved = output.read_bytes()
            invoke(command + ["--output", str(output)], successful=False)
            assert output.read_bytes() == saved
            assert not (CANARY / f"{suite_id}-0-positive.ownership.json").exists()
            suite_output = Path(directory) / "suite.json"
            suite = json.loads(invoke(command + ["--output", str(suite_output)], successful=False).stdout)
            check_suite(suite, "INCONCLUSIVE")
            assert json.loads(suite_output.read_text()) == suite
            assert suite["executed_variants"] == 6
            assert suite["complete_local_pairs"] == 3
            assert sum(e["gap"] is not None for e in suite["entries"]) == 6
            before = {entry["attempt_id"]: (CANARY / f'{entry["attempt_id"]}.ownership.json').read_bytes()
                      for entry in suite["entries"]}
            repeated = json.loads(invoke(command, successful=False).stdout)
            check_suite(repeated, "FAILED")
            assert all(entry["evidence"] is None and entry["gap"] for entry in repeated["entries"])
            for attempt, reservation in before.items():
                assert (CANARY / f"{attempt}.ownership.json").read_bytes() == reservation

            _, command = suite_command("deadline", timeout=1)
            check_suite(json.loads(invoke(command, successful=False).stdout), "FAILED")
            if os.name == "posix":
                suite_id, command = suite_command("interrupt")
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                processes.append(process)
                ledger = CANARY / f"{suite_id}-3-positive.ownership.json"
                deadline = time.monotonic() + 5
                while True:
                    try:
                        if json.loads(ledger.read_text()).get("state") == "RESERVED":
                            break
                    except (FileNotFoundError, json.JSONDecodeError):
                        pass
                    assert process.poll() is None, process.communicate()
                    assert time.monotonic() < deadline
                    time.sleep(0.002)
                process.send_signal(signal.SIGINT)
                stdout, stderr = process.communicate(timeout=5)
                assert process.returncode != 0, stderr
                interrupted = json.loads(stdout)
                check_suite(interrupted, "FAILED")
                assert any(entry["evidence"] is None and "cancelled" in entry["gap"]
                           for entry in interrupted["entries"])
                assert any(entry["evidence"] and entry["evidence"]["status"] == "CANCELLED"
                           for entry in interrupted["entries"])

            if os.environ.get("ASMODEUS_PROCEDURE_EVIDENCE_OUT"):
                Path(os.environ["ASMODEUS_PROCEDURE_EVIDENCE_OUT"]).write_text(json.dumps({
                    "context": "owned_loopback_fixture", "protection_result": "INCONCLUSIVE",
                    "attempts": evidence, "suites": suites,
                }, indent=2) + "\n")
        print("PASS: local HTTP/DNS/transfer paired receipts, unsigned evidence, exclusive attempts, non-overwriting export, timeout, SIGINT cleanup and SIGKILL non-acceptance; six-slot suite denominator, gaps, export, retry rejection, timeout and cancellation")
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
        # Only unique IDs allocated by this script; preserve all other attempts.
        for attempt in owned:
            shutil.rmtree(CANARY / attempt, ignore_errors=True)
            (CANARY / f"{attempt}.ownership.json").unlink(missing_ok=True)


if __name__ == "__main__":
    main()
