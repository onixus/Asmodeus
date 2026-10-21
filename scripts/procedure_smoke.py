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

            if os.environ.get("ASMODEUS_PROCEDURE_EVIDENCE_OUT"):
                Path(os.environ["ASMODEUS_PROCEDURE_EVIDENCE_OUT"]).write_text(json.dumps({
                    "context": "owned_loopback_fixture", "protection_result": "INCONCLUSIVE",
                    "attempts": evidence,
                }, indent=2) + "\n")
        print("PASS: local HTTP/DNS/transfer paired receipts, unsigned evidence, exclusive attempts, non-overwriting export, timeout, SIGINT cleanup and SIGKILL non-acceptance")
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
