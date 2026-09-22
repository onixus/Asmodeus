#!/usr/bin/env python3
"""Two-process feature acceptance test. Run after cargo build --workspace.

Uses isolated keys, loopback ports, state and an owned canary directory; no
external sensors, services or credentials. Does not test the Linux BPF backend.
"""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
BIN = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")) / "debug"


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def until(check, seconds=8):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(0.03)
    raise AssertionError("acceptance condition timed out")


def main():
    processes = []
    logs = []
    canary = None
    with tempfile.TemporaryDirectory(prefix="asmodeus-features-") as directory:
        work = Path(directory)
        try:
            canary = Path("/tmp/asmodeus-canary") / work.name
            canary.mkdir(parents=True, exist_ok=False)
            (canary / "operator.txt").write_text("preserve me")
            subprocess.run([BIN / "asmodeus", "keygen", "--name", work / "operator"], check=True, stdout=subprocess.DEVNULL)
            manifests = work / "scenarios"
            manifests.mkdir()
            for scenario, dwell in [("SMOKE-LONG", 5000), ("SMOKE-SHORT", 60)]:
                manifest = {
                    "apiVersion": "asmodeus.io/v1alpha1", "kind": "AttackScenario",
                    "metadata": {"id": scenario, "name": scenario, "category": "red_team"},
                    "spec": {
                        "target_scope": {"target_path": str(canary)},
                        "safety": {"max_duration_sec": 15, "cpu_limit_percent": 25},
                        "action": {"nature": "synthetic", "type": "synthetic_canary_encrypt",
                                   "parameters": {"file_count": 3, "chunk_size_kb": 2, "duration_ms": dwell}},
                    },
                }
                (manifests / f"{scenario}.json").write_text(json.dumps(manifest))
            env = {k: v for k, v in os.environ.items() if not k.startswith("ASMODEUS_")}
            runner_port, api_port = port(), port()
            base = f"http://127.0.0.1:{api_port}"
            env.update({
                "ASMODEUS_RUNNER_LISTEN": f"127.0.0.1:{runner_port}",
                "ASMODEUS_RUNNER_ENDPOINT": f"http://127.0.0.1:{runner_port}",
                "ASMODEUS_LISTEN": f"127.0.0.1:{api_port}",
                "ASMODEUS_RUNNER_TRUSTED_KEY": str(work / "operator.pub"),
                "ASMODEUS_SCENARIO_SIGNING_KEY": str(work / "operator.key"),
                "ASMODEUS_AUDIT_SIGNING_KEY": str(work / "operator.key"),
                "ASMODEUS_AUDIT_LOG": str(work / "audit.jsonl"),
                "ASMODEUS_STATE_DIR": str(work / "state"),
                "ASMODEUS_SCENARIOS_DIR": str(manifests),
                "ASMODEUS_SCHEDULER_INTERVAL_SEC": "5",
                "ASMODEUS_ALLOW_ROLE_HEADER": "1",  # isolated loopback stand only
            })

            def start(name):
                log = (work / f"{name}-{len(logs)}.log").open("w+")
                logs.append(log)
                process = subprocess.Popen([BIN / name], env=env, stdout=log, stderr=log)
                processes.append(process)
                return process

            def stop(process):
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

            def request(method, path, body=None, expected=200):
                data = None if body is None else json.dumps(body).encode()
                req = urllib.request.Request(base + path, data=data, method=method,
                    headers={"x-apex-role": "admin", "content-type": "application/json"})
                try:
                    with urllib.request.urlopen(req, timeout=8) as response:
                        status, raw = response.status, response.read()
                except urllib.error.HTTPError as error:
                    status, raw = error.code, error.read()
                assert status == expected, (method, path, status, raw.decode())
                return json.loads(raw)

            def ready():
                try:
                    return request("GET", "/healthz")["status"] == "ok"
                except (OSError, AssertionError):
                    return False

            prefix = "/api/v1/asmodeus"
            start("asmodeus-runner")
            cp = start("asmodeus-control-plane")
            until(ready)
            until(lambda: request("GET", prefix + "/runners/default-runner/ping").get("healthy", False))

            def launch(scenario, options=None):
                return request("POST", prefix + f"/scenarios/{scenario}/run", options or {})

            def background():
                reply = request("POST", prefix + "/scenarios/SMOKE-LONG/run", {"background": True}, 202)
                run_id = reply["run_id"]
                until(lambda: (canary / run_id / "canary_000.docx").exists())
                return run_id

            run_id = background()
            request("POST", prefix + f"/runs/{run_id}/cancel", {}, 202)
            result = until(lambda: (r if r["status"] == "CANCELLED" else None)
                           if (r := request("GET", prefix + f"/runs/{run_id}")) else None)
            assert result["evidence"]["cleanup_confirmed"] and not (canary / run_id).exists()
            assert (canary / "operator.txt").read_text() == "preserve me"
            completed = launch("SMOKE-SHORT")
            assert completed["execution"]["files_created"] == 3
            assert completed["execution"]["bytes_written"] == 3 * 2 * 2 * 1024
            assert not completed["evidence"]["feedback_received"]
            assert request("GET", prefix + "/telemetry/mttd")["confirmed_feedback_runs"] == 0
            request("POST", prefix + f"/runs/{completed['run_id']}/feedback",
                    {"detected": True, "contained": True, "mttd_ms": 40, "mttr_ms": 80})
            assert request("GET", prefix + "/telemetry/mttd")["mean_mttr_ms"] == 80
            request("POST", prefix + "/campaigns", {"id": "SMOKE-CAMPAIGN", "name": "Smoke", "description": "smoke",
                    "steps": [{"order": 1, "scenario_id": "SMOKE-SHORT"}]}, 201)
            request("POST", prefix + "/schedules", {"id": "SMOKE-SCHEDULE", "name": "Smoke", "scenario_id": "SMOKE-SHORT",
                    "interval_sec": 600, "baseline_mttd_ms":20, "enabled": True}, 201)
            job = until(lambda: (j if j["last_run_id"] else None)
                        if (j := request("GET", prefix + "/schedules/SMOKE-SCHEDULE")["schedule"]) else None)
            feedback_path = prefix + f"/runs/{job['last_run_id']}/feedback"
            feedback = {"detected":True,"contained":True,"mttd_ms":40,"mttr_ms":80}
            request("POST", feedback_path, feedback)
            request("POST", feedback_path, feedback)
            updated = request("GET", prefix + "/schedules/SMOKE-SCHEDULE")["schedule"]
            assert updated["last_run_epoch_secs"] == job["last_run_epoch_secs"]
            assert updated["last_status"] == "COMPLETED" and len(updated["run_history"]) == 1
            assert updated["run_history"][0]["feedback_received"] and updated["drift_detected"]
            assert len(request("GET", prefix + "/schedules/alerts")["alerts"]) == 1
            request("PATCH", prefix + "/schedules/SMOKE-SCHEDULE", {"enabled":False})
            request("DELETE", prefix + "/schedules/SCHED-BASE-RANSOMWARE")
            interrupted = background()
            stop(cp)
            until(lambda: not (canary / interrupted).exists())
            cp = start("asmodeus-control-plane")
            until(ready)
            restored = request("GET", prefix + f"/runs/{interrupted}")
            assert restored["status"] == "INTERRUPTED" and not restored["evidence"]["cleanup_confirmed"]
            assert request("GET", prefix + f"/runs/{completed['run_id']}/verify")["verified"]
            assert request("GET", prefix + "/telemetry/mttd")["mean_mttr_ms"] == 80
            assert not request("GET", prefix + "/schedules/SMOKE-SCHEDULE")["schedule"]["enabled"]
            request("GET", prefix + "/schedules/SCHED-BASE-RANSOMWARE", expected=404)
            assert any(c["id"] == "SMOKE-CAMPAIGN" for c in request("GET", prefix + "/campaigns")["campaigns"])
            timed_out = launch("SMOKE-LONG", {"timeout_sec": 1})
            assert timed_out["status"] == "TIMED_OUT" and timed_out["evidence"]["cleanup_confirmed"]
            simulated = launch("LATENCY_SPIKE_VM")
            assert simulated["evidence"]["execution_mode"] == "simulated"
            assert request("GET", prefix + "/telemetry/mttd")["confirmed_feedback_runs"] == 2
            print("PASS: signed DSL parameters, async cancel/cleanup, feedback, restart recovery, catalogs, scheduled feedback/drift, timeout, simulation provenance")
        except Exception:
            for log in logs:
                log.flush()
                log.seek(0)
                print(log.read())
            raise
        finally:
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
            for log in logs:
                log.close()
            if canary is not None:
                shutil.rmtree(canary, ignore_errors=True)


if __name__ == "__main__":
    main()
