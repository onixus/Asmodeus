#!/usr/bin/env python3
"""Real-process durable campaign restart acceptance on an isolated simulator.

No runner, injection or external services: verifies process death, signed audit
reconciliation, explicit resume, plan preservation and CLI/API operations.
Run after cargo build --workspace --locked. feature_smoke.py separately covers
cancellation/resume and confirmed cleanup with a live synthetic runner.
"""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

sys.dont_write_bytecode = True
from feature_smoke import BIN, port, until


def main():
    with tempfile.TemporaryDirectory(prefix="asmodeus-campaign-") as directory:
        work = Path(directory)
        manifests = work / "scenarios"
        manifests.mkdir()
        for name, dwell in [("FAST", 60), ("SLOW", 1500)]:
            manifest = {
                "apiVersion": "asmodeus.io/v1alpha1", "kind": "AttackScenario",
                "metadata": {"id": name, "name": name, "category": "red_team"},
                "spec": {
                    "target_scope": {"target_path": "/tmp/asmodeus-canary"},
                    "safety": {"max_duration_sec": 5, "cpu_limit_percent": 25},
                    "action": {"nature": "synthetic", "type": "synthetic_canary_encrypt",
                               "parameters": {"duration_ms": dwell}},
                },
            }
            (manifests / f"{name}.json").write_text(json.dumps(manifest))
        subprocess.run([BIN / "asmodeus", "keygen", "--name", work / "operator"], check=True, stdout=subprocess.DEVNULL)
        env = {key: value for key, value in os.environ.items() if not key.startswith("ASMODEUS_")}
        base = f"http://127.0.0.1:{port()}"
        env.update({
            "ASMODEUS_LISTEN": base.removeprefix("http://"),
            "ASMODEUS_SCENARIOS_DIR": str(manifests),
            "ASMODEUS_SCENARIO_SIGNING_KEY": str(work / "operator.key"),
            "ASMODEUS_AUDIT_SIGNING_KEY": str(work / "operator.key"),
            "ASMODEUS_AUDIT_LOG": str(work / "audit.jsonl"),
            "ASMODEUS_STATE_DIR": str(work / "state"),
            "ASMODEUS_ALLOW_ROLE_HEADER": "1",  # isolated loopback acceptance only
        })
        log = (work / "control-plane.log").open("w+")
        process = None
        processes = []
        prefix = "/api/v1/asmodeus"

        def request(method, path, body=None, expected=200):
            data = None if body is None else json.dumps(body).encode()
            req = urllib.request.Request(base + path, data=data, method=method,
                                         headers={"x-apex-role": "admin", "content-type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=8) as response:
                    status, raw = response.status, response.read()
            except urllib.error.HTTPError as error:
                status, raw = error.code, error.read()
            if expected is not None:
                assert status == expected, (method, path, status, raw.decode())
            return status, json.loads(raw)

        def ready():
            try:
                return request("GET", "/healthz")[1]["status"] == "ok"
            except (OSError, AssertionError):
                return False

        def start():
            proc = subprocess.Popen([BIN / "asmodeus-control-plane"], env=env, stdout=log, stderr=log)
            # Retain ownership before readiness checks can fail, so a slow
            # startup never leaves a daemon behind after the temporary directory
            # is removed. Distinguish process exit from an HTTP timeout.
            processes.append(proc)
            def process_ready():
                if proc.poll() is not None:
                    raise RuntimeError(f"control-plane exited before readiness: {proc.returncode}")
                return ready()
            until(process_ready, seconds=20)
            return proc

        def cli(action, *args):
            reply = subprocess.run([BIN / "asmodeus", "campaigns", action, "--url", base, *args],
                                   env=env, check=True, capture_output=True, text=True)
            return json.loads(reply.stdout)

        try:
            process = start()
            request("POST", prefix + "/campaigns", {
                "id": "RESTART", "name": "Original plan", "description": "smoke",
                "steps": [{"order": 1, "scenario_id": "FAST"}, {"order": 2, "scenario_id": "SLOW"}, {"order": 3, "scenario_id": "FAST"}],
            }, 201)
            admitted = cli("run", "--id", "RESTART", "--background")
            run_id = admitted["id"]
            path = prefix + f"/campaign-runs/{run_id}"
            current = until(lambda: r if len((r := request("GET", path)[1])["step_results"]) == 2 else None)
            first_id, old_id = [step["run_id"] for step in current["step_results"]]
            until(lambda: request("GET", prefix + f"/runs/{old_id}", expected=None)[0] == 200)
            assert current["step_results"][0]["status"] == "COMPLETED"
            # Delete the definition while the snapshotted worker is in flight.
            request("DELETE", prefix + "/campaigns/RESTART")
            process.kill()
            process.wait(timeout=3)
            process = start()
            interrupted = request("GET", path)[1]
            assert interrupted["status"] == "INTERRUPTED" and not interrupted["worker_active"]
            assert len(interrupted["step_results"]) == 2
            assert request("GET", prefix + f"/runs/{old_id}")[1]["status"] == "INTERRUPTED"
            # Two simultaneous requests must admit exactly one replacement worker.
            with ThreadPoolExecutor(max_workers=2) as pool:
                replies = list(pool.map(lambda _: request("POST", path + "/resume", expected=None), range(2)))
            assert sorted(status for status, _ in replies) == [202, 409], replies
            finished = until(lambda: r if (r := cli("status", "--id", run_id))["status"] == "COMPLETED" else None)
            assert finished["campaign_name"] == "Original plan"
            assert len(finished["steps"]) == 3 and finished["resume_count"] == 1
            assert finished["step_results"][0]["run_id"] == first_id
            assert finished["step_results"][1]["run_id"] != old_id
            assert finished["superseded_results"][0]["run_id"] == old_id
            history = cli("runs", "--campaign-id", "RESTART", "--status", "completed", "--limit", "1")
            assert history["returned"] == 1 and history["runs"][0]["id"] == run_id
            assert request("GET", prefix + "/runs")[1]["total"] == 4
            for step in finished["step_results"] + finished["superseded_results"]:
                assert request("GET", prefix + f"/runs/{step['run_id']}/verify")[1]["verified"]
            assert finished["report"]["successful_steps"] == 3
            request("POST", path + "/resume", expected=409)
            process.terminate()
            process.wait(timeout=3)
            # Unsupported persisted schemas fail startup instead of dropping history.
            snapshot = work / "state" / "campaign_runs.json"
            data = json.loads(snapshot.read_text())
            data["version"] = 999
            snapshot.write_text(json.dumps(data))
            process = subprocess.Popen([BIN / "asmodeus-control-plane"], env=env, stdout=log, stderr=log)
            processes.append(process)
            assert process.wait(timeout=3) != 0
            print("PASS: durable campaign process death/restart, signed audit, explicit single resume, no completed-stage replay, immutable campaign plan, CLI history/status, rejected unsupported snapshot")
        except Exception:
            log.flush()
            log.seek(0)
            print(log.read())
            raise
        finally:
            for proc in processes:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=3)
            log.close()


if __name__ == "__main__":
    main()
