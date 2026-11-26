#!/usr/bin/env python3
"""Check the real HTTP/worker lifecycle with an isolated, network-free curl fixture."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

SCRIPTS = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("panel_fixture", SCRIPTS / "test-rust-panel.py")
panel_fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(panel_fixture)


def wait_for(check, timeout=10):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        result = check()
        if result:
            return result
        time.sleep(0.05)
    raise AssertionError("timed out waiting for fixture result")


def check(panel, worker, root):
    data, modules = root / "data", root / "modules"
    fixture = root / "bin"
    fixture.mkdir()
    curl = fixture / ("curl.exe" if os.name == "nt" else "curl")
    subprocess.run(["rustc", "--edition=2021", SCRIPTS.parent / "rust/runs/tests/support/curl.rs",
                    "-o", curl], check=True)
    env = {"PATH": str(fixture) + os.pathsep + os.environ["PATH"], "N2S_RUN_FIXTURE": str(fixture)}
    if worker:
        module = modules / "runs" / worker.name
        module.parent.mkdir(parents=True)
        shutil.copy2(worker, module)

    def instance():
        return panel_fixture.server(panel, data, modules, env)

    def api(fetch, path, obj=None):
        code, body = fetch(path, json.dumps(obj).encode() if obj is not None else None)
        assert code == 200, (code, body)
        return json.loads(body)

    def launch(fetch, **kwargs):
        return api(fetch, "/api/runs", dict(mode="current_https", threads=1, **kwargs))

    def finished(fetch, ident):
        run = api(fetch, f"/api/runs/{ident}")
        return run if run["status"] != "running" else None

    with instance() as fetch:
        caps = api(fetch, "/api/runs/capabilities")
        assert caps["modes"] == ["current_https"] and caps["installed"]
        saved = api(fetch, "/api/lists", {"name": "Local fixture", "domains": ["ok.test", "reject.test"]})
        started = launch(fetch, list_id=saved["id"])
        report = wait_for(lambda: finished(fetch, started["id"]))
        assert report["status"] == "done" and report["done"] == 2 and report["results"] == []
        outcomes = [(c["host"], c["code"], c["ok"], c["ttfb_ms"]) for c in report["checks"]]
        assert outcomes == [("ok.test", 204, True, 42), ("reject.test", 404, False, 42)]
        assert not api(fetch, "/api/lists/" + saved["id"]).get("successful_strategies")

        slow = launch(fetch, targets=[f"slow{i}.test" for i in range(8)])
        ident = slow["id"]
        url = f"/api/runs/{ident}"
        assert api(fetch, url)["status"] == "running"
        assert next(r for r in api(fetch, "/api/runs") if r["id"] == ident)["status"] == "running"
        other = {"targets": ["ok.test"], "mode": "current_https", "threads": 1}
        assert fetch("/api/runs", json.dumps(other).encode())[0] == 400
        wait_for(lambda: (fixture / "slow0.test").is_file())
        assert not (fixture / "slow1.test").exists()
        assert api(fetch, url + "/threads", {"threads": 3})["threads"] == 3
        wait_for(lambda: (fixture / "slow2.test").is_file())
        assert api(fetch, url + "/cancel", {})["status"] == "cancelling"
        cancelled = wait_for(lambda: finished(fetch, ident))
        assert cancelled["status"] == "cancelled" and cancelled["done"] == 0 and cancelled["checks"] == []
        assert not (fixture / "slow3.test").exists()

        restart = launch(fetch, targets=["slowrestart.test"])
        wait_for(lambda: (fixture / "slowrestart.test").is_file())
    # POSIX SIGTERM and abrupt Windows process termination both close worker stdin.
    path = data / "runs" / (restart["id"] + ".json")
    wait_for(lambda: json.loads(path.read_text(encoding="utf-8"))["status"] == "cancelled")
    with instance() as fetch:
        assert api(fetch, "/api/runs/" + restart["id"])["status"] == "cancelled"
        assert api(fetch, "/api/runs/" + started["id"])["done"] == 2
    print("Current HTTPS runs: start, HEAD outcomes, live history, thread count, cancellation, persistence and restart passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--panel", required=True, type=Path)
    parser.add_argument("--worker", type=Path, help="install this helper for compact mode")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as folder:
        check(args.panel.resolve(), args.worker, Path(folder))
