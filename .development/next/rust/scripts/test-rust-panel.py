#!/usr/bin/env python3
"""Exercise the installed compact panel on an ephemeral port with isolated state."""
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import time
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener


@contextmanager
def server(binary, data, modules, extra_env=None):
    env = dict(os.environ, N2S_NOAUTH="1", N2S_DATA=str(data), N2S_MODULE_DIR=str(modules),
               N2S_NFQWS2_CONF=str(data.parent / "nfqws2.conf"))
    env.update(extra_env or {})
    with subprocess.Popen([binary, "serve", "-l", "127.0.0.1:0", "--ignore-saved-port"],
                          env=env, stderr=subprocess.PIPE) as process:
        try:
            for line in process.stderr:
                match = re.search(rb"listening on (127\.0\.0\.1:\d+)", line)
                if match:
                    break
            else:
                raise RuntimeError("panel exited before accepting connections")
            origin = "http://" + match[1].decode()
            opener = build_opener(ProxyHandler({}))

            def fetch(path, payload=None, content_type="application/json", **headers):
                req = Request(origin + path, data=payload, headers={"Content-Type": content_type, **headers})
                try:
                    response = opener.open(req, timeout=8)
                except HTTPError as error:
                    response = error
                with response:
                    return response.status, response.read()

            yield fetch
        finally:
            process.terminate()
            process.wait(timeout=10)


def check(args, scratch):
    data, modules = scratch / "data", scratch / "modules"
    manifest = json.loads((args.web / "modules.json").read_text())
    src = args.assets / (manifest["runs"] + ".gz")
    dst = scratch / (manifest["runs"] + ".gz")
    (scratch / "nfqws2.conf").write_text("TCP_PORTS='80'\n")
    with server(args.panel, data, modules) as fetch:
        assert fetch("/api/config")[0] == 200
        assert b"nfqws2-strategy-runs" in fetch("/api/modules")[1]
        status, body = fetch("/api/devices/192.0.2.7/blobcap", b'{"seconds":1}')
        assert status == 200 and json.loads(body) == {"need_install": True, "package": "nfqws2-strategy-trace"}
        status, body = fetch("/api/blobcap/unknown/save", b'{"index":0,"name":"example.bin"}')
        assert status == 400 and "ClientHello" in body.decode()
        status, body = fetch("/api/lists", b'{"name":"smoke","domains":["example.test"]}')
        assert status == 200
        ident = json.loads(body)["id"]
        assert fetch("/api/runs")[0] == 503
        url = "/" + manifest["runs"]
        assert fetch(url)[0] == 404
        dst.parent.mkdir(parents=True)
        shutil.copyfile(src, dst)
        assert fetch(url, **{"Accept-Encoding":"gzip"}) == (200, src.read_bytes())
        worker = dst.parent / args.runs.name
        shutil.copy2(args.runs, worker)
        assert fetch("/api/runs") == (200, b"[]")
        assert fetch("/modules/runs/" + worker.name)[0] == 404
        worker.unlink()
        dst.unlink()
        assert fetch(url)[0] == 404 and fetch("/api/runs")[0] == 503
        endpoint = "/api/nfqws2/service-strategies"
        assert fetch(endpoint)[0] == 503
        strategy_binary = args.strategies or args.runs.with_name("nfqws2-strategies" + args.runs.suffix)
        worker = modules / "strategies" / strategy_binary.name
        worker.parent.mkdir(parents=True)
        shutil.copy2(strategy_binary, worker)
        state = json.loads(fetch(endpoint)[1])
        service = dict(id="one",name="Local",enabled=True,groups=[dict(id="web",name="Web",
                       kind="domains",entries=["*.Example.test"],strategy="--filter-tcp=443")])
        change = json.dumps(dict(services=[service],revision=state["revision"])).encode()
        preview = json.loads(fetch(endpoint + "/preview", change)[1])
        assert preview["tcp_ports"] == "80,443" and preview["profiles"] == 1
        assert fetch(endpoint, change)[0] == 200
        assert fetch(endpoint, change)[0] == 409
        assert next((scratch / "lists").glob("n2s_service_*.list")).read_text() == "example.test\n"
        assert json.loads(fetch(endpoint)[1])["restart_required"]
        worker.unlink()
        assert fetch(endpoint)[0] == 503
    with server(args.panel, data, modules) as fetch:
        assert json.loads(fetch("/api/lists/" + ident)[1])["name"] == "smoke"
        status, archive = fetch("/api/system/backup", b"")
        assert status == 200 and archive.startswith(b"SLBAK1")
        if args.go_oracle:
            doc = data / "lists" / (ident + ".json")
            baseline = doc.read_bytes()
            backup = scratch / "compat.bak"
            backup.write_bytes(archive)
            doc.unlink()
            subprocess.run([args.go_oracle, "restore", backup, data], check=True)
            assert doc.read_bytes() == baseline
            subprocess.run([args.go_oracle, "build", backup, data], check=True)
            doc.unlink()
            multipart = (b'--backup\r\nContent-Disposition: form-data; name="archive"; filename="data.bak"\r\n'
                         b'Content-Type: application/octet-stream\r\n\r\n' + backup.read_bytes() + b'\r\n--backup--\r\n')
            status, restored = fetch("/api/system/restore", multipart, "multipart/form-data; boundary=backup")
            assert status == 200 and json.loads(restored)["restored"] >= 1
            assert doc.read_bytes() == baseline

        live_ports = json.loads(fetch("/api/system/ports")[1])
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            reserved.listen()
            target_port = reserved.getsockname()[1]
            def switch():
                return fetch("/api/system/ports", json.dumps({"panel_port": target_port}).encode())
            assert switch()[0] == 400
            assert json.loads(fetch("/api/system/ports")[1]) == live_ports
        status, changed = switch()
        assert status == 200
        location = json.loads(changed)["panel_url"]
        assert location == f"http://127.0.0.1:{target_port}"
        with build_opener(ProxyHandler({})).open(location + "/api/system/ports", timeout=8) as response:
            assert json.load(response)["panel_port"] == target_port
        assert json.loads((data/"ports.json").read_text())["panel_port"] == target_port
        dns_path = data / "dnsserver.json"
        dns = json.loads(dns_path.read_text())
        dns["cache_size"] = 73
        dns_path.write_text(json.dumps(dns))
        http = build_opener(ProxyHandler({}))
        with http.open(Request(location + "/api/system/restart", data=b""), timeout=8) as response:
            assert json.load(response)["status"] == "restarting"
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            with http.open(location + "/api/dnsserver", timeout=8) as response:
                if json.load(response)["config"]["cache_size"] == 73:
                    break
            time.sleep(0.05)
        else:
            raise AssertionError("restarted panel did not reload the persisted configuration")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--panel", type=Path, required=True)
    parser.add_argument("--runs", type=Path, required=True)
    parser.add_argument("--strategies", type=Path, help="defaults to the compiler alongside --runs")
    parser.add_argument("--web", type=Path, default=Path("internal/server/compactweb"))
    parser.add_argument("--assets", type=Path, default=Path("dist/compact-ui"))
    parser.add_argument("--go-oracle", type=Path, help="optional Go backup compatibility test binary")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as directory:
        check(args, Path(directory))
    print("Local HTTP, persisted lists, optional worker and GUI, backup, hot port change and panel restart: OK")
