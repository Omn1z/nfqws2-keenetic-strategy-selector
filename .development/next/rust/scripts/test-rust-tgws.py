"""Exercise the panel and its real TG WS subprocess using only loopback sockets."""

import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def exercise(panel, directory):
    root = Path(directory)
    ca = root / "fixture-ca.pem"
    roots = ssl.create_default_context().get_ca_certs(binary_form=True)
    ca.write_text(ssl.DER_cert_to_PEM_cert(roots[0]), encoding="ascii")
    env = dict(os.environ, N2S_DATA=str(root), N2S_NOAUTH="1", SSL_CERT_FILE=str(ca))
    port = free_port()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def api(path="", value=None):
        data = None if value is None else json.dumps(value).encode()
        request = urllib.request.Request(f"http://127.0.0.1:{port}/api/tgws{path}", data=data,
                                         headers={"Content-Type": "application/json"})
        with opener.open(request, timeout=10) as response:
            return json.load(response)

    process = subprocess.Popen([str(panel), "serve", "-l", f"127.0.0.1:{port}", "--ignore-saved-port"],
                               env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 15
        while True:
            try:
                loaded = api()
                break
            except urllib.error.URLError:
                if process.poll() is not None or time.monotonic() > deadline:
                    raise
                time.sleep(0.05)
        assert loaded["native"]["installed"] and not loaded["running"]
        cfg = loaded["config"]
        cfg["port"] = free_port()
        cfg["proxy_protocol"] = True
        cfg["pool_size"] = 2
        api("/config", cfg)
        started = api("/start", {})
        assert started["running"] and started["stats"]["connections"]["total"] == 0
        # An incomplete handshake is rejected locally before any upstream dial.
        with socket.create_connection(("127.0.0.1", cfg["port"]), timeout=2):
            pass
        deadline = time.monotonic() + 5
        while api()["stats"]["connections"]["bad"] != 1:
            if time.monotonic() >= deadline:
                raise AssertionError("TG WS did not account for the closed local connection")
            time.sleep(0.02)
        with opener.open(f"http://127.0.0.1:{port}/api/dashboard", timeout=10) as response:
            tgws = json.load(response)["tgws"]
            assert tgws["running"] and tgws["stats"]["connections"]["bad"] == 1
        ws = api()["stats"]["ws"]
        assert ws["pool_hits"] == ws["pool_misses"] == 0
        with socket.socket() as occupied:
            occupied.bind(("127.0.0.1", 0))
            occupied.listen()
            try:
                api("/config", dict(cfg, port=occupied.getsockname()[1]))
            except urllib.error.HTTPError as err:
                assert err.code == 400
            else:
                raise AssertionError("TG WS accepted a busy port")
        restored = api()
        assert restored["running"] and restored["config"]["port"] == cfg["port"]
        rotated = api("/secret", {})
        assert rotated["secret"] != cfg["secret"] and api()["running"]
        assert not api("/stop", {})["running"]
        saved = json.loads((root / "tgws.json").read_bytes())
        assert not saved["enabled"] and saved["secret"] == rotated["secret"]
    finally:
        process.terminate()
        try:
            process.wait(timeout=6)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="n2s-tgws-") as root:
        exercise(Path(sys.argv[1]).resolve(), root)
    print("TG WS panel, subprocess, rollback, statistics and secret rotation passed")
