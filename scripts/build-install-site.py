#!/usr/bin/env python3
"""Mirror verified, unmodified release assets into an install-only Pages site.

Authentication is delegated to gh (GH_TOKEN in Actions). No release is created,
edited, or rebuilt. Downloads and verification finish before output is published.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any

DEFAULT_REPO = "Omn1z/nfqws2-keenetic-strategy-selector"
DEFAULT_BASE_URL = "https://omn1z.github.io/nfqws2-keenetic-strategy-selector"
PANEL_ASSETS = tuple("nfqws2-strategy-linux-" + arch for arch in (
    "arm64", "arm", "mipsle", "mips", "amd64",
))
LICENSE_ASSETS = (
    "ADGUARD-URLFILTER-LICENSE.txt", "TGWS-LICENSE.txt", "THIRD-PARTY-NOTICES.txt",
)
REQUIRED_ASSETS = ("install.sh", "SHA256SUMS") + PANEL_ASSETS + LICENSE_ASSETS
OPTIONAL_ASSETS = ("AMNEZIAWG-LICENSE.txt",)
TAG_RE = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
CHECKSUM_RE = re.compile(r"([0-9a-fA-F]{64}) [ *]([A-Za-z0-9][A-Za-z0-9._-]*)\Z")
TOKEN_RE = re.compile(r"@[A-Z][A-Z0-9_]*@")


class BuildError(Exception):
    """A fail-closed, user-readable build failure."""


def release_version(tag: Any) -> tuple[int, int, int]:
    match = TAG_RE.fullmatch(tag) if isinstance(tag, str) else None
    if not match or len(tag) > 64:
        raise BuildError("release tag must be a stable vMAJOR.MINOR.PATCH")
    return tuple(int(part) for part in match.groups())


def validate_base_url(value: str) -> str:
    value = value.rstrip("/")
    # This value is embedded in a single-quoted shell assignment. Restrict both
    # URL structure and characters rather than relying on shell escaping.
    if not re.fullmatch(r"https://[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?(?:/[A-Za-z0-9_-]+)*", value):
        raise BuildError("base URL must be HTTPS with a plain hostname and path, without credentials/query/fragment")
    return value


def select_releases(latest: Any, recent: Any) -> list[dict[str, Any]]:
    if not isinstance(latest, dict) or latest.get("draft") is not False or latest.get("prerelease") is not False:
        raise BuildError("latest release is not a published stable release")
    latest_version = release_version(latest.get("tag_name"))
    if not isinstance(recent, list):
        raise BuildError("GitHub release list is malformed")
    previous: dict[tuple[int, int, int], dict[str, Any]] = {}
    for release in recent:
        if not isinstance(release, dict) or release.get("draft") is not False or release.get("prerelease") is not False:
            continue
        try:
            version = release_version(release.get("tag_name"))
        except BuildError:
            continue
        if version < latest_version:
            if version in previous:
                raise BuildError("duplicate stable release in GitHub metadata")
            previous[version] = release
    return [latest] + ([previous[max(previous)]] if previous else [])


def parse_checksums(data: bytes) -> dict[str, str]:
    if not data or len(data) > 1024 * 1024:
        raise BuildError("release checksum manifest is empty or too large")
    try:
        lines = data.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise BuildError("release checksum manifest is not ASCII") from exc
    result: dict[str, str] = {}
    for line in lines:
        match = CHECKSUM_RE.fullmatch(line)
        if not match:
            raise BuildError("invalid line or unsafe filename in release checksum manifest")
        digest, name = match.groups()
        if name in result:
            raise BuildError(f"duplicate checksum entry: {name}")
        result[name] = digest.lower()
    return result


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def release_assets(release: dict[str, Any]) -> dict[str, dict[str, Any]]:
    release_version(release.get("tag_name"))
    assets = release.get("assets")
    if not isinstance(assets, list):
        raise BuildError("release assets metadata is missing")
    selected: dict[str, dict[str, Any]] = {}
    for asset in assets:
        if not isinstance(asset, dict):
            raise BuildError("release asset metadata is malformed")
        name = asset.get("name")
        if name not in REQUIRED_ASSETS + OPTIONAL_ASSETS:
            continue
        if name in selected:
            raise BuildError(f"duplicate release asset: {name}")
        digest = asset.get("digest")
        if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", digest):
            raise BuildError(f"GitHub SHA-256 digest is missing or invalid: {name}")
        size = asset.get("size")
        max_size = 100 * 1024 * 1024 if name in PANEL_ASSETS else 5 * 1024 * 1024
        if not isinstance(size, int) or isinstance(size, bool) or not 0 < size <= max_size:
            raise BuildError(f"release asset size is invalid: {name}")
        selected[name] = asset
    missing = set(REQUIRED_ASSETS) - selected.keys()
    if missing:
        raise BuildError("required release assets missing: " + ", ".join(sorted(missing)))
    return selected


class GitHubClient:
    def __init__(self, repo: str = DEFAULT_REPO):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
            raise BuildError("invalid GitHub owner/repository")
        self.repo = repo

    def _run(self, args: list[str], timeout: int, action: str) -> bytes:
        try:
            completed = subprocess.run(
                ["gh", *args], check=False, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=timeout,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise BuildError(f"{action} failed; check gh authentication and network access") from exc
        if completed.returncode:
            # gh may print signed asset URLs. Keep credentials and transient
            # authorization URLs out of Actions logs and generated site files.
            raise BuildError(f"{action} failed (exit {completed.returncode}); check gh authentication and network access")
        return completed.stdout

    def _json(self, suffix: str) -> Any:
        data = self._run(["api", f"repos/{self.repo}/{suffix}"], 90, "GitHub metadata request")
        if len(data) > 5 * 1024 * 1024:
            raise BuildError("GitHub metadata response is too large")
        try:
            return json.loads(data)
        except (ValueError, UnicodeDecodeError) as exc:
            raise BuildError("GitHub metadata response is not valid JSON") from exc

    def latest_release(self) -> Any:
        return self._json("releases/latest")

    def recent_releases(self) -> Any:
        return self._json("releases?per_page=20")

    def download_assets(self, tag: str, names: list[str], destination: Path) -> None:
        release_version(tag)
        args = ["release", "download", tag, "--repo", self.repo, "--dir", str(destination)]
        for name in names:
            args.extend(["--pattern", name])
        self._run(args, 1200, f"Download release {tag}")


def verify_release(release: dict[str, Any], client: Any, destination: Path) -> str:
    selected = release_assets(release)
    destination.mkdir()
    tag = release["tag_name"]
    print(f"Downloading and verifying {tag}: {len(selected)} assets", flush=True)
    client.download_assets(tag, list(selected), destination)
    actual = {path.name for path in destination.iterdir()}
    if actual != set(selected):
        raise BuildError(f"downloaded file inventory does not match release {tag}")
    hashes: dict[str, str] = {}
    for name, asset in selected.items():
        path = destination / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size != asset["size"]:
            raise BuildError(f"downloaded file size/type mismatch: {tag}/{name}")
        hashes[name] = sha256_file(path)
        if hashes[name] != asset["digest"][7:].lower():
            raise BuildError(f"GitHub SHA-256 mismatch: {tag}/{name}")
    manifest = parse_checksums((destination / "SHA256SUMS").read_bytes())
    for name, digest in hashes.items():
        if name == "SHA256SUMS":
            continue
        if manifest.get(name) != digest:
            raise BuildError(f"release manifest SHA-256 missing or mismatched: {tag}/{name}")
    return hashes["SHA256SUMS"]


def render_bootstrap(template: str, base_url: str, tag: str, manifest_hash: str) -> bytes:
    base_url = validate_base_url(base_url)
    release_version(tag)
    if not re.fullmatch(r"[0-9a-f]{64}", manifest_hash):
        raise BuildError("invalid manifest SHA-256 for bootstrap")
    values = {
        "@PAGES_BASE_URL@": base_url,
        "@RELEASE_TAG@": tag,
        "@SHA256SUMS_SHA256@": manifest_hash,
    }
    for token, value in values.items():
        if template.count(token) != 1:
            raise BuildError(f"bootstrap template requires exactly one {token}")
        template = template.replace(token, value)
    if TOKEN_RE.search(template):
        raise BuildError("unresolved bootstrap placeholder")
    if not template.startswith("#!/bin/sh\n") and not template.startswith("#!/bin/sh\r\n"):
        raise BuildError("bootstrap template must be a POSIX shell script")
    return template.encode("utf-8")


def check_output(output: Path) -> None:
    if output.is_symlink() or output == Path(output.anchor):
        raise BuildError("output must be a new or empty non-symlink directory")
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise BuildError("output must be a new or empty directory; refusing to replace existing files")


def build_site(output: Path, base_url: str, template: str, client: Any) -> list[str]:
    output = output.absolute()
    check_output(output)
    base_url = validate_base_url(base_url)
    releases = select_releases(client.latest_release(), client.recent_releases())
    # Validate all metadata before starting expensive downloads.
    for release in releases:
        release_assets(release)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".n2s-install-site-", dir=output.parent) as workspace_name:
        workspace = Path(workspace_name)
        downloads = workspace / "downloads"
        downloads.mkdir()
        hashes = {
            release["tag_name"]: verify_release(release, client, downloads / release["tag_name"])
            for release in releases
        }
        latest_tag = releases[0]["tag_name"]
        bootstrap = render_bootstrap(template, base_url, latest_tag, hashes[latest_tag])
        site = workspace / "site"
        site.mkdir()
        # Byte-exact release assets; only the root bootstrap is generated.
        shutil.copytree(downloads, site / "releases")
        (site / "install.sh").write_bytes(bootstrap)
        (site / ".nojekyll").write_bytes(b"")
        project_url = "https://github.com/" + client.repo
        release_links = "\n".join(
            f'<li><a href="{html.escape(project_url)}/releases/tag/{r["tag_name"]}">{r["tag_name"]}</a></li>'
            for r in releases
        )
        license_links = "\n".join(
            f'<li><a href="releases/{latest_tag}/{name}">{name}</a></li>'
            for name in LICENSE_ASSETS + OPTIONAL_ASSETS
            if (site / "releases" / latest_tag / name).exists()
        )
        homepage = f'''<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NFQWS2 Strategy installation</title>
<main><h1>NFQWS2 Strategy installation</h1>
<p>Verified release files for Keenetic/Entware and OpenWrt.</p>
<p><a href="{html.escape(project_url)}#установка">Installation instructions</a> · <a href="install.sh">Bootstrap script</a></p>
<h2>Original releases</h2><ul>{release_links}</ul>
<p>Release assets are mirrored unchanged and checked against GitHub SHA-256 digests and their original checksum manifest. Source code is available at the release links above.</p>
<h2>Third-party licenses and notices</h2><ul>{license_links}</ul></main></html>
'''
        (site / "index.html").write_bytes(homepage.encode("utf-8"))
        check_output(output)
        if output.exists():
            # Only remove the caller's empty directory, never recursively.
            output.rmdir()
        os.replace(site, output)
    tags = [release["tag_name"] for release in releases]
    print(f"Install site ready: {output} ({', '.join(tags)})", flush=True)
    return tags


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new or empty site output directory")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--repo", default=DEFAULT_REPO)
    args = parser.parse_args()
    try:
        template_path = Path(__file__).resolve().parents[1] / "packaging" / "bootstrap.sh"
        build_site(args.output, args.base_url, template_path.read_bytes().decode("utf-8"), GitHubClient(args.repo))
    except (BuildError, OSError, UnicodeDecodeError) as exc:
        print(f"Install site build failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
