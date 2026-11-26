#!/usr/bin/env python3
"""Offline integrity and failure-path tests for the install site publisher."""

import copy
import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest


# Keep running the standalone tests from creating files in the source tree.
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("install_site", Path(__file__).with_name("build-install-site.py"))
site = importlib.util.module_from_spec(spec)
spec.loader.exec_module(site)
TEMPLATE = "#!/bin/sh\nURL='@PAGES_BASE_URL@'\nTAG='@RELEASE_TAG@'\nHASH='@SHA256SUMS_SHA256@'\n"


def release_fixture(tag, optional=True):
    names = site.REQUIRED_ASSETS + (site.OPTIONAL_ASSETS if optional else ())
    files = {name: (tag + ":" + name + "\n").encode() for name in names if name != "SHA256SUMS"}
    files["install.sh"] = b"#!/bin/sh\n# preserved byte for byte\nprintf 'install\\n'\n"
    files["SHA256SUMS"] = "".join(
        hashlib.sha256(content).hexdigest() + "  " + name + "\n" for name, content in files.items()
    ).encode()
    release = {"tag_name": tag, "draft": False, "prerelease": False, "assets": [
        {"name": name, "digest": "sha256:" + hashlib.sha256(content).hexdigest(), "size": len(content)}
        for name, content in files.items()
    ]}
    return release, files


class FakeClient:
    repo = site.DEFAULT_REPO

    def __init__(self):
        self.latest, current = release_fixture("v1.7.1")
        self.previous, previous = release_fixture("v1.7.0")
        self.recent = [self.latest, self.previous]
        self.files = {"v1.7.1": current, "v1.7.0": previous}
        self.fail_tag = None
        self.downloads = []

    def latest_release(self):
        return self.latest

    def recent_releases(self):
        return self.recent

    def download_assets(self, tag, names, destination):
        self.downloads.append(tag)
        if tag == self.fail_tag:
            raise site.BuildError("simulated download failure")
        for name in names:
            (destination / name).write_bytes(self.files[tag][name])

    def replace_file_and_digest(self, name, data):
        self.files["v1.7.1"][name] = data
        asset = next(a for a in self.latest["assets"] if a["name"] == name)
        asset["size"] = len(data)
        asset["digest"] = "sha256:" + hashlib.sha256(data).hexdigest()


class InstallSiteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name) / "site"
        self.client = FakeClient()

    def build(self, template=TEMPLATE):
        return site.build_site(self.output, site.DEFAULT_BASE_URL, template, self.client)

    def assert_rejected_without_output(self, pattern, template=TEMPLATE):
        with self.assertRaisesRegex(site.BuildError, pattern):
            self.build(template)
        self.assertFalse(self.output.exists())

    def test_both_releases_are_byte_exact_and_bootstrap_pins_manifest(self):
        self.assertEqual(self.build(), ["v1.7.1", "v1.7.0"])
        for tag, files in self.client.files.items():
            for name, original in files.items():
                self.assertEqual((self.output / "releases" / tag / name).read_bytes(), original)
        bootstrap = (self.output / "install.sh").read_text()
        self.assertIn("TAG='v1.7.1'", bootstrap)
        manifest_hash = hashlib.sha256(self.client.files["v1.7.1"]["SHA256SUMS"]).hexdigest()
        self.assertIn(manifest_hash, bootstrap)
        self.assertNotIn("@", bootstrap)
        self.assertTrue((self.output / ".nojekyll").is_file())
        self.assertIn("ADGUARD-URLFILTER-LICENSE.txt", (self.output / "index.html").read_text(encoding="utf-8"))

    def test_empty_output_directory_is_supported(self):
        self.output.mkdir()
        self.build()
        self.assertTrue((self.output / "install.sh").exists())

    def test_nonempty_output_is_never_replaced(self):
        self.output.mkdir()
        sentinel = self.output / "keep.txt"
        sentinel.write_text("existing site")
        with self.assertRaisesRegex(site.BuildError, "refusing to replace"):
            self.build()
        self.assertEqual(sentinel.read_text(), "existing site")
        self.assertEqual(self.client.downloads, [])

    def test_previous_release_failure_does_not_publish_partial_site(self):
        self.client.fail_tag = "v1.7.0"
        self.assert_rejected_without_output("download failure")
        self.assertEqual(list(Path(self.temp.name).iterdir()), [])

    def test_missing_required_license_is_rejected_before_download(self):
        self.client.latest["assets"] = [a for a in self.client.latest["assets"] if a["name"] != site.LICENSE_ASSETS[0]]
        self.assert_rejected_without_output("required release assets missing")
        self.assertEqual(self.client.downloads, [])

    def test_optional_engine_license_is_not_required(self):
        self.client.latest, self.client.files["v1.7.1"] = release_fixture("v1.7.1", optional=False)
        self.build()
        self.assertFalse((self.output / "releases" / "v1.7.1" / site.OPTIONAL_ASSETS[0]).exists())

    def test_missing_github_digest_is_rejected(self):
        self.client.latest["assets"][0]["digest"] = None
        self.assert_rejected_without_output("GitHub SHA-256 digest")

    def test_github_digest_mismatch_is_rejected(self):
        name = site.PANEL_ASSETS[0]
        original = self.client.files["v1.7.1"][name]
        self.client.files["v1.7.1"][name] = b"x" * len(original)
        self.assert_rejected_without_output("GitHub SHA-256 mismatch")

    def test_manifest_mismatch_is_rejected_even_with_valid_github_digest(self):
        self.client.replace_file_and_digest(site.PANEL_ASSETS[0], b"changed binary")
        self.assert_rejected_without_output("manifest SHA-256 missing or mismatched")

    def test_duplicate_checksums_are_rejected(self):
        manifest = self.client.files["v1.7.1"]["SHA256SUMS"]
        self.client.replace_file_and_digest("SHA256SUMS", manifest + manifest.splitlines(keepends=True)[0])
        self.assert_rejected_without_output("duplicate checksum")

    def test_unsafe_manifest_names_are_rejected(self):
        for name in ("../install.sh", "/install.sh", "sub/file", "back\\file", "file with spaces"):
            with self.subTest(name=name), self.assertRaises(site.BuildError):
                site.parse_checksums(("a" * 64 + "  " + name + "\n").encode())

    def test_invalid_latest_tags_cannot_be_paths_or_shell(self):
        for tag in ("../v1.7.1", "v1.7.1-rc1", "v01.7.1", "v1.7.1'", "v1.7.1\n", None):
            with self.subTest(tag=tag), self.assertRaises(site.BuildError):
                release = copy.deepcopy(self.client.latest)
                release["tag_name"] = tag
                site.select_releases(release, self.client.recent)

    def test_prereleases_and_newer_versions_are_not_previous(self):
        future, _ = release_fixture("v1.8.0")
        prerelease, _ = release_fixture("v1.7.2")
        prerelease["prerelease"] = True
        self.client.recent = [future, prerelease, self.client.previous, self.client.latest]
        self.assertEqual([r["tag_name"] for r in site.select_releases(self.client.latest, self.client.recent)], ["v1.7.1", "v1.7.0"])

    def test_bootstrap_requires_all_tokens_and_no_unknown_tokens(self):
        for template in (TEMPLATE.replace("@RELEASE_TAG@", "v1.0.0"), TEMPLATE + "@UNKNOWN_TOKEN@\n", TEMPLATE + "@RELEASE_TAG@\n"):
            with self.subTest(template=template), self.assertRaises(site.BuildError):
                site.render_bootstrap(template, site.DEFAULT_BASE_URL, "v1.7.1", "a" * 64)

    def test_invalid_bootstrap_does_not_publish_partial_site(self):
        self.assert_rejected_without_output("unresolved bootstrap placeholder", TEMPLATE + "@UNKNOWN_TOKEN@\n")

    def test_https_url_cannot_inject_shell_or_change_transport(self):
        for url in ("http://example.com", "https://example.com/'", "https://example.com/$(id)", "https://user@example.com", "https://example.com/?token=x", "https://example.com/#x", "https://example.com/../else"):
            with self.subTest(url=url), self.assertRaises(site.BuildError):
                site.validate_base_url(url)

    def test_duplicate_release_assets_are_rejected(self):
        self.client.latest["assets"].append(dict(self.client.latest["assets"][0]))
        self.assert_rejected_without_output("duplicate release asset")


if __name__ == "__main__":
    unittest.main()
