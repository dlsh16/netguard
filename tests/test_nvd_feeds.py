import gzip
import hashlib
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import download_nvd_feeds as updater


class FeedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.cache = Path(self.temp.name) / "cache"
        self.cache.mkdir()
        self.payload = json.dumps({"totalResults": 1, "vulnerabilities": [{"cve": {"id": "CVE-2024-12345"}}]}).encode()
        self.compressed = gzip.compress(self.payload)
        self.meta = {"size": str(len(self.payload)), "gzSize": str(len(self.compressed)),
                     "sha256": hashlib.sha256(self.payload).hexdigest(), "lastModifiedDate": "2026-11-06T03:00:00-05:00"}

    def tearDown(self):
        self.temp.cleanup()

    def fake_download(self, url, dest):
        dest.write_bytes(("\n".join(f"{k}:{v}" for k, v in self.meta.items())).encode() if url.endswith(".meta") else self.compressed)

    def test_verified_update_backup_unchanged_and_bundle(self):
        target = self.cache / "nvdcve-2024.json"
        target.write_text("old data", encoding="utf-8")
        with patch.object(updater, "download", side_effect=self.fake_download) as download:
            result = updater.update_cache([2024], self.cache)
            self.assertEqual(result["feeds"]["2024"]["count"], 1)
            self.assertEqual(target.read_bytes(), self.payload)
            self.assertEqual(next((self.cache / ".backups").glob("*/nvdcve-2024.json")).read_text(), "old data")
            before = target.stat().st_mtime_ns
            download.reset_mock()
            updater.update_cache([2024], self.cache)
            self.assertEqual(download.call_count, 1)
            self.assertEqual(target.stat().st_mtime_ns, before)
        bundle = Path(self.temp.name) / "bundle.zip"
        updater.export_bundle(self.cache, [2024], bundle)
        with zipfile.ZipFile(bundle) as archive:
            self.assertIsNone(archive.testzip())
            self.assertEqual(archive.read("data/nvd_cache/nvdcve-2024.json"), self.payload)
            self.assertEqual(len(archive.namelist()), 3)

    def test_hash_failure_preserves_live_data(self):
        target = self.cache / "nvdcve-2024.json"
        target.write_text("original", encoding="utf-8")
        self.meta["sha256"] = "0" * 64
        with patch.object(updater, "download", side_effect=self.fake_download), self.assertRaises(ValueError):
            updater.update_cache([2024], self.cache)
        self.assertEqual(target.read_text(), "original")
        self.assertFalse((self.cache / "cache_meta.json").exists())
        self.assertFalse((self.cache / ".nvd-feed-update.lock").exists())

    def test_later_download_failure_keeps_all_previous_feeds(self):
        target = self.cache / "nvdcve-2024.json"
        target.write_text("original", encoding="utf-8")
        def fail_second_year(url, dest):
            if "2025" in url:
                raise OSError("test network failure")
            self.fake_download(url, dest)
        with patch.object(updater, "download", side_effect=fail_second_year), self.assertRaises(OSError):
            updater.update_cache([2024, 2025], self.cache)
        self.assertEqual(target.read_text(), "original")

    def test_invalid_meta_and_incomplete_feed(self):
        with self.assertRaises(ValueError):
            updater.parse_meta("sha256:bad")
        self.payload = b'{"vulnerabilities": [], "totalResults": 1}'
        self.compressed = gzip.compress(self.payload)
        self.meta.update(size=str(len(self.payload)), gzSize=str(len(self.compressed)), sha256=hashlib.sha256(self.payload).hexdigest())
        with patch.object(updater, "download", side_effect=self.fake_download), self.assertRaises(ValueError):
            updater.update_cache([2024], self.cache)

    def test_existing_lock_and_invalid_year(self):
        with self.assertRaises(ValueError):
            updater.update_cache([1999], self.cache)
        (self.cache / ".nvd-feed-update.lock").touch()
        with self.assertRaises(RuntimeError):
            updater.update_cache([2024], self.cache)


if __name__ == "__main__":
    unittest.main()
