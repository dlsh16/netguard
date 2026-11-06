"""Download and verify official annual NVD 2.0 feeds without an API key."""
import argparse
import gzip
import hashlib
import json
import logging
import os
import re
import shutil
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path


BASE_URL = "https://nvd.nist.gov/feeds/json/cve/2.0"
DEFAULT_CACHE_DIR = Path(__file__).resolve().parents[1] / "data" / "nvd_cache"
LOG = logging.getLogger("netguard.nvd.feeds")


def parse_meta(text):
    meta = dict(line.split(":", 1) for line in text.splitlines() if ":" in line)
    if not re.fullmatch(r"[0-9a-fA-F]{64}", meta.get("sha256", "")):
        raise ValueError("NVD META has no valid SHA256")
    for key in ("size", "gzSize"):
        if int(meta.get(key, 0)) <= 0:
            raise ValueError(f"NVD META has no valid {key}")
    datetime.fromisoformat(meta["lastModifiedDate"].replace("Z", "+00:00"))
    return meta


def download(url, dest):
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NetGuard-NVD-Feed-Updater/1.0"})
            with urllib.request.urlopen(req, timeout=120) as response, dest.open("wb") as output:
                shutil.copyfileobj(response, output, length=1024 * 1024)
            return
        except (OSError, urllib.error.URLError):
            if attempt == 2:
                raise
            time.sleep(6 * (attempt + 1))


def verify_feed(path, meta):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    if path.stat().st_size != int(meta["size"]) or digest.hexdigest() != meta["sha256"].lower():
        raise ValueError(f"NVD SHA256/size verification failed: {path.name}")
    with path.open("r", encoding="utf-8-sig") as source:
        feed = json.load(source)
    items = feed.get("vulnerabilities")
    if not isinstance(items, list) or not items or len(items) != feed.get("totalResults"):
        raise ValueError(f"NVD feed is empty or incomplete: {path.name}")
    if any(not re.fullmatch(r"CVE-\d{4}-\d{4,}", item.get("cve", {}).get("id", "")) for item in items):
        raise ValueError(f"NVD feed has an invalid CVE identifier: {path.name}")
    return len(items)


def stage_feed(year, stage, cache_dir):
    name = f"nvdcve-{year}.json"
    meta_path = stage / f"nvdcve-{year}.meta"
    download(f"{BASE_URL}/nvdcve-2.0-{year}.meta", meta_path)
    meta = parse_meta(meta_path.read_text(encoding="utf-8-sig"))
    existing = cache_dir / name
    if existing.is_file():
        try:
            count = verify_feed(existing, meta)
            LOG.info("%s unchanged: %d CVEs", year, count)
            return {"year": year, "count": count, "meta": meta, "changed": False}
        except (ValueError, OSError):
            pass
    compressed = stage / f"{name}.gz"
    LOG.info("Downloading %s: %.1f MiB", year, int(meta["gzSize"]) / 1024 / 1024)
    download(f"{BASE_URL}/nvdcve-2.0-{year}.json.gz", compressed)
    if compressed.stat().st_size != int(meta["gzSize"]):
        raise ValueError(f"NVD compressed size mismatch: {year}; retry after feed publication completes")
    with gzip.open(compressed, "rb") as source, (stage / name).open("wb") as output:
        shutil.copyfileobj(source, output, length=1024 * 1024)
    count = verify_feed(stage / name, meta)
    LOG.info("Verified %s: %d CVEs; source updated %s", year, count, meta["lastModifiedDate"])
    return {"year": year, "count": count, "meta": meta, "changed": True}


def update_cache(years, cache_dir):
    cache_dir = Path(cache_dir).resolve()
    cache_dir.mkdir(parents=True, exist_ok=True)
    years = sorted(set(years))
    if not years or any(year < 2002 or year > datetime.now(timezone.utc).year for year in years):
        raise ValueError("Specify annual feed years from 2002 through the current year")
    # Do not expose partially downloaded JSON files to the running CVE loader.
    lock = cache_dir / ".nvd-feed-update.lock"
    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        raise RuntimeError(f"Another update may be running; inspect before removing {lock}") from None
    os.close(descriptor)
    try:
        with tempfile.TemporaryDirectory(prefix=".nvd-staging-", dir=cache_dir) as temp:
            stage = Path(temp)
            results = [stage_feed(year, stage, cache_dir) for year in years]
            now = datetime.now(timezone.utc)
            meta_path = cache_dir / "cache_meta.json"
            prior = json.loads(meta_path.read_text(encoding="utf-8-sig")) if meta_path.exists() else {}
            sources = dict(prior.get("feeds", {}))
            for result in results:
                sources[str(result["year"])] = {
                    "file": f"nvdcve-{result['year']}.json", "count": result["count"],
                    "source_updated": result["meta"]["lastModifiedDate"],
                    "sha256": result["meta"]["sha256"].lower(), "size": int(result["meta"]["size"]),
                }
            latest = max(datetime.fromisoformat(r["meta"]["lastModifiedDate"].replace("Z", "+00:00")) for r in results)
            metadata = {"mode": "official_annual_feeds", "last_updated": latest.astimezone(timezone.utc).isoformat(),
                        "downloaded_at": now.isoformat(), "years": sorted(int(y) for y in sources),
                        "updated_years": years, "feeds": sources, "source": BASE_URL}
            (stage / "cache_meta.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
            names = [f"nvdcve-{r['year']}.json" for r in results if r["changed"]]
            names += [f"nvdcve-{year}.meta" for year in years] + ["cache_meta.json"]
            backup = cache_dir / ".backups" / now.strftime("%Y%m%dT%H%M%S%fZ")
            existing = [name for name in names if (cache_dir / name).exists()]
            if existing:
                backup.mkdir(parents=True)
                for name in existing:
                    shutil.copy2(cache_dir / name, backup / name)
                LOG.info("Backup: %s", backup)
            for name in names:
                os.replace(stage / name, cache_dir / name)
            return metadata
    finally:
        lock.unlink()


def export_bundle(cache_dir, years, dest):
    dest = Path(dest).resolve()
    dest.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temp = tempfile.mkstemp(prefix=".nvd-bundle-", suffix=".zip", dir=dest.parent)
    os.close(descriptor)
    try:
        with zipfile.ZipFile(temp, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=True) as archive:
            for year in sorted(set(years)):
                for suffix in ("json", "meta"):
                    name = f"nvdcve-{year}.{suffix}"
                    archive.write(cache_dir / name, f"data/nvd_cache/{name}")
            metadata = json.loads((cache_dir / "cache_meta.json").read_text(encoding="utf-8"))
            metadata["years"] = sorted(set(years))
            metadata["feeds"] = {str(year): metadata["feeds"][str(year)] for year in years}
            archive.writestr("data/nvd_cache/cache_meta.json", json.dumps(metadata, indent=2) + "\n")
        os.replace(temp, dest)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
    LOG.info("Offline bundle: %s (%.1f MiB)", dest, dest.stat().st_size / 1024 / 1024)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--years", nargs="+", type=int, required=True)
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR)
    parser.add_argument("--bundle", type=Path, help="Optional offline ZIP path")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    try:
        metadata = update_cache(args.years, args.cache_dir)
        if args.bundle:
            export_bundle(args.cache_dir.resolve(), args.years, args.bundle)
        LOG.info("Complete: %d CVEs in selected years", sum(metadata["feeds"][str(y)]["count"] for y in set(args.years)))
    except Exception:
        LOG.exception("NVD update failed; do not treat this run as a successful update")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
