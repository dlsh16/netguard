"""Prebuild disposable parsed NVD caches without touching the application DB."""
import argparse
import json
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from security.cve_checker import CVEChecker
from security.nvd_cache import _signature


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", type=Path)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    checker = CVEChecker()
    if args.cache_dir:
        checker.cache_dir = args.cache_dir.resolve()
    checker.load_local_db()
    if checker.load_errors or not checker.feed_count or not checker._cve_db:
        raise SystemExit("NVD cache preparation failed or no entries were loaded; check source files and logs")
    for source in checker.cache_dir.glob("nvdcve-*.json*"):
        derived = checker.cache_dir / ".parsed-v1" / (source.name + ".jsonl")
        try:
            with derived.open(encoding="utf-8") as handle:
                header = json.loads(handle.readline())
            if header.get("source") != _signature(source):
                raise ValueError("Stale parsed cache")
        except (OSError, ValueError, AttributeError) as error:
            raise SystemExit(f"Parsed cache not persisted for {source.name}: {error}") from error
    print(f"Prepared {len(checker._cve_db)} CVEs from {checker.feed_count} feeds: {checker.cache_dir}")


if __name__ == "__main__":
    main()
