import argparse
import json
import logging
import os
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
logger = logging.getLogger("nvd_update")

DEFAULT_CACHE_DIR = Path(__file__).parent.parent / "data" / "nvd_cache"
API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def iso_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def request_page(api_key: str, start: datetime, end: datetime, start_index: int) -> dict:
    params = urllib.parse.urlencode({
        "lastModStartDate": start.isoformat(timespec="milliseconds"),
        "lastModEndDate": end.isoformat(timespec="milliseconds"),
        "startIndex": start_index,
        "resultsPerPage": 2000,
    })
    req = urllib.request.Request(
        f"{API_BASE}?{params}",
        headers={"apiKey": api_key, "User-Agent": "NetGuard/1.0"},
    )
    with urllib.request.urlopen(req, timeout=120) as response:
        return json.loads(response.read())


def fetch_modified(api_key: str, start: datetime, end: datetime) -> list[dict]:
    results = []
    start_index = 0
    while True:
        data = request_page(api_key, start, end, start_index)
        total = data.get("totalResults", 0)
        vulns = data.get("vulnerabilities", [])
        results.extend(vulns)
        logger.info("변경 CVE 수집: %d/%d", start_index + len(vulns), total)
        if start_index + len(vulns) >= total:
            break
        start_index += 2000
        time.sleep(6)
    return results


def cve_year(item: dict) -> str:
    cve_id = item.get("cve", {}).get("id", "")
    parts = cve_id.split("-")
    return parts[1] if len(parts) >= 3 and parts[1].isdigit() else "unknown"


def load_feed(path: Path) -> dict:
    if not path.exists():
        return {"vulnerabilities": [], "year": path.stem.rsplit("-", 1)[-1]}
    with open(path, "r", encoding="utf-8-sig") as f:
        return json.load(f)


def merge_updates(cache_dir: Path, vulnerabilities: list[dict]) -> dict[str, int]:
    grouped: dict[str, list[dict]] = {}
    for item in vulnerabilities:
        grouped.setdefault(cve_year(item), []).append(item)

    changed_counts: dict[str, int] = {}
    for year, items in sorted(grouped.items()):
        if year == "unknown":
            logger.warning("연도 식별 불가 CVE %d건은 건너뜀", len(items))
            continue

        dest = cache_dir / f"nvdcve-{year}.json"
        feed = load_feed(dest)
        current = {
            item.get("cve", {}).get("id"): item
            for item in feed.get("vulnerabilities", [])
            if item.get("cve", {}).get("id")
        }
        for item in items:
            cve_id = item.get("cve", {}).get("id")
            if cve_id:
                current[cve_id] = item

        feed["year"] = int(year)
        feed["vulnerabilities"] = list(current.values())
        with open(dest, "w", encoding="utf-8") as f:
            json.dump(feed, f)
        changed_counts[year] = len(items)
        logger.info("%s년 피드 반영: %d건", year, len(items))

    return changed_counts


def read_meta(cache_dir: Path) -> dict:
    path = cache_dir / "cache_meta.json"
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8-sig") as f:
        return json.load(f)


def write_meta(cache_dir: Path, start: datetime, end: datetime, changed_counts: dict[str, int]) -> None:
    meta = read_meta(cache_dir)
    meta.update({
        "mode": "incremental",
        "last_updated": iso_utc(end),
        "last_incremental_start": iso_utc(start),
        "last_incremental_end": iso_utc(end),
        "changed_counts": changed_counts,
    })
    with open(cache_dir / "cache_meta.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-key", default=os.environ.get("NVD_API_KEY"))
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR)
    parser.add_argument("--hours", type=int, default=2)
    parser.add_argument("--since")
    args = parser.parse_args()

    if not args.api_key:
        parser.error("--api-key 또는 NVD_API_KEY 환경변수가 필요합니다.")

    args.cache_dir.mkdir(parents=True, exist_ok=True)
    end = datetime.now(timezone.utc)
    start = parse_iso(args.since) if args.since else end - timedelta(hours=args.hours)

    logger.info("NVD 증분 업데이트 시작: %s ~ %s", iso_utc(start), iso_utc(end))
    vulnerabilities = fetch_modified(args.api_key, start, end)
    changed_counts = merge_updates(args.cache_dir, vulnerabilities)
    write_meta(args.cache_dir, start, end, changed_counts)
    logger.info("NVD 증분 업데이트 완료: 총 %d건", len(vulnerabilities))


if __name__ == "__main__":
    main()
