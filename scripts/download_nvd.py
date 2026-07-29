import argparse
import json
import logging
import os
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
logger = logging.getLogger("nvd_download")
CACHE_DIR = Path(__file__).parent.parent / "data" / "nvd_cache"
API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_cves(api_key, year):
    results = []
    start_index = 0
    while True:
        url = (
            API_BASE
            + "?pubStartDate="
            + str(year)
            + "-01-01T00:00:00.000%2B00:00&pubEndDate="
            + str(year)
            + "-12-31T23:59:59.999%2B00:00&startIndex="
            + str(start_index)
            + "&resultsPerPage=2000"
        )
        req = urllib.request.Request(url, headers={"apiKey": api_key, "User-Agent": "NetGuard/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=120) as response:
                data = json.loads(response.read())
            total = data.get("totalResults", 0)
            vulns = data.get("vulnerabilities", [])
            results.extend(vulns)
            logger.info("  %d/%d 건 수집", start_index + len(vulns), total)
            if start_index + len(vulns) >= total:
                break
            start_index += 2000
            time.sleep(6)
        except Exception as exc:
            logger.error("  오류: %s", exc)
            break
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-key", default=os.environ.get("NVD_API_KEY"))
    parser.add_argument("--years", nargs="+", type=int, default=list(range(2020, datetime.now().year + 1)))
    args = parser.parse_args()

    if not args.api_key:
        parser.error("--api-key 또는 NVD_API_KEY 환경변수가 필요합니다.")

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    for year in args.years:
        dest = CACHE_DIR / ("nvdcve-" + str(year) + ".json")
        if dest.exists():
            dest.unlink()
        logger.info("%d년 CVE 수집 시작...", year)
        cves = fetch_cves(args.api_key, year)
        with open(dest, "w", encoding="utf-8") as f:
            json.dump({"vulnerabilities": cves, "year": year}, f)
        logger.info("%d년 완료: %d건", year, len(cves))
        time.sleep(1)

    with open(CACHE_DIR / "cache_meta.json", "w", encoding="utf-8") as f:
        json.dump({
            "mode": "full",
            "last_updated": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "years": args.years,
        }, f, ensure_ascii=False, indent=2)

    logger.info("전체 완료. 저장 위치: %s", CACHE_DIR)


if __name__ == "__main__":
    main()
