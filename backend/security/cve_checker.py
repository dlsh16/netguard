"""
CVE/CWE/CVSS Vulnerability Checker.
Offline mode: uses locally cached NVD JSON feeds.
Online mode: fetches from NVD API (when internet is available).

NVD JSON feed download (run once with internet, then use offline):
  python scripts/download_nvd.py
"""
import gzip
import json
import logging
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger('netguard.cve')

# OS/software keyword → CVE keyword mapping for impact assessment
DEVICE_KEYWORDS = {
    'Rocky Linux': ['linux', 'rhel', 'centos', 'rocky', 'glibc', 'kernel', 'openssl'],
    'Windows Server': ['windows', 'microsoft', 'iis', 'smb', 'rdp', 'ntlm'],
    'Cisco IOS': ['cisco', 'ios', 'catalyst', 'iosxe'],
    'HP ProCurve': ['hp', 'procurve', 'hpe'],
    'APC UPS': ['apc', 'ups', 'schneider'],
    'Raspbian': ['raspberry', 'raspbian', 'debian', 'linux'],
}

SEVERITY_MAP = {
    'CRITICAL': (9.0, 10.0),
    'HIGH':     (7.0, 8.9),
    'MEDIUM':   (4.0, 6.9),
    'LOW':      (0.1, 3.9),
    'NONE':     (0.0, 0.0),
}


class CVEChecker:
    def __init__(self):
        from config import settings
        self.cache_dir = Path(settings.NVD_CACHE_DIR)
        if not self.cache_dir.is_absolute():
            self.cache_dir = Path(__file__).resolve().parents[2] / self.cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._cve_db: List[dict] = []
        self._loaded = False
        self.last_updated: Optional[str] = None
        self.feed_count = 0
        self._cache_signature: Optional[Tuple[Tuple[str, float, int], ...]] = None

    def load_local_db(self):
        """Load NVD JSON feeds from cache directory."""
        entries = []
        feed_files = list(self.cache_dir.glob("nvdcve-*.json*"))
        self.feed_count = len(feed_files)
        self.last_updated = self._get_last_updated(feed_files)

        if not feed_files:
            logger.warning("No NVD cache files found. Run scripts/download_nvd.py to populate.")
            self._loaded = True
            return

        for path in sorted(feed_files):
            try:
                opener = gzip.open if path.suffix == '.gz' else open
                # utf-8-sig accepts both regular UTF-8 and Windows-exported UTF-8 with BOM.
                with opener(path, 'rt', encoding='utf-8-sig') as f:
                    feed = json.load(f)
                items = feed.get('CVE_Items', feed.get('vulnerabilities', []))
                for item in items:
                    entry = self._parse_nvd_item(item)
                    if entry:
                        entries.append(entry)
            except Exception as e:
                logger.error(f"Failed to load {path}: {e}")

        self._cve_db = entries
        self._loaded = True
        self._cache_signature = self._build_cache_signature(feed_files)
        logger.info(f"Loaded {len(entries)} CVE entries from local NVD cache")

    def _get_last_updated(self, feed_files: List[Path]) -> Optional[str]:
        """Return cache metadata time, or fall back to newest feed file mtime."""
        meta_path = self.cache_dir / "cache_meta.json"
        if meta_path.exists():
            try:
                with open(meta_path, 'r', encoding='utf-8-sig') as f:
                    meta = json.load(f)
                last_updated = meta.get('last_updated')
                if last_updated:
                    return last_updated
            except Exception as e:
                logger.warning(f"Failed to read {meta_path}: {e}")

        if not feed_files:
            return None

        newest_mtime = max(path.stat().st_mtime for path in feed_files)
        return datetime.fromtimestamp(newest_mtime).astimezone().isoformat()

    def _build_cache_signature(self, feed_files: Optional[List[Path]] = None) -> Tuple[Tuple[str, float, int], ...]:
        """Build a lightweight signature to detect imported or updated cache files."""
        paths = list(feed_files or self.cache_dir.glob("nvdcve-*.json*"))
        meta_path = self.cache_dir / "cache_meta.json"
        if meta_path.exists():
            paths.append(meta_path)
        return tuple(
            sorted((path.name, path.stat().st_mtime, path.stat().st_size) for path in paths)
        )

    def reload_if_changed(self):
        """Reload cached CVEs when feed files or metadata changed on disk."""
        current_signature = self._build_cache_signature()
        if self._loaded and current_signature != self._cache_signature:
            logger.info("NVD cache change detected. Reloading local CVE database.")
            self.load_local_db()

    def _parse_nvd_item(self, item: dict) -> Optional[dict]:
        """Parse both NVD 1.1 and 2.0 feed formats."""
        try:
            # NVD 2.0 format
            if 'cve' in item and 'id' in item.get('cve', {}):
                cve = item['cve']
                cve_id = cve['id']
                desc = next((d['value'] for d in cve.get('descriptions', []) if d['lang'] == 'en'), '')
                metrics = cve.get('metrics', {})
                cvss_data = (metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {})
                             or metrics.get('cvssMetricV30', [{}])[0].get('cvssData', {})
                             or metrics.get('cvssMetricV2', [{}])[0].get('cvssData', {}))
                score = cvss_data.get('baseScore', 0.0)
                vector = cvss_data.get('vectorString', '')
                cwe_list = [p['description'][0]['value'] for p in cve.get('weaknesses', [])
                            if p.get('description')]
                severity = self._score_to_severity(score)
                keywords = self._extract_keywords(cve_id, desc, cve.get('configurations', {}))
                return {'id': cve_id, 'desc': desc, 'score': score, 'vector': vector,
                        'cwe': cwe_list[0] if cwe_list else '', 'severity': severity,
                        'keywords': keywords, 'published': cve.get('published', '')}

            # NVD 1.1 format
            if 'cve' in item:
                cve = item['cve']
                cve_id = cve['CVE_data_meta']['ID']
                desc = cve['description']['description_data'][0]['value']
                impact = item.get('impact', {})
                base_metric = impact.get('baseMetricV3', impact.get('baseMetricV2', {}))
                cvss_data = base_metric.get('cvssV3', base_metric.get('cvssV2', {}))
                score = cvss_data.get('baseScore', 0.0)
                vector = cvss_data.get('vectorString', '')
                cwes = [p['value'] for pb in cve.get('problemtype', {}).get('problemtype_data', [])
                        for p in pb.get('description', [])]
                severity = self._score_to_severity(score)
                keywords = self._extract_keywords(cve_id, desc, item.get('configurations', {}))
                return {'id': cve_id, 'desc': desc, 'score': score, 'vector': vector,
                        'cwe': cwes[0] if cwes else '', 'severity': severity,
                        'keywords': keywords, 'published': item.get('publishedDate', '')}
        except Exception:
            pass
        return None

    @staticmethod
    def _score_to_severity(score: float) -> str:
        if score >= 9.0: return 'CRITICAL'
        if score >= 7.0: return 'HIGH'
        if score >= 4.0: return 'MEDIUM'
        if score > 0:    return 'LOW'
        return 'NONE'

    @staticmethod
    def _extract_keywords(cve_id: str, desc: str, configurations: dict) -> List[str]:
        words = set(re.findall(r'\b[a-zA-Z]{3,}\b', desc.lower()))
        return list(words)

    def check_device(self, device_name: str, os_version: str,
                     software_list: Optional[List[str]] = None) -> List[dict]:
        """Return CVEs relevant to the given device/OS."""
        if not self._loaded:
            self.load_local_db()

        os_keywords = set()
        for os_key, kws in DEVICE_KEYWORDS.items():
            if os_key.lower() in os_version.lower():
                os_keywords.update(kws)

        if not os_keywords:
            os_words = re.findall(r'\b[a-zA-Z]{3,}\b', os_version.lower())
            os_keywords.update(os_words)

        if software_list:
            for sw in software_list:
                os_keywords.update(re.findall(r'\b[a-zA-Z]{3,}\b', sw.lower()))

        results = []
        for cve in self._cve_db:
            if cve['score'] < 4.0:
                continue
            cve_kws = set(cve.get('keywords', []))
            if os_keywords & cve_kws:
                results.append({
                    'cve_id': cve['id'],
                    'severity': cve['severity'],
                    'cvss': cve['score'],
                    'cwe': cve['cwe'],
                    'description': cve['desc'][:200],
                    'vector': cve['vector'],
                    'device': device_name,
                    'published': cve.get('published', '')
                })

        results.sort(key=lambda x: x['cvss'], reverse=True)
        return results[:50]

    def get_summary(self, devices: List[dict], completed_cve_ids: Optional[set[str]] = None) -> dict:
        """Return aggregated CVE summary across all devices."""
        if not self._loaded:
            self.load_local_db()
        else:
            self.reload_if_changed()

        completed_cve_ids = completed_cve_ids or set()
        all_cves: Dict[str, dict] = {}
        for device in devices:
            hits = self.check_device(
                device['name'],
                device.get('os_version', ''),
                device.get('software', [])
            )
            for hit in hits:
                cid = hit['cve_id']
                if cid in completed_cve_ids:
                    continue
                if cid not in all_cves:
                    all_cves[cid] = {**hit, 'affected_devices': []}
                all_cves[cid]['affected_devices'].append(device['name'])

        cve_list = list(all_cves.values())
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for c in cve_list:
            counts[c['severity']] = counts.get(c['severity'], 0) + 1

        return {
            'total': len(cve_list),
            'counts': counts,
            'items': sorted(cve_list, key=lambda x: x['cvss'], reverse=True)[:100],
            'last_updated': self.last_updated,
            'feed_count': self.feed_count,
            'loaded_entries': len(self._cve_db),
        }
