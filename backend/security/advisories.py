"""Normalized advisory provider boundary; RSS now, approved C-TAS API later."""
import asyncio
import hashlib
import logging
import re
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from urllib.parse import urlparse, parse_qs
from xml.etree import ElementTree as ET

import aiohttp

RSS_URL = 'https://www.boho.or.kr/kr/rss.do?bbsId=B0000133'
MAX_FEED = 5 * 1024 * 1024
logger = logging.getLogger('netguard.advisories')
sync_lock = asyncio.Lock()


class PlainText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []

    def handle_data(self, data):
        self.parts.append(data)


def plain(value):
    parser = PlainText()
    parser.feed(value or '')
    return ' '.join(' '.join(parser.parts).split())


def safe_link(url):
    parsed = urlparse(url)
    return parsed.scheme == 'https' and parsed.hostname in ('www.boho.or.kr', 'www.krcert.or.kr', 'ctas.krcert.or.kr') and not parsed.username


def parse_rss(data):
    if len(data) > MAX_FEED or b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper():
        raise ValueError('Unsupported or oversized RSS XML')
    root = ET.fromstring(data.decode('utf-8-sig'))
    if root.tag != 'rss' or root.find('channel') is None:
        raise ValueError('Expected RSS channel; login/error HTML cannot be imported')
    entries = []
    for item in root.findall('./channel/item')[:1000]:
        title, url = plain(item.findtext('title')), (item.findtext('link') or '').strip()
        if not title or not safe_link(url):
            continue
        date = None
        raw_date = (item.findtext('pubDate') or '').strip()
        if raw_date:
            try:
                date = parsedate_to_datetime(raw_date)
            except (TypeError, ValueError):
                try:
                    date = datetime.fromisoformat(raw_date.replace('Z', '+00:00'))
                except ValueError:
                    pass
        if date and date.tzinfo is None:
            date = date.replace(tzinfo=timezone(timedelta(hours=9)))
        query = parse_qs(urlparse(url).query)
        identity = 'kisa-rss:'+query['nttId'][0] if query.get('nttId') else url
        entries.append(dict(id=hashlib.sha256(identity.encode()).hexdigest(), provider='kisa-rss',
                            title=title[:1000],url=url,summary=plain(item.findtext('description'))[:30000],published_at=date))
    if not entries:
        raise ValueError('RSS contains no usable security advisories; existing data preserved')
    return entries


class KisaRssProvider:
    name = 'kisa-rss'

    async def fetch(self):
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
            async with session.get(RSS_URL, allow_redirects=False) as response:
                response.raise_for_status()
                if response.status != 200:
                    raise ValueError('Unexpected RSS response status')
                chunks, size = [], 0
                async for chunk in response.content.iter_chunked(65536):
                    size += len(chunk)
                    if size > MAX_FEED:
                        raise ValueError('RSS exceeds size limit')
                    chunks.append(chunk)
                return parse_rss(b''.join(chunks))


# An API adapter must implement fetch() and return the same normalized records.
# No unverified C-TAS endpoint, authentication method or HTML scraping is assumed.
PROVIDERS = {'kisa-rss': KisaRssProvider}


async def save_advisories(conn, entries, provider='kisa-rss'):
    if any(entry['provider'] != provider for entry in entries):
        raise ValueError('Advisory provider mismatch')
    async with conn.transaction():
        await conn.executemany('''INSERT INTO security_advisories(id,provider,title,url,summary,published_at)
            VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(id) DO UPDATE SET title=EXCLUDED.title,
            url=EXCLUDED.url,summary=EXCLUDED.summary,published_at=EXCLUDED.published_at,received_at=NOW()''',
            [(e['id'],e['provider'],e['title'],e['url'],e['summary'],e['published_at']) for e in entries])
        await conn.execute('''INSERT INTO advisory_sync(provider,attempted_at,succeeded_at,item_count)
            VALUES($1,NOW(),NOW(),$2) ON CONFLICT(provider) DO UPDATE SET
            attempted_at=NOW(),succeeded_at=NOW(),error=NULL,item_count=$2''',provider,len(entries))


async def sync_advisories(pool, provider='kisa-rss'):
    if sync_lock.locked():
        return {'status': 'running'}
    async with sync_lock:
        try:
            entries = await PROVIDERS[provider]().fetch()
            async with pool.acquire() as conn:
                await save_advisories(conn, entries, provider)
            logger.info('RSS synchronized: %s advisories',len(entries))
            return {'status': 'ok','count':len(entries)}
        except Exception as exc:
            logger.warning('RSS synchronization failed: %s',exc)
            async with pool.acquire() as conn:
                await conn.execute('''INSERT INTO advisory_sync(provider,attempted_at,error)
                    VALUES($1,NOW(),$2) ON CONFLICT(provider) DO UPDATE SET attempted_at=NOW(),error=$2''',provider,str(exc)[:500])
            raise


async def advisory_loop(pool, settings):
    while True:
        if settings.ADVISORY_SYNC_ENABLED:
            try:
                await sync_advisories(pool, settings.ADVISORY_PROVIDER)
            except Exception:
                pass
        await asyncio.sleep(max(300, settings.ADVISORY_SYNC_INTERVAL))


FAMILIES = {
    'PHP': r'(?<![a-z])php(?:[0-9.-]|\b)',
    'Node.js': r'\bnode(?:[ .-]?js)\b',
    'Apache Tomcat': r'\btomcat\b',
    'Apache HTTP Server': r'\b(?:httpd|apache\s+http\s+server)\b',
    'OpenSSL': r'\bopenssl\b', 'OpenSSH': r'\bopenssh\b',
    'Linux': r'\b(?:linux|kernel)\b', 'Windows': r'\bwindows\b',
    'VMware': r'\b(?:vmware|esxi|vcenter)\b', 'Chrome': r'\bchrome\b',
    'Firefox': r'\bfirefox\b', 'PostgreSQL': r'\bpostgres(?:ql)?\b',
    'MySQL': r'\bmysql\b', 'MariaDB': r'\bmariadb\b', 'Drupal': r'\bdrupal\b',
    'WordPress': r'\bwordpress\b', 'nginx': r'\bnginx\b', 'Java': r'\b(?:java|jdk|jre)\b',
    'Palo Alto Networks': r'\b(?:palo alto|pan-os|globalprotect)\b',
    'Synology': r'\bsynology\b', 'HPE': r'\b(?:hpe|hewlett.packard|comware)\b',
}


def families(text):
    return {name for name, pattern in FAMILIES.items() if re.search(pattern,text,re.I)}


def match_reason(advisory, software, advisory_families=None, software_families=None):
    text = advisory['title'] + ' ' + advisory['summary']
    common = (families(text) if advisory_families is None else advisory_families) & (families(software['software_name']) if software_families is None else software_families)
    if common:
        return ', '.join(sorted(common)) + ' 제품군 일치 · 버전 검증 필요'
    name = software['software_name'].strip().casefold()
    if len(name) >= 5 and re.search(r'(?<!\w)' + re.escape(name) + r'(?!\w)',text.casefold()):
        return '제품명 일치 · 버전 검증 필요'
    return None
