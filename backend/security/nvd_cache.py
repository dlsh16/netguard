"""Reusable normalized feeds; raw NVD JSON stays the source of truth."""
import gzip
import json
import logging
import os
import tempfile

LOG = logging.getLogger("netguard.cve")
CACHE_VERSION = 1


def _signature(path):
    stat = path.stat()
    return {"version": CACHE_VERSION, "size": stat.st_size, "mtime_ns": stat.st_mtime_ns}


def load_entries(path, parse):
    signature = _signature(path)
    cached = path.parent / ".parsed-v1" / (path.name + ".jsonl")
    try:
        with cached.open("r", encoding="utf-8") as source:
            header = json.loads(source.readline())
            if isinstance(header, dict) and header.get("source") == signature:
                entries = [json.loads(line) for line in source]
                if len(entries) == header["count"] and all(isinstance(e, dict) and "id" in e and "score" in e for e in entries):
                    if _signature(path) != signature:
                        raise ValueError("NVD source changed while reading parsed cache")
                    LOG.info("Loaded parsed NVD cache: %s (%d CVEs)", path.name, len(entries))
                    return entries
    except (OSError, ValueError, KeyError, TypeError):
        pass
    entries = None
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8-sig") as source:
        feed = json.load(source)
    items = feed.get("CVE_Items", feed.get("vulnerabilities", []))
    entries = []
    for item in items:
        entry = parse(item)
        if entry:
            entries.append(entry)
    # Release the raw object tree before reading the next annual feed.
    del feed, items
    if _signature(path) != signature:
        raise ValueError(f"NVD file changed during loading: {path.name}; retry after import completes")
    temporary = None
    try:
        cached.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=".building-", dir=cached.parent)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(json.dumps({"source": signature, "count": len(entries)}) + "\n")
            for entry in entries:
                output.write(json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n")
        os.replace(temporary, cached)
        LOG.info("Built parsed NVD cache: %s (%d CVEs)", path.name, len(entries))
    except OSError as error:
        LOG.warning("Cannot persist parsed NVD cache for %s: %s", path.name, error)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)
    return entries
