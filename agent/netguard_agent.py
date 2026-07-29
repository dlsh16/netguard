#!/usr/bin/env python3
"""
NetGuard Agent — 오프라인 호환 시스템 모니터링 에이전트
의존성: Python 3.6+ 표준 라이브러리만 사용 (psutil 선택적 자동 감지)
실행: python netguard_agent.py
"""
import ctypes
import base64
import json
import logging
import os
import platform
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib import error, request

# ── 설정 ──────────────────────────────────────────────────────────────────────
SCRIPT_DIR  = Path(__file__).parent.resolve()
CONFIG_FILE = SCRIPT_DIR / "agent_config.json"

DEFAULT_CONFIG = {
    "server_url":  "http://10.60.8.186:8000",
    "api_key":     "netguard-agent-key-2026",
    "interval":    60,
    "hostname":    "",
    "device_type": "server",
    "location":    "",
    "log_file":    "",
    "security_checks": {
        "enabled": False,
        "interval_hours": 24,
        "scripts": []
    },
}

def load_config():
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, encoding="utf-8") as f:
            cfg = json.load(f)
        merged = {**DEFAULT_CONFIG, **cfg}
    else:
        merged = DEFAULT_CONFIG.copy()
    if not merged["hostname"]:
        merged["hostname"] = socket.gethostname()
    merged["server_url"] = normalize_server_url(merged["server_url"])
    return merged

def normalize_server_url(url: str) -> str:
    value = str(url).strip()
    if not value.startswith(("http://", "https://")):
        value = "http://" + value
    return value.rstrip("/")

# ── 로깅 ──────────────────────────────────────────────────────────────────────
def setup_logging(log_file: str):
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=handlers,
    )
    return logging.getLogger("netguard-agent")

# ── psutil 자동 감지 ──────────────────────────────────────────────────────────
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

IS_WINDOWS = platform.system() == "Windows"

# ── 네트워크 속도 계산용 상태 ────────────────────────────────────────────────
_prev_net = {"rx": 0, "tx": 0, "ts": 0.0}

# ── Linux /proc 수집 함수 ─────────────────────────────────────────────────────
def _proc_read(path: str) -> str:
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return ""

def _cpu_linux() -> float:
    """두 번 /proc/stat 읽어 CPU 사용률(%) 계산"""
    def read_stat():
        line = _proc_read("/proc/stat").splitlines()[0]
        nums = list(map(int, line.split()[1:8]))
        return sum(nums), nums[3]

    t1, i1 = read_stat()
    time.sleep(0.5)
    t2, i2 = read_stat()
    dt = t2 - t1
    return round((1 - (i2 - i1) / dt) * 100, 1) if dt > 0 else 0.0

def _mem_linux() -> float:
    data = {}
    for line in _proc_read("/proc/meminfo").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            data[k.strip()] = int(v.strip().split()[0])
    total = data.get("MemTotal", 0)
    avail = data.get("MemAvailable", data.get("MemFree", 0))
    return round((total - avail) / total * 100, 1) if total else 0.0

def _disk_linux(path: str = "/") -> float:
    try:
        st = os.statvfs(path)
        total = st.f_blocks * st.f_frsize
        used  = (st.f_blocks - st.f_bfree) * st.f_frsize
        return round(used / total * 100, 1) if total else 0.0
    except OSError:
        return 0.0

def _disks_linux() -> list:
    disks = []
    try:
        out = subprocess.check_output(
            ["df", "-kP", "-x", "tmpfs", "-x", "devtmpfs"],
            stderr=subprocess.DEVNULL,
            timeout=8,
        ).decode(errors="replace")
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 6:
                continue
            size_kb, used_kb, avail_kb = int(parts[1]), int(parts[2]), int(parts[3])
            if size_kb <= 0:
                continue
            disks.append({
                "path": parts[5],
                "used_pct": round(used_kb / size_kb * 100, 1),
                "size_gb": round(size_kb / 1024 / 1024, 1),
                "used_gb": round(used_kb / 1024 / 1024, 1),
                "free_gb": round(avail_kb / 1024 / 1024, 1),
            })
    except Exception:
        pass
    return disks

def _processes_linux() -> list:
    processes = []
    try:
        out = subprocess.check_output(
            ["ps", "-eo", "pid=,comm=,cputime=,rss=", "--sort=-rss"],
            stderr=subprocess.DEVNULL,
            timeout=8,
        ).decode(errors="replace")
        for line in out.splitlines()[:50]:
            parts = line.split(None, 3)
            if len(parts) < 4:
                continue
            processes.append({
                "pid": int(parts[0]),
                "name": parts[1],
                "cpu_centisec": 0,
                "mem_kb": int(parts[3]),
            })
    except Exception:
        pass
    return processes

def _net_linux():
    """(rx_bytes, tx_bytes) 반환 — lo 인터페이스 제외"""
    rx = tx = 0
    for line in _proc_read("/proc/net/dev").splitlines()[2:]:
        parts = line.split()
        if len(parts) >= 10 and not parts[0].startswith("lo"):
            rx += int(parts[1])
            tx += int(parts[9])
    return rx, tx

# ── Windows wmic/ctypes 수집 함수 ────────────────────────────────────────────
def _wmic(args: list) -> str:
    try:
        return subprocess.check_output(
            ["wmic"] + args, stderr=subprocess.DEVNULL, timeout=8
        ).decode(errors="replace")
    except Exception:
        return ""

def _cpu_windows() -> float:
    out = _wmic(["cpu", "get", "LoadPercentage", "/value"])
    for line in out.splitlines():
        if "LoadPercentage=" in line:
            val = line.split("=", 1)[1].strip()
            return float(val) if val.isdigit() else 0.0
    return 0.0

def _mem_windows() -> float:
    out = _wmic(["OS", "get", "FreePhysicalMemory,TotalVisibleMemorySize", "/value"])
    d = {}
    for line in out.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            v = v.strip()
            if v.isdigit():
                d[k.strip()] = int(v)
    total = d.get("TotalVisibleMemorySize", 0)
    free  = d.get("FreePhysicalMemory", 0)
    return round((total - free) / total * 100, 1) if total else 0.0

def _disk_windows(path: str = "C:\\") -> float:
    try:
        free_b  = ctypes.c_ulonglong(0)
        total_b = ctypes.c_ulonglong(0)
        ctypes.windll.kernel32.GetDiskFreeSpaceExW(
            ctypes.c_wchar_p(path), None,
            ctypes.pointer(total_b),
            ctypes.pointer(free_b),
        )
        t = total_b.value
        return round((t - free_b.value) / t * 100, 1) if t else 0.0
    except Exception:
        return 0.0

def _disks_windows() -> list:
    disks = []
    out = _wmic(["logicaldisk", "where", "DriveType=3", "get", "DeviceID,FreeSpace,Size", "/value"])
    current = {}
    for line in out.splitlines():
        line = line.strip()
        if not line:
            if current:
                disks.append(current)
                current = {}
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            current[k.strip()] = v.strip()
    if current:
        disks.append(current)

    result = []
    for d in disks:
        try:
            size = int(d.get("Size", "0") or 0)
            free = int(d.get("FreeSpace", "0") or 0)
            if size <= 0:
                continue
            used = size - free
            result.append({
                "path": d.get("DeviceID", ""),
                "used_pct": round(used / size * 100, 1),
                "size_gb": round(size / 1024**3, 1),
                "used_gb": round(used / 1024**3, 1),
                "free_gb": round(free / 1024**3, 1),
            })
        except Exception:
            continue
    return result

def _processes_windows() -> list:
    processes = []
    out = _wmic(["process", "get", "Name,ProcessId,WorkingSetSize", "/format:csv"])
    for line in out.splitlines()[1:]:
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 4:
            continue
        try:
            name, pid, mem = parts[1], int(parts[2]), int(parts[3] or 0)
            if not name:
                continue
            processes.append({
                "pid": pid,
                "name": name,
                "cpu_centisec": 0,
                "mem_kb": int(mem / 1024),
            })
        except Exception:
            continue
    processes.sort(key=lambda p: p["mem_kb"], reverse=True)
    return processes[:50]

def _net_windows():
    """wmic으로 정확한 누적 바이트 취득이 어려워 netstat 파싱"""
    try:
        out = subprocess.check_output(
            ["netstat", "-e"], stderr=subprocess.DEVNULL, timeout=5
        ).decode(errors="replace")
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3 and "Bytes" in parts[0]:
                return int(parts[1]), int(parts[2])
    except Exception:
        pass
    return 0, 0

# ── 통합 수집 ─────────────────────────────────────────────────────────────────
def collect() -> dict:
    global _prev_net

    if HAS_PSUTIL:
        cpu  = psutil.cpu_percent(interval=1)
        mem  = psutil.virtual_memory().percent
        # 시스템 루트 파티션 선택
        parts = psutil.disk_partitions(all=False)
        root  = next(
            (p for p in parts if p.mountpoint in ("/", "C:\\")),
            parts[0] if parts else None,
        )
        disks = []
        for p in parts:
            try:
                usage = psutil.disk_usage(p.mountpoint)
                if usage.total <= 0:
                    continue
                disks.append({
                    "path": p.mountpoint,
                    "used_pct": round(usage.percent, 1),
                    "size_gb": round(usage.total / 1024**3, 1),
                    "used_gb": round(usage.used / 1024**3, 1),
                    "free_gb": round(usage.free / 1024**3, 1),
                })
            except Exception:
                continue
        disk = max([d["used_pct"] for d in disks], default=0.0)
        processes = []
        for proc in psutil.process_iter(["pid", "name", "cpu_times", "memory_info"]):
            try:
                info = proc.info
                cpu_times = info.get("cpu_times")
                cpu_centisec = int((cpu_times.user + cpu_times.system) * 100) if cpu_times else 0
                mem_info = info.get("memory_info")
                processes.append({
                    "pid": info["pid"],
                    "name": info.get("name") or "",
                    "cpu_centisec": cpu_centisec,
                    "mem_kb": int((mem_info.rss if mem_info else 0) / 1024),
                })
            except Exception:
                continue
        processes.sort(key=lambda p: (p["mem_kb"], p["cpu_centisec"]), reverse=True)
        processes = processes[:50]
        net  = psutil.net_io_counters()
        rx, tx = net.bytes_recv, net.bytes_sent

    elif IS_WINDOWS:
        cpu  = _cpu_windows()
        mem  = _mem_windows()
        disks = _disks_windows()
        disk = max([d["used_pct"] for d in disks], default=_disk_windows())
        processes = _processes_windows()
        rx, tx = _net_windows()
    else:
        cpu  = _cpu_linux()
        mem  = _mem_linux()
        disks = _disks_linux()
        disk = max([d["used_pct"] for d in disks], default=_disk_linux())
        processes = _processes_linux()
        rx, tx = _net_linux()

    # 네트워크 속도 계산 (bytes/sec)
    now = time.time()
    if _prev_net["ts"] > 0 and now > _prev_net["ts"]:
        dt = now - _prev_net["ts"]
        net_in_bps  = max(0.0, (rx - _prev_net["rx"]) / dt)
        net_out_bps = max(0.0, (tx - _prev_net["tx"]) / dt)
    else:
        net_in_bps = net_out_bps = 0.0
    _prev_net = {"rx": rx, "tx": tx, "ts": now}

    return {
        "cpu_pct":      round(float(cpu),  1),
        "mem_pct":      round(float(mem),  1),
        "disk_max_pct": round(float(disk), 1),
        "net_in_bps":   round(net_in_bps,  1),
        "net_out_bps":  round(net_out_bps, 1),
        "disks":        disks,
        "processes":    processes,
    }

# ── 로컬 IP 탐지 ──────────────────────────────────────────────────────────────
def local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

# ── HTTP 전송 ─────────────────────────────────────────────────────────────────
def post_json(url: str, data: dict, api_key: str, timeout: int = 10) -> dict:
    body = json.dumps(data).encode("utf-8")
    req  = request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("X-Agent-Key",  api_key)
    with request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())

# ── 점검/취약점 스크립트 실행 및 결과 업로드 ─────────────────────────────────
def _expand_agent_value(value: str, output_dir: str = "") -> str:
    return str(value).format(
        script_dir=str(SCRIPT_DIR),
        output_dir=output_dir,
        check_script_dir=str(SCRIPT_DIR / "check_scripts"),
    )

def _resolve_agent_path(value: str) -> Path:
    path = Path(_expand_agent_value(value))
    return path if path.is_absolute() else (SCRIPT_DIR / path).resolve()

def _report_files(output_dir: Path, since_ts: float) -> list:
    if not output_dir.exists():
        return []
    allowed = {".csv", ".html", ".htm", ".xlsx"}
    files = []
    for path in output_dir.iterdir():
        if path.is_file() and path.suffix.lower() in allowed and path.stat().st_mtime >= since_ts - 5:
            files.append(path)
    return sorted(files, key=lambda p: p.stat().st_mtime)

def _post_report(base: str, key: str, cfg: dict, ip: str, path: Path, run_type: str, logger):
    content = base64.b64encode(path.read_bytes()).decode("ascii")
    payload = {
        "hostname": cfg["hostname"],
        "ip_address": ip,
        "filename": path.name,
        "content_base64": content,
        "run_type": run_type,
        "os_type": platform.platform(),
    }
    result = post_json(f"{base}/api/agent/security-report", payload, key, timeout=60)
    logger.info(
        "Uploaded check report: %s (run=%s rows=%s)",
        path.name,
        result.get("id"),
        result.get("imported_results"),
    )

def run_security_checks(cfg: dict, base: str, key: str, ip: str, logger):
    check_cfg = cfg.get("security_checks") or {}
    if not check_cfg.get("enabled"):
        return
    scripts = check_cfg.get("scripts") or []
    if not scripts:
        logger.info("Security checks enabled but no scripts configured")
        return

    for item in scripts:
        name = item.get("name") or item.get("run_type") or "check-script"
        run_type = item.get("run_type") or "security"
        output_dir = _resolve_agent_path(item.get("output_dir") or f"output/{run_type}")
        output_dir.mkdir(parents=True, exist_ok=True)
        command = item.get("command")
        if not command:
            logger.warning("Check script skipped (%s): command is empty", name)
            continue
        expanded_command = (
            [_expand_agent_value(part, str(output_dir)) for part in command]
            if isinstance(command, list)
            else _expand_agent_value(command, str(output_dir))
        )
        started = time.time()
        logger.info("Running check script: %s", name)
        try:
            completed = subprocess.run(
                expanded_command,
                cwd=str(SCRIPT_DIR),
                shell=isinstance(expanded_command, str),
                capture_output=True,
                text=True,
                timeout=int(item.get("timeout_sec") or 3600),
            )
            if completed.returncode != 0:
                logger.warning(
                    "Check script failed (%s): rc=%s stdout=%s stderr=%s",
                    name,
                    completed.returncode,
                    (completed.stdout or "")[-500:],
                    (completed.stderr or "")[-500:],
                )
                continue
        except Exception as e:
            logger.error("Check script error (%s): %s", name, e)
            continue

        files = _report_files(output_dir, started)
        if not files:
            logger.warning("Check script produced no report files: %s", name)
            continue
        for report in files:
            try:
                _post_report(base, key, cfg, ip, report, run_type, logger)
            except Exception as e:
                logger.error("Report upload failed (%s): %s", report, e)

# ── 메인 루프 ─────────────────────────────────────────────────────────────────
def main():
    cfg    = load_config()
    logger = setup_logging(cfg.get("log_file", ""))
    base   = cfg["server_url"]
    key    = cfg["api_key"]

    logger.info("NetGuard Agent starting")
    logger.info(f"  Server  : {base}")
    logger.info(f"  Hostname: {cfg['hostname']}")
    logger.info(f"  psutil  : {'available' if HAS_PSUTIL else 'not found (stdlib fallback)'}")
    logger.info(f"  Interval: {cfg['interval']}s")

    ip = local_ip()

    # 초기 장치 등록
    try:
        post_json(f"{base}/api/agent/register", {
            "hostname":    cfg["hostname"],
            "ip_address":  ip,
            "device_type": cfg["device_type"],
            "location":    cfg["location"],
            "os":          platform.platform(),
        }, key)
        logger.info("Device registered/updated on server")
    except Exception as e:
        logger.warning(f"Register failed (will retry on next metrics post): {e}")

    # 첫 수집은 net 속도 0이므로 한 번 예열
    collect()
    time.sleep(2)
    next_check_at = 0.0

    while True:
        start = time.time()
        try:
            metrics = collect()
            payload = {
                "hostname":   cfg["hostname"],
                "ip_address": ip,
                **metrics,
            }
            post_json(f"{base}/api/agent/metrics", payload, key)
            logger.info(
                f"OK  cpu={metrics['cpu_pct']}%  "
                f"mem={metrics['mem_pct']}%  "
                f"disk={metrics['disk_max_pct']}%  "
                f"net_in={metrics['net_in_bps']:.0f}B/s"
            )
            check_cfg = cfg.get("security_checks") or {}
            if check_cfg.get("enabled") and time.time() >= next_check_at:
                run_security_checks(cfg, base, key, ip, logger)
                hours = float(check_cfg.get("interval_hours") or 24)
                next_check_at = time.time() + max(1.0, hours) * 3600
        except error.URLError as e:
            logger.warning(f"Network error: {e}")
        except error.HTTPError as e:
            body = e.read().decode(errors="replace")
            if e.code == 404:
                # 장치가 DB에 없음 → 재등록 시도
                logger.warning("Device not found on server, re-registering...")
                try:
                    post_json(f"{base}/api/agent/register", {
                        "hostname":    cfg["hostname"],
                        "ip_address":  ip,
                        "device_type": cfg["device_type"],
                        "location":    cfg["location"],
                        "os":          platform.platform(),
                    }, key)
                except Exception:
                    pass
            else:
                logger.error(f"HTTP {e.code}: {body[:200]}")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")

        elapsed = time.time() - start
        sleep_sec = max(1, cfg["interval"] - elapsed)
        time.sleep(sleep_sec)

if __name__ == "__main__":
    main()
