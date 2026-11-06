"""Measure local NVD load/search cost without connecting to the production DB."""
import ctypes
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from security.cve_checker import CVEChecker


def peak_memory_mb():
    if os.name != "nt":
        import resource
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    class Counters(ctypes.Structure):
        _fields_ = [("cb", ctypes.c_ulong), ("PageFaultCount", ctypes.c_ulong)] + [
            (name, ctypes.c_size_t) for name in ("PeakWorkingSetSize", "WorkingSetSize",
                "QuotaPeakPagedPoolUsage", "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage",
                "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage")]
    counters = Counters()
    counters.cb = ctypes.sizeof(counters)
    get_process = ctypes.windll.kernel32.GetCurrentProcess
    get_process.restype = ctypes.c_void_p
    memory_info = ctypes.windll.psapi.GetProcessMemoryInfo
    memory_info.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong]
    if not memory_info(get_process(), ctypes.byref(counters), counters.cb):
        raise ctypes.WinError()
    return counters.PeakWorkingSetSize / 1024 / 1024


def main():
    devices = [{"id": i + 1, "name": f"benchmark-{i+1}", "type": "switch" if i < 16 else "server",
                "ip_address": f"192.0.2.{i+1}", "os_version": "HPE Comware 7.1.070" if i < 16 else "Windows Server 2019"}
               for i in range(20)]
    checker = CVEChecker()
    results = {}
    start = time.perf_counter()
    data = checker.get_summary(devices)
    results["initial_summary_seconds"] = round(time.perf_counter() - start, 3)
    for name, query in (("repeat_summary", {}), ("catalog", {"scope": "catalog"}),
                        ("catalog_repeat", {"scope": "catalog"}), ("product_search", {"scope": "catalog", "q": "product:comware"})):
        start = time.perf_counter()
        checker.get_summary(devices) if name == "repeat_summary" else checker.search(devices, **query)
        results[name + "_seconds"] = round(time.perf_counter() - start, 3)
    results.update(catalog_total=data.get("catalog_total"), candidate_cves=data["total"],
                   peak_memory_mb=round(peak_memory_mb(), 1), load_errors=checker.load_errors)
    print(json.dumps(results), flush=True)


if __name__ == "__main__":
    main()
