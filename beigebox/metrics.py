"""
System metrics collection — CPU, RAM, GPU.
All collection is best-effort; missing hardware or libraries produce None/[] rather than raising.

Linux-only for direct collection: reads /proc/stat, /proc/meminfo, and
/sys/class/thermal for CPU/RAM/temp; shells out to nvidia-smi for GPU stats.
On non-Linux hosts (e.g. macOS) the /proc and /sys paths are absent — the
collectors return Nones and an empty GPU list, matching prior behavior.

Host-bridge mode (macOS): when running BeigeBox inside Docker on macOS, in-container
metrics report the Linux VM's stats, not the host Mac's. Set the env var
BEIGEBOX_HOST_METRICS_URL (or `metrics.host_metrics_url` in config.yaml) to a tiny
host-side helper (~/.beigebox/host_metrics.py) and the collector will fetch real
host stats from there instead. The helper runs as a LaunchAgent on the host.
"""

from __future__ import annotations

import asyncio
import logging
import os
import subprocess
import time
import urllib.request
from typing import Any
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_cache: dict[str, Any] = {}
_cache_ts: float = 0.0
_CACHE_TTL: float = 1.0  # seconds

# Set once at first use; populated from env var or config.
_host_metrics_url: str | None = None
_host_metrics_resolved: bool = False
_host_metrics_failures: int = 0
_HOST_METRICS_FAIL_THRESHOLD = 3  # back off after this many consecutive failures

# CPU sampling state: stash the previous /proc/stat snapshot so successive
# calls compute a delta without paying a 100ms blocking sleep every time.
_cpu_prev_total: int | None = None
_cpu_prev_idle: int | None = None


# ---------------------------------------------------------------------------
# CPU — /proc/stat
# ---------------------------------------------------------------------------

def _read_proc_stat_cpu() -> tuple[int, int] | None:
    """Read first 'cpu' line of /proc/stat and return (total_jiffies, idle_jiffies).

    Returns None if /proc/stat is unavailable (non-Linux host).
    """
    try:
        with open("/proc/stat", "r") as f:
            line = f.readline()
    except OSError:
        return None
    if not line.startswith("cpu "):
        return None
    fields = line.split()
    # Fields after 'cpu': user nice system idle iowait irq softirq steal guest guest_nice
    try:
        nums = [int(x) for x in fields[1:]]
    except ValueError:
        return None
    if len(nums) < 4:
        return None
    total = sum(nums)
    # idle = idle + iowait (psutil counts iowait as idle for cpu_percent).
    idle = nums[3] + (nums[4] if len(nums) > 4 else 0)
    return total, idle


def _cpu_percent(interval: float = 0.1) -> float | None:
    """Compute system-wide CPU utilization percent over `interval` seconds.

    First call after import: takes a snapshot, sleeps `interval`, takes a
    second snapshot, returns the delta-based percent. This matches
    psutil.cpu_percent(interval=0.1) semantics — including the 100ms blocking
    sleep that cpu_percent() does on the first call.
    Subsequent calls reuse the previous snapshot if interval is 0, but for
    parity with the previous behavior we always re-sample.
    """
    global _cpu_prev_total, _cpu_prev_idle
    first = _read_proc_stat_cpu()
    if first is None:
        return None
    if interval > 0:
        time.sleep(interval)
        second = _read_proc_stat_cpu()
        if second is None:
            return None
    else:
        # Use previous snapshot if available, else block briefly.
        if _cpu_prev_total is None:
            time.sleep(0.1)
            second = _read_proc_stat_cpu()
            if second is None:
                return None
        else:
            second = first
            first = (_cpu_prev_total, _cpu_prev_idle)

    total_delta = second[0] - first[0]
    idle_delta = second[1] - first[1]
    _cpu_prev_total, _cpu_prev_idle = second
    if total_delta <= 0:
        return 0.0
    busy = total_delta - idle_delta
    return max(0.0, min(100.0, 100.0 * busy / total_delta))


def _cpu_temp() -> float | None:
    """Read CPU temperature from /sys/class/thermal/.

    Walks thermal_zone* directories, prefers types matching common CPU
    sensors (coretemp, k10temp, cpu_thermal, etc.) in the same priority
    order the previous psutil.sensors_temperatures() code used.
    """
    base = "/sys/class/thermal"
    if not os.path.isdir(base):
        return None
    preferred = ("coretemp", "k10temp", "acpitz", "acpi", "cpu_thermal", "x86_pkg_temp")
    candidates: dict[str, list[float]] = {}
    try:
        zones = sorted(d for d in os.listdir(base) if d.startswith("thermal_zone"))
    except OSError:
        return None
    for z in zones:
        zpath = os.path.join(base, z)
        try:
            with open(os.path.join(zpath, "type"), "r") as f:
                ztype = f.read().strip()
            with open(os.path.join(zpath, "temp"), "r") as f:
                # Value is in millidegrees Celsius.
                temp_c = int(f.read().strip()) / 1000.0
        except (OSError, ValueError):
            continue
        candidates.setdefault(ztype, []).append(temp_c)
    for key in preferred:
        if key in candidates and candidates[key]:
            return round(candidates[key][0], 1)
    # Fallback: first available zone (matches "any sensor better than none").
    for zlist in candidates.values():
        if zlist:
            return round(zlist[0], 1)
    return None


def _collect_cpu() -> dict[str, Any]:
    """Collect CPU utilization and temperature."""
    try:
        pct = _cpu_percent(interval=0.1)
        temp = _cpu_temp()
        return {
            "cpu_percent": round(pct, 1) if pct is not None else None,
            "cpu_temp_c": temp,
        }
    except Exception as e:
        logger.debug("CPU metrics failed: %s", e)
        return {"cpu_percent": None, "cpu_temp_c": None}


# ---------------------------------------------------------------------------
# RAM — /proc/meminfo
# ---------------------------------------------------------------------------

def _read_meminfo() -> dict[str, int] | None:
    """Parse /proc/meminfo into a dict mapping field name -> bytes.

    /proc/meminfo reports values in kB (kibibytes); we multiply by 1024 to
    return raw bytes, matching psutil.virtual_memory()'s units.
    """
    info: dict[str, int] = {}
    try:
        with open("/proc/meminfo", "r") as f:
            for line in f:
                # Lines look like "MemTotal:       16384000 kB"
                if ":" not in line:
                    continue
                key, _, rest = line.partition(":")
                parts = rest.split()
                if not parts:
                    continue
                try:
                    val_kb = int(parts[0])
                except ValueError:
                    continue
                # Most numeric fields are in kB; some (HugePages_Total etc.)
                # are unit-less. Multiply by 1024 only when explicit kB suffix
                # is present.
                if len(parts) > 1 and parts[1].lower() == "kb":
                    info[key] = val_kb * 1024
                else:
                    info[key] = val_kb
    except OSError:
        return None
    return info


def _virtual_memory() -> dict[str, Any] | None:
    """Mimic psutil.virtual_memory() shape: total/available/used/free/percent.

    `available` follows the kernel's MemAvailable hint when present, falling
    back to MemFree+Buffers+Cached for older kernels. `percent` is the
    used-as-fraction-of-total figure psutil reports (computed off available).
    """
    info = _read_meminfo()
    if info is None:
        return None
    total = info.get("MemTotal")
    if not total:
        return None
    if "MemAvailable" in info:
        available = info["MemAvailable"]
    else:
        free = info.get("MemFree", 0)
        buffers = info.get("Buffers", 0)
        cached = info.get("Cached", 0)
        available = free + buffers + cached
    used = max(0, total - available)
    percent = 100.0 * used / total if total > 0 else 0.0
    return {
        "total": total,
        "available": available,
        "used": used,
        "free": info.get("MemFree", 0),
        "percent": round(percent, 1),
    }


def _collect_ram() -> dict[str, Any]:
    """Collect system RAM utilization."""
    try:
        vm = _virtual_memory()
        if vm is None:
            return {"ram_percent": None, "ram_used_mb": None, "ram_total_mb": None}
        return {
            "ram_percent": vm["percent"],
            "ram_used_mb": vm["used"] // (1024 * 1024),
            "ram_total_mb": vm["total"] // (1024 * 1024),
        }
    except Exception as e:
        logger.debug("RAM metrics failed: %s", e)
        return {"ram_percent": None, "ram_used_mb": None, "ram_total_mb": None}


# ---------------------------------------------------------------------------
# GPU — nvidia-smi subprocess
# ---------------------------------------------------------------------------

_NVSMI_QUERY = (
    "index,name,memory.total,memory.used,memory.free,utilization.gpu,temperature.gpu"
)


def _collect_gpus() -> list[dict[str, Any]]:
    """Collect NVIDIA GPU metrics via `nvidia-smi --query-gpu=...`.

    Returns an empty list when nvidia-smi is missing, the driver is absent,
    or the query times out — matching the previous pynvml behavior on a
    GPU-less host.
    """
    gpus: list[dict[str, Any]] = []
    try:
        proc = subprocess.run(
            [
                "nvidia-smi",
                f"--query-gpu={_NVSMI_QUERY}",
                "--format=csv,noheader,nounits",
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except FileNotFoundError:
        # No NVIDIA driver / nvidia-smi not on PATH — silent, same as the
        # previous `except ImportError: pass` branch on pynvml.
        return gpus
    except subprocess.TimeoutExpired:
        logger.debug("nvidia-smi timed out")
        return gpus
    except Exception as e:
        logger.debug("nvidia-smi exec failed: %s", e)
        return gpus

    if proc.returncode != 0:
        # Driver mismatch / no GPUs — return empty, do not raise.
        if proc.stderr:
            logger.debug("nvidia-smi exit %d: %s", proc.returncode, proc.stderr.strip()[:200])
        return gpus

    # CSV with one row per GPU. Fields are MiB / % / °C respectively (nounits
    # strips the suffixes). Empty / "[Not Supported]" cells become None.
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 7:
            continue

        def _to_int(s: str) -> int | None:
            try:
                return int(s)
            except (ValueError, TypeError):
                return None

        idx = _to_int(parts[0])
        name = parts[1]
        mem_total = _to_int(parts[2])
        mem_used = _to_int(parts[3])
        # mem_free = _to_int(parts[4])  # noqa: not surfaced by previous code
        util_gpu = _to_int(parts[5])
        temp_c = _to_int(parts[6])

        gpus.append({
            "id": idx if idx is not None else 0,
            "name": name,
            "load_percent": float(util_gpu) if util_gpu is not None else None,
            "memory_used_mb": mem_used if mem_used is not None else None,
            "memory_total_mb": mem_total if mem_total is not None else None,
            "temp_c": temp_c,
        })
    return gpus


# ---------------------------------------------------------------------------
# Host-bridge fallback (macOS-in-Docker)
# ---------------------------------------------------------------------------

def _get_host_metrics_url() -> str | None:
    """
    Resolve the host-bridge URL once. Order of precedence:
      1. BEIGEBOX_HOST_METRICS_URL env var
      2. config.yaml -> metrics.host_metrics_url
    Returns None if neither is set, or after we've tripped the failure threshold.
    """
    global _host_metrics_url, _host_metrics_resolved
    if _host_metrics_failures >= _HOST_METRICS_FAIL_THRESHOLD:
        return None
    if _host_metrics_resolved:
        return _host_metrics_url
    url = os.environ.get("BEIGEBOX_HOST_METRICS_URL", "").strip()
    if not url:
        try:
            from beigebox.config import get_config
            cfg = get_config()
            url = (cfg.get("metrics", {}) or {}).get("host_metrics_url", "").strip()
        except Exception:
            url = ""
    if url:
        # urllib.request.urlopen accepts file:// by default — refuse anything
        # other than http/https, plus reject embedded creds. Private IPs are
        # permitted (the host bridge legitimately runs on the LAN/loopback).
        from beigebox.security.safe_url import SsrfRefusedError, validate_backend_url
        try:
            url = validate_backend_url(url)
        except SsrfRefusedError as e:
            logger.error("metrics: rejecting host_metrics_url %r: %s", url, e)
            url = ""
    _host_metrics_url = url or None
    _host_metrics_resolved = True
    if _host_metrics_url:
        logger.info("metrics: using host bridge at %s", _host_metrics_url)
    return _host_metrics_url


def _collect_via_host_bridge(url: str) -> dict[str, Any] | None:
    """Fetch real host stats from the host-side metrics helper. Returns None on any failure."""
    global _host_metrics_failures
    try:
        with urllib.request.urlopen(url, timeout=4.0) as resp:
            import json
            data = json.loads(resp.read().decode("utf-8"))
            _host_metrics_failures = 0
            # Normalize: ensure all expected keys exist so the UI never sees None where it expects a number.
            data.setdefault("cpu_percent", None)
            data.setdefault("cpu_temp_c", None)
            data.setdefault("ram_percent", None)
            data.setdefault("ram_used_mb", None)
            data.setdefault("ram_total_mb", None)
            data.setdefault("gpus", [])
            data["timestamp"] = datetime.now(timezone.utc).isoformat()
            return data
    except Exception as e:
        _host_metrics_failures += 1
        logger.debug("host metrics bridge fetch failed (attempt %d): %s",
                     _host_metrics_failures, e)
        if _host_metrics_failures >= _HOST_METRICS_FAIL_THRESHOLD:
            logger.warning("host metrics bridge unreachable after %d attempts; falling back to in-container reads",
                           _HOST_METRICS_FAIL_THRESHOLD)
        return None


def collect_system_metrics() -> dict[str, Any]:
    """
    Collect all system metrics synchronously.
    Cached for _CACHE_TTL seconds to avoid repeated expensive calls.

    On macOS-in-Docker, prefers a host-side bridge (see module docstring) since
    in-container reads of /proc/* only see the Linux VM, not the real Mac.
    """
    global _cache, _cache_ts
    now = time.monotonic()
    if _cache and (now - _cache_ts) < _CACHE_TTL:
        return _cache

    bridge_url = _get_host_metrics_url()
    if bridge_url:
        bridged = _collect_via_host_bridge(bridge_url)
        if bridged is not None:
            _cache = bridged
            _cache_ts = now
            return bridged
        # bridge failure — fall through to in-container reads

    result = {
        **_collect_cpu(),
        **_collect_ram(),
        "gpus": _collect_gpus(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "in-container /proc",
    }
    _cache = result
    _cache_ts = now
    return result


async def collect_system_metrics_async() -> dict[str, Any]:
    """
    Run collect_system_metrics() in a thread pool to avoid blocking the event loop.
    The CPU collector does a 100ms blocking sleep between /proc/stat snapshots.
    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, collect_system_metrics)
