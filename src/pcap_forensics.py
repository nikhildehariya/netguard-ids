"""
pcap_forensics.py — NetGuard IDS v3.5
Automated Rolling PCAP Forensics Engine:
- In-memory circular buffer of raw packet captures (last 30-60 seconds)
- Automated dump to Wireshark-compatible .pcap upon critical / high threat triggers
- Retention policy & rotation preventing disk space exhaustion
- Forensic artifact registry for SOC investigation
"""

import os
import time
import threading
from collections import deque
from pathlib import Path
from typing import Optional, List, Dict, Any

try:
    from scapy.utils import wrpcap
    SCAPY_WRPCAP_OK = True
except ImportError:
    SCAPY_WRPCAP_OK = False

BASE_DIR = Path(__file__).resolve().parent.parent
FORENSICS_DIR = BASE_DIR / "reports" / "forensics"

# Rolling buffer configuration
BUFFER_MAX_PACKETS = 2500
BUFFER_MAX_AGE_SECONDS = 60.0
MAX_STORED_PCAPS = 50

_packet_buffer = deque(maxlen=BUFFER_MAX_PACKETS)
_buffer_lock = threading.Lock()


def record_raw_packet(pkt):
    """Store raw scapy packet with timestamp in circular memory buffer."""
    now = time.time()
    with _buffer_lock:
        _packet_buffer.append((now, pkt))


def _clean_stale_packets_locked():
    """Prune packets older than BUFFER_MAX_AGE_SECONDS."""
    now = time.time()
    cutoff = now - BUFFER_MAX_AGE_SECONDS
    while _packet_buffer and _packet_buffer[0][0] < cutoff:
        _packet_buffer.popleft()


def trigger_alert_pcap(source_ip: str, prediction: str, severity: str = "critical") -> Optional[str]:
    """
    Dumps the rolling packet buffer into an alert forensic .pcap file.
    Returns the absolute path of the created PCAP file, or None if empty.
    """
    if not SCAPY_WRPCAP_OK:
        return None

    FORENSICS_DIR.mkdir(parents=True, exist_ok=True)

    with _buffer_lock:
        _clean_stale_packets_locked()
        if not _packet_buffer:
            return None
        # Extract scapy packet objects in chronological order
        packets_to_save = [pkt for _, pkt in _packet_buffer]

    timestamp_str = time.strftime("%Y%m%d_%H%M%S")
    clean_ip = source_ip.replace(":", "_").replace(".", "_")
    clean_pred = prediction.replace(" ", "_").upper()

    filename = f"incident_{timestamp_str}_{clean_ip}_{clean_pred}.pcap"
    filepath = FORENSICS_DIR / filename

    try:
        wrpcap(str(filepath), packets_to_save)
        _prune_old_pcaps()
        return str(filepath)
    except Exception as e:
        print(f"[forensics] Failed to write PCAP dump: {e}")
        return None


def _prune_old_pcaps():
    """Enforces MAX_STORED_PCAPS retention limit."""
    try:
        if not FORENSICS_DIR.exists():
            return
        pcap_files = sorted(
            FORENSICS_DIR.glob("*.pcap"),
            key=lambda f: f.stat().st_mtime,
            reverse=True
        )
        for old_file in pcap_files[MAX_STORED_PCAPS:]:
            try:
                old_file.unlink()
            except Exception:
                pass
    except Exception:
        pass


def list_forensic_pcaps() -> List[Dict[str, Any]]:
    """List all available forensic PCAPs for SOC analysis and dashboard download."""
    if not FORENSICS_DIR.exists():
        return []

    results = []
    pcap_files = sorted(
        FORENSICS_DIR.glob("*.pcap"),
        key=lambda f: f.stat().st_mtime,
        reverse=True
    )
    for p in pcap_files:
        try:
            stat = p.stat()
            results.append({
                "filename": p.name,
                "size_bytes": stat.st_size,
                "size_formatted": f"{stat.st_size / 1024:.1f} KB",
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime)),
                "path": str(p),
            })
        except Exception:
            continue
    return results
