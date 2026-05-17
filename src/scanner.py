# =============================================================
# scanner.py — NetGuard IDS v2.1
# Network Device Scanner: ARP (fast) + Nmap (detailed)
# =============================================================

import subprocess
import platform
import threading
import socket
import re
from datetime import datetime
from typing import Optional

try:
    import nmap
    NMAP_OK = True
except ImportError:
    NMAP_OK = False
    print("[scanner] python-nmap not installed — nmap scan disabled")

try:
    from scapy.all import ARP, Ether, srp
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False
    print("[scanner] scapy not installed — ARP scan disabled")

# ── Cache ──────────────────────────────────────────────────────
_cache: dict = {"devices": [], "timestamp": None}
_lock = threading.Lock()


# ── Get local subnet ───────────────────────────────────────────
def _get_local_subnet() -> str:
    """Detect local subnet automatically."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        parts = ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except Exception:
        return "192.168.1.0/24"


def _get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "unknown"


# ── MAC vendor lookup ──────────────────────────────────────────
def _get_vendor(mac: str) -> str:
    """Basic MAC vendor lookup using nmap's MAC DB."""
    vendors = {
        "00:50:56": "VMware",
        "00:0c:29": "VMware",
        "00:1a:a0": "Dell",
        "00:1b:21": "Intel",
        "00:23:14": "Intel",
        "3c:5a:b4": "Google",
        "f4:f5:d8": "Google",
        "b8:27:eb": "Raspberry Pi",
        "dc:a6:32": "Raspberry Pi",
        "00:17:88": "Philips Hue",
        "ac:87:a3": "Apple",
        "f8:ff:c2": "Apple",
        "3c:22:fb": "Apple",
        "00:16:3e": "Xen",
        "08:00:27": "VirtualBox",
        "52:54:00": "QEMU/KVM",
    }
    prefix = mac[:8].lower()
    for k, v in vendors.items():
        if prefix == k.lower():
            return v
    return "Unknown"


# ── ARP Scan ───────────────────────────────────────────────────
def arp_scan(subnet: Optional[str] = None) -> list[dict]:
    """Fast ARP scan — discovers devices on local subnet."""
    if not SCAPY_OK:
        return _arp_fallback(subnet)

    target = subnet or _get_local_subnet()
    devices = []

    try:
        arp_request = ARP(pdst=target)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request
        answered, _ = srp(packet, timeout=3, verbose=False)

        local_ip = _get_local_ip()

        for sent, received in answered:
            ip = received.psrc
            mac = received.hwsrc
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = "unknown"

            devices.append({
                "ip":       ip,
                "mac":      mac.upper(),
                "hostname": hostname,
                "vendor":   _get_vendor(mac),
                "status":   "online",
                "is_gateway": ip.endswith(".1"),
                "is_self":  ip == local_ip,
                "open_ports": [],
                "os":       "unknown",
                "scan_type": "arp",
            })

    except Exception as e:
        print(f"[scanner] ARP scan error: {e}")
        return _arp_fallback(subnet)

    return sorted(devices, key=lambda x: [int(i) for i in x["ip"].split(".")])


def _arp_fallback(subnet: Optional[str] = None) -> list[dict]:
    """Fallback ARP using arp -a command."""
    devices = []
    try:
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True, text=True, timeout=10
        )
        local_ip = _get_local_ip()
        pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+([\w\-:]+)\s+(\w+)")

        for line in result.stdout.splitlines():
            match = pattern.search(line)
            if match:
                ip  = match.group(1)
                mac = match.group(2).replace("-", ":").upper()
                typ = match.group(3)

                if typ.lower() == "static" and ip.endswith(".255"):
                    continue
                if mac in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
                    continue

                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except Exception:
                    hostname = "unknown"

                devices.append({
                    "ip":       ip,
                    "mac":      mac,
                    "hostname": hostname,
                    "vendor":   _get_vendor(mac),
                    "status":   "online",
                    "is_gateway": ip.endswith(".1"),
                    "is_self":  ip == local_ip,
                    "open_ports": [],
                    "os":       "unknown",
                    "scan_type": "arp-fallback",
                })
    except Exception as e:
        print(f"[scanner] ARP fallback error: {e}")

    return devices


# ── Nmap Scan ──────────────────────────────────────────────────
def nmap_scan(subnet: Optional[str] = None, fast: bool = True) -> list[dict]:
    """Detailed Nmap scan with OS detection and open ports."""
    if not NMAP_OK:
        print("[scanner] python-nmap not available")
        return arp_scan(subnet)

    target = subnet or _get_local_subnet()
    devices = []
    local_ip = _get_local_ip()

    try:
        nm = nmap.PortScanner()

        # Fast scan: ping + common ports
        # Full scan: OS detection (requires admin)
        args = "-sn" if fast else "-O --osscan-guess -T4"
        nm.scan(hosts=target, arguments=args)

        for host in nm.all_hosts():
            info = nm[host]
            status = info.state()

            if status != "up":
                continue

            mac = ""
            vendor = "Unknown"
            if "mac" in info.get("addresses", {}):
                mac = info["addresses"]["mac"].upper()
                vendor = info.get("vendor", {}).get(mac, _get_vendor(mac))

            hostname = "unknown"
            hostnames = info.get("hostnames", [])
            if hostnames and hostnames[0].get("name"):
                hostname = hostnames[0]["name"]
            else:
                try:
                    hostname = socket.gethostbyaddr(host)[0]
                except Exception:
                    pass

            # OS detection
            os_name = "unknown"
            if not fast:
                osmatch = info.get("osmatch", [])
                if osmatch:
                    os_name = osmatch[0].get("name", "unknown")

            # Open ports
            open_ports = []
            for proto in info.all_protocols():
                ports = info[proto].keys()
                for port in ports:
                    port_info = info[proto][port]
                    if port_info["state"] == "open":
                        open_ports.append({
                            "port":    port,
                            "proto":   proto,
                            "service": port_info.get("name", "unknown"),
                        })

            devices.append({
                "ip":         host,
                "mac":        mac,
                "hostname":   hostname,
                "vendor":     vendor,
                "status":     status,
                "is_gateway": host.endswith(".1"),
                "is_self":    host == local_ip,
                "open_ports": open_ports,
                "os":         os_name,
                "scan_type":  "nmap",
            })

    except Exception as e:
        print(f"[scanner] Nmap scan error: {e}")
        return arp_scan(subnet)

    return sorted(devices, key=lambda x: [int(i) for i in x["ip"].split(".")])


# ── Combined Scan ──────────────────────────────────────────────
def full_scan(subnet: Optional[str] = None) -> dict:
    """Run ARP first (fast), then enrich with Nmap."""
    start = datetime.now()

    # ARP — fast discovery
    arp_devices = arp_scan(subnet)
    arp_map = {d["ip"]: d for d in arp_devices}

    # Nmap — enrich with port/OS info
    if NMAP_OK:
        nmap_devices = nmap_scan(subnet, fast=True)
        for nd in nmap_devices:
            ip = nd["ip"]
            if ip in arp_map:
                # Merge — ARP has MAC, Nmap has ports/OS
                arp_map[ip]["open_ports"] = nd["open_ports"]
                arp_map[ip]["os"] = nd["os"]
                if nd["mac"] and not arp_map[ip]["mac"]:
                    arp_map[ip]["mac"] = nd["mac"]
                arp_map[ip]["scan_type"] = "arp+nmap"
            else:
                arp_map[ip] = nd

    devices = sorted(arp_map.values(), key=lambda x: [int(i) for i in x["ip"].split(".")])
    elapsed = (datetime.now() - start).total_seconds()

    result = {
        "subnet":      subnet or _get_local_subnet(),
        "total":       len(devices),
        "online":      sum(1 for d in devices if d["status"] == "online"),
        "scan_time_s": round(elapsed, 2),
        "timestamp":   datetime.now().isoformat(timespec="seconds"),
        "devices":     devices,
    }

    # Update cache
    with _lock:
        _cache["devices"]   = devices
        _cache["timestamp"] = result["timestamp"]

    return result


def get_cached() -> dict:
    """Return cached scan result."""
    with _lock:
        return {
            "devices":   _cache["devices"],
            "timestamp": _cache["timestamp"],
            "total":     len(_cache["devices"]),
            "cached":    True,
        }
