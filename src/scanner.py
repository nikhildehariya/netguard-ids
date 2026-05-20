# =============================================================
# scanner.py — NetGuard IDS v2.1
# Network Device Scanner: ARP (fast) + Nmap (detailed)
# =============================================================

import subprocess
import platform
import threading
import socket
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
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


def _sort_devices(devices: list[dict]) -> list[dict]:
    return sorted(devices, key=lambda x: [int(i) for i in x["ip"].split(".")])


def _merge_devices(*groups: list[dict]) -> list[dict]:
    """Merge device lists, preferring actively confirmed online results."""
    rank = {"seen_recently": 0, "online": 1, "up": 1}
    merged: dict[str, dict] = {}
    for devices in groups:
        for device in devices:
            ip = device["ip"]
            current = merged.get(ip)
            if current is None or rank.get(device.get("status"), 0) >= rank.get(current.get("status"), 0):
                merged[ip] = {**current, **device} if current else device
            elif not current.get("mac") and device.get("mac"):
                current["mac"] = device["mac"]
                current["vendor"] = device.get("vendor", current.get("vendor", "Unknown"))
    return _sort_devices(list(merged.values()))


def update_cache(devices: list[dict], timestamp: Optional[str] = None) -> None:
    """Store the latest device scan for /network/devices."""
    with _lock:
        _cache["devices"] = devices
        _cache["timestamp"] = timestamp or datetime.now().isoformat(timespec="seconds")


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


def _get_default_gateway() -> str:
    """Return the IPv4 default gateway for the active route."""
    try:
        if platform.system().lower() == "windows":
            result = subprocess.run(
                ["route", "print", "-4"],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                    return parts[2]
        else:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=10
            )
            parts = result.stdout.split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
    except Exception:
        pass
    return ""


def _get_local_mac() -> str:
    """Find the MAC address for the adapter that owns the active IPv4 address."""
    local_ip = _get_local_ip()
    if local_ip == "unknown":
        return ""
    try:
        if platform.system().lower() == "windows":
            result = subprocess.run(
                ["ipconfig", "/all"],
                capture_output=True, text=True, timeout=10
            )
            current_mac = ""
            for line in result.stdout.splitlines():
                if "Physical Address" in line:
                    current_mac = line.split(":", 1)[1].strip().replace("-", ":").upper()
                if "IPv4 Address" in line and local_ip in line:
                    return current_mac
        else:
            result = subprocess.run(
                ["ip", "-o", "addr", "show"],
                capture_output=True, text=True, timeout=10
            )
            iface = ""
            for line in result.stdout.splitlines():
                if local_ip in line:
                    parts = line.split()
                    iface = parts[1] if len(parts) > 1 else ""
                    break
            if iface:
                result = subprocess.run(
                    ["cat", f"/sys/class/net/{iface}/address"],
                    capture_output=True, text=True, timeout=5
                )
                return result.stdout.strip().upper()
    except Exception:
        pass
    return ""


def _is_gateway(ip: str) -> bool:
    gateway = _get_default_gateway()
    return ip == gateway or (not gateway and ip.endswith(".1"))


def _device_type(ip: str, is_self: bool = False, vendor: str = "") -> str:
    if is_self:
        return "this_device"
    if _is_gateway(ip):
        return "gateway"
    vendor_lower = vendor.lower()
    if any(name in vendor_lower for name in ("apple", "samsung", "xiaomi", "oppo", "vivo", "oneplus")):
        return "phone"
    if any(name in vendor_lower for name in ("intel", "dell", "vmware", "virtualbox", "qemu")):
        return "computer"
    return "unknown"


def _get_subnet_base(subnet: Optional[str] = None) -> str:
    """Extract base IP from subnet string like 10.233.135.0/24."""
    target = subnet or _get_local_subnet()
    return target.split("/")[0].rsplit(".", 1)[0]  # e.g. "10.233.135"


# ── Ping Sweep ─────────────────────────────────────────────────
def _ping_one(ip: str) -> None:
    """Ping a single IP (fire-and-forget, just to populate ARP table)."""
    try:
        if platform.system().lower() == "windows":
            subprocess.run(
                ["ping", "-n", "1", "-w", "300", ip],
                capture_output=True, timeout=2
            )
        else:
            subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                capture_output=True, timeout=2
            )
    except Exception:
        pass


def ping_sweep(subnet: Optional[str] = None, max_workers: int = 100) -> None:
    """
    Blast pings across entire subnet in parallel.
    This populates the OS ARP table so subsequent ARP scan finds all devices.
    Takes ~3-5 seconds for /24 subnet.
    """
    base = _get_subnet_base(subnet)
    ips = [f"{base}.{i}" for i in range(1, 255)]

    print(f"[scanner] Ping sweep started — {len(ips)} IPs on {base}.0/24")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_ping_one, ip): ip for ip in ips}
        for _ in as_completed(futures):
            pass  # just wait for all to finish
    print(f"[scanner] Ping sweep done")


# ── MAC vendor lookup ──────────────────────────────────────────
def _get_vendor(mac: str) -> str:
    """Basic MAC vendor lookup."""
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
def arp_scan(subnet: Optional[str] = None, do_ping_sweep: bool = True) -> list[dict]:
    """
    Fast ARP scan — discovers devices on local subnet.
    do_ping_sweep=True: pings all IPs first so ARP table is fully populated.
    """
    # Always ping sweep first so all active devices appear in ARP table
    if do_ping_sweep:
        ping_sweep(subnet)

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
        local_mac = _get_local_mac()

        for sent, received in answered:
            ip = received.psrc
            mac = received.hwsrc
            if ip == local_ip and local_mac:
                mac = local_mac
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = "unknown"

            devices.append({
                "ip":         ip,
                "mac":        mac.upper(),
                "hostname":   hostname,
                "vendor":     _get_vendor(mac),
                "status":     "online",
                "is_gateway": _is_gateway(ip),
                "is_self":    ip == local_ip,
                "device_type": _device_type(ip, ip == local_ip, _get_vendor(mac)),
                "open_ports": [],
                "os":         "unknown",
                "scan_type":  "arp",
            })

    except Exception as e:
        print(f"[scanner] ARP scan error: {e}")
        return _arp_fallback(subnet)

    # On Windows services Scapy can send successfully but receive zero replies
    # on the selected adapter. ARP cache entries are not proof of current
    # connectivity, so fallback-only devices are marked seen_recently.
    fallback_devices = _arp_fallback(subnet)
    return _merge_devices(fallback_devices, devices)


def _arp_fallback(subnet: Optional[str] = None) -> list[dict]:
    """Fallback ARP using arp -a command (used when Scapy unavailable)."""
    devices = []
    seen = set()
    base = _get_subnet_base(subnet)
    try:
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True, text=True, timeout=10
        )
        local_ip = _get_local_ip()
        local_mac = _get_local_mac()
        pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+([\w\-:]+)\s+(\w+)")

        for line in result.stdout.splitlines():
            match = pattern.search(line)
            if match:
                ip  = match.group(1)
                mac = match.group(2).replace("-", ":").upper()
                typ = match.group(3)

                if not ip.startswith(base + "."):
                    continue
                if ip in seen:
                    continue
                if typ.lower() == "static" and ip.endswith(".255"):
                    continue
                if mac in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
                    continue

                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except Exception:
                    hostname = "unknown"

                is_self = ip == local_ip
                if is_self and local_mac:
                    mac = local_mac
                vendor = _get_vendor(mac)
                devices.append({
                    "ip":         ip,
                    "mac":        mac,
                    "hostname":   hostname,
                    "vendor":     vendor,
                    "status":     "online" if is_self else "seen_recently",
                    "is_gateway": _is_gateway(ip),
                    "is_self":    is_self,
                    "device_type": _device_type(ip, is_self, vendor),
                    "open_ports": [],
                    "os":         "unknown",
                    "scan_type":  "arp-cache",
                })
                seen.add(ip)
    except Exception as e:
        print(f"[scanner] ARP fallback error: {e}")

    return _sort_devices(devices)


# ── Nmap Scan ──────────────────────────────────────────────────
def nmap_discovery_scan(subnet: Optional[str] = None) -> list[dict]:
    """Active host discovery. Devices returned here are confirmed online."""
    if not NMAP_OK:
        return []

    target = subnet or _get_local_subnet()
    devices = []
    local_ip = _get_local_ip()
    local_mac = _get_local_mac()

    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments="-sn -PR")

        for host in nm.all_hosts():
            info = nm[host]
            if info.state() != "up":
                continue

            mac = info.get("addresses", {}).get("mac", "").upper()
            if host == local_ip and local_mac:
                mac = local_mac
            vendor = info.get("vendor", {}).get(mac, _get_vendor(mac)) if mac else "Unknown"
            hostname = "unknown"
            hostnames = info.get("hostnames", [])
            if hostnames and hostnames[0].get("name"):
                hostname = hostnames[0]["name"]
            else:
                try:
                    hostname = socket.gethostbyaddr(host)[0]
                except Exception:
                    pass

            devices.append({
                "ip":         host,
                "mac":        mac,
                "hostname":   hostname,
                "vendor":     vendor,
                "status":     "online",
                "is_gateway": _is_gateway(host),
                "is_self":    host == local_ip,
                "device_type": _device_type(host, host == local_ip, vendor),
                "open_ports": [],
                "os":         "unknown",
                "scan_type":  "nmap-discovery",
            })
    except Exception as e:
        print(f"[scanner] Nmap discovery error: {e}")

    return _sort_devices(devices)


def nmap_scan(subnet: Optional[str] = None, fast: bool = True) -> list[dict]:
    """Detailed Nmap scan with OS detection and open ports."""
    if not NMAP_OK:
        print("[scanner] python-nmap not available")
        return arp_scan(subnet)

    target = subnet or _get_local_subnet()
    devices = []
    local_ip = _get_local_ip()
    local_mac = _get_local_mac()

    try:
        nm = nmap.PortScanner()

        # Fast scan: discover hosts and common open ports.
        # Full scan: add OS guessing, which may require elevated Npcap access.
        args = "-T4 -F --open" if fast else "-O --osscan-guess -T4 -F --open"
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
            if host == local_ip and local_mac:
                mac = local_mac
                vendor = _get_vendor(mac)

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
                "is_gateway": _is_gateway(host),
                "is_self":    host == local_ip,
                "device_type": _device_type(host, host == local_ip, vendor),
                "open_ports": open_ports,
                "os":         os_name,
                "scan_type":  "nmap",
            })

    except Exception as e:
        print(f"[scanner] Nmap scan error: {e}")
        return arp_scan(subnet)

    return _sort_devices(devices)


# ── Combined Scan ──────────────────────────────────────────────
def full_scan(subnet: Optional[str] = None) -> dict:
    """
    Full scan pipeline:
    1. Ping sweep — populates OS ARP table with all active devices
    2. ARP scan  — fast MAC/IP discovery (skip_ping=True, already done)
    3. Nmap      — enriches with open ports & OS info
    """
    start = datetime.now()

    # Step 1+2: Ping sweep then ARP (do_ping_sweep=True inside arp_scan)
    arp_devices = arp_scan(subnet, do_ping_sweep=True)
    arp_map = {d["ip"]: d for d in arp_devices}

    # Nmap host discovery gives active confirmation when Scapy is limited by
    # Windows service adapter selection.
    if NMAP_OK:
        for device in nmap_discovery_scan(subnet):
            arp_map[device["ip"]] = {**arp_map.get(device["ip"], {}), **device}

    # Step 3: Nmap — enrich with port/OS info (no extra ping sweep needed)
    if NMAP_OK:
        nmap_devices = nmap_scan(subnet, fast=True)
        for nd in nmap_devices:
            ip = nd["ip"]
            if ip in arp_map:
                arp_map[ip]["open_ports"] = nd["open_ports"]
                arp_map[ip]["os"] = nd["os"]
                if nd["mac"] and not arp_map[ip]["mac"]:
                    arp_map[ip]["mac"] = nd["mac"]
                arp_map[ip]["scan_type"] = "arp+nmap"
            else:
                arp_map[ip] = nd

    devices = _sort_devices(list(arp_map.values()))
    elapsed = (datetime.now() - start).total_seconds()

    result = {
        "subnet":      subnet or _get_local_subnet(),
        "total":       len(devices),
        "online":      sum(1 for d in devices if d["status"] == "online"),
        "scan_time_s": round(elapsed, 2),
        "timestamp":   datetime.now().isoformat(timespec="seconds"),
        "devices":     devices,
    }

    update_cache(devices, result["timestamp"])

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
