import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))

import argparse
import time
import threading
import requests
import numpy as np
from datetime import datetime
from collections import defaultdict

from config import API_URL

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False
    print("[capture] pip install scapy")

# ── Flow table ────────────────────────────────────────────────
flows = defaultdict(lambda: {
    "start":        None,
    "last":         None,
    "pkts_fwd":     0,
    "pkts_bwd":     0,
    "bytes_fwd":    [],
    "bytes_bwd":    [],
    "iats_fwd":     [],
    "iats_bwd":     [],
    "iats_all":     [],
    "flags":        defaultdict(int),
    "dst_port":     0,
    "protocol":     0,
    "src_ip":       "",
    "last_fwd":     None,
    "last_bwd":     None,
    "init_win_fwd": -1,
    "init_win_bwd": -1,
    "active":       [],
    "idle":         [],
    "last_active":  None,
})

capture_running = False
lock = threading.Lock()


def _stats(lst):
    if not lst:
        return {"mean": 0, "std": 0, "max": 0, "min": 0, "total": 0, "var": 0}
    a = np.array(lst, dtype=float)
    return {
        "mean":  float(np.mean(a)),
        "std":   float(np.std(a)),
        "max":   float(np.max(a)),
        "min":   float(np.min(a)),
        "total": float(np.sum(a)),
        "var":   float(np.var(a)),
    }


def flow_to_features(f, src_ip) -> dict:
    bf = _stats(f["bytes_fwd"])
    bb = _stats(f["bytes_bwd"])
    iaf = _stats(f["iats_fwd"])
    iab = _stats(f["iats_bwd"])
    iaa = _stats(f["iats_all"])
    act = _stats(f["active"])
    idl = _stats(f["idle"])

    duration = max((f["last"] - f["start"]) * 1e6, 1) if f["start"] and f["last"] else 1
    tot_pkts  = f["pkts_fwd"] + f["pkts_bwd"]
    tot_bytes = bf["total"] + bb["total"]

    all_bytes = f["bytes_fwd"] + f["bytes_bwd"]
    ab = _stats(all_bytes)

    return {
        "Dst Port":             f["dst_port"],
        "Protocol":             f["protocol"],
        "Flow Duration":        duration,
        "Tot Fwd Pkts":         f["pkts_fwd"],
        "Tot Bwd Pkts":         f["pkts_bwd"],
        "TotLen Fwd Pkts":      bf["total"],
        "TotLen Bwd Pkts":      bb["total"],
        "Fwd Pkt Len Max":      bf["max"],
        "Fwd Pkt Len Min":      bf["min"],
        "Fwd Pkt Len Mean":     bf["mean"],
        "Fwd Pkt Len Std":      bf["std"],
        "Bwd Pkt Len Max":      bb["max"],
        "Bwd Pkt Len Min":      bb["min"],
        "Bwd Pkt Len Mean":     bb["mean"],
        "Bwd Pkt Len Std":      bb["std"],
        "Flow Byts/s":          tot_bytes / (duration / 1e6),
        "Flow Pkts/s":          tot_pkts  / (duration / 1e6),
        "Flow IAT Mean":        iaa["mean"],
        "Flow IAT Std":         iaa["std"],
        "Flow IAT Max":         iaa["max"],
        "Flow IAT Min":         iaa["min"],
        "Fwd IAT Tot":          iaf["total"],
        "Fwd IAT Mean":         iaf["mean"],
        "Fwd IAT Std":          iaf["std"],
        "Fwd IAT Max":          iaf["max"],
        "Fwd IAT Min":          iaf["min"],
        "Bwd IAT Tot":          iab["total"],
        "Bwd IAT Mean":         iab["mean"],
        "Bwd IAT Std":          iab["std"],
        "Bwd IAT Max":          iab["max"],
        "Bwd IAT Min":          iab["min"],
        "Fwd PSH Flags":        f["flags"].get("PSH_fwd", 0),
        "Bwd PSH Flags":        f["flags"].get("PSH_bwd", 0),
        "Fwd URG Flags":        f["flags"].get("URG_fwd", 0),
        "Bwd URG Flags":        f["flags"].get("URG_bwd", 0),
        "Fwd Header Len":       f["pkts_fwd"] * 20,
        "Bwd Header Len":       f["pkts_bwd"] * 20,
        "Fwd Pkts/s":           f["pkts_fwd"] / (duration / 1e6),
        "Bwd Pkts/s":           f["pkts_bwd"] / (duration / 1e6),
        "Pkt Len Min":          ab["min"],
        "Pkt Len Max":          ab["max"],
        "Pkt Len Mean":         ab["mean"],
        "Pkt Len Std":          ab["std"],
        "Pkt Len Var":          ab["var"],
        "FIN Flag Cnt":         f["flags"].get("FIN", 0),
        "SYN Flag Cnt":         f["flags"].get("SYN", 0),
        "RST Flag Cnt":         f["flags"].get("RST", 0),
        "PSH Flag Cnt":         f["flags"].get("PSH", 0),
        "ACK Flag Cnt":         f["flags"].get("ACK", 0),
        "URG Flag Cnt":         f["flags"].get("URG", 0),
        "CWE Flag Count":       f["flags"].get("CWE", 0),
        "ECE Flag Cnt":         f["flags"].get("ECE", 0),
        "Down/Up Ratio":        bb["total"] / max(bf["total"], 1),
        "Pkt Size Avg":         ab["mean"],
        "Fwd Seg Size Avg":     bf["mean"],
        "Bwd Seg Size Avg":     bb["mean"],
        "Subflow Fwd Pkts":     f["pkts_fwd"],
        "Subflow Fwd Byts":     bf["total"],
        "Subflow Bwd Pkts":     f["pkts_bwd"],
        "Subflow Bwd Byts":     bb["total"],
        "Init Fwd Win Byts":    f["init_win_fwd"],
        "Init Bwd Win Byts":    f["init_win_bwd"],
        "Fwd Act Data Pkts":    f["pkts_fwd"],
        "Fwd Seg Size Min":     bf["min"],
        "Active Mean":          act["mean"],
        "Active Std":           act["std"],
        "Active Max":           act["max"],
        "Active Min":           act["min"],
        "Idle Mean":            idl["mean"],
        "Idle Std":             idl["std"],
        "Idle Max":             idl["max"],
        "Idle Min":             idl["min"],
        "source_ip":            src_ip or "unknown",  # FIX: guard against None
    }


def send_to_api(features: dict):
    try:
        resp = requests.post(
            f"{API_URL}/predict",
            json=features,
            timeout=2
        )
        result = resp.json()
        pred = result.get("prediction", "NORMAL")
        conf = result.get("confidence", 0) * 100
        sev  = result.get("severity", "none")
        src  = features.get("source_ip", "?")

        colors = {"none": "\033[92m", "high": "\033[93m", "critical": "\033[91m"}
        reset  = "\033[0m"
        c      = colors.get(sev, "")
        ts     = datetime.now().strftime("%H:%M:%S")

        print(f"{c}[{ts}] {pred:15s} ({conf:5.1f}%) | "
              f"src={src} | "
              f"port={int(features.get('Dst Port', 0))}{reset}")

    except requests.exceptions.ConnectionError:
        pass
    except Exception as e:
        print(f"[capture] API error: {e}")


def process_packet(pkt):
    global flows

    if not pkt.haslayer(IP):
        return

    ip   = pkt[IP]
    now  = time.time()
    size = len(pkt)

    # Flow key
    if pkt.haslayer(TCP):
        proto    = 6
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        proto    = 17
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
    else:
        proto    = 1
        src_port = 0
        dst_port = 0

    fwd_key = (ip.src, ip.dst, src_port, dst_port, proto)
    bwd_key = (ip.dst, ip.src, dst_port, src_port, proto)

    with lock:
        # Determine direction
        if fwd_key in flows:
            key       = fwd_key
            direction = "fwd"
        elif bwd_key in flows:
            key       = bwd_key
            direction = "bwd"
        else:
            key       = fwd_key
            direction = "fwd"
            flows[key]["start"]    = now
            flows[key]["src_ip"]   = ip.src
            flows[key]["dst_port"] = dst_port
            flows[key]["protocol"] = proto

        f = flows[key]

        # IAT
        if direction == "fwd":
            if f["last_fwd"]:
                f["iats_fwd"].append((now - f["last_fwd"]) * 1e6)
            f["last_fwd"] = now
            f["pkts_fwd"] += 1
            f["bytes_fwd"].append(size)
        else:
            if f["last_bwd"]:
                f["iats_bwd"].append((now - f["last_bwd"]) * 1e6)
            f["last_bwd"] = now
            f["pkts_bwd"] += 1
            f["bytes_bwd"].append(size)

        if f["last"]:
            f["iats_all"].append((now - f["last"]) * 1e6)
        f["last"] = now

        # TCP flags
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            flags_map = {
                "FIN": 0x01, "SYN": 0x02, "RST": 0x04,
                "PSH": 0x08, "ACK": 0x10, "URG": 0x20,
                "ECE": 0x40, "CWE": 0x80,
            }
            for flag, bit in flags_map.items():
                if tcp.flags & bit:
                    f["flags"][flag] += 1
                    if direction == "fwd":
                        f["flags"][f"{flag}_fwd"] = f["flags"].get(f"{flag}_fwd", 0) + 1
                    else:
                        f["flags"][f"{flag}_bwd"] = f["flags"].get(f"{flag}_bwd", 0) + 1

            # Init window
            if f["init_win_fwd"] == -1 and direction == "fwd":
                f["init_win_fwd"] = tcp.window
            if f["init_win_bwd"] == -1 and direction == "bwd":
                f["init_win_bwd"] = tcp.window

        # Send flow every 20 packets or on FIN/RST
        total_pkts  = f["pkts_fwd"] + f["pkts_bwd"]
        should_send = False

        if pkt.haslayer(TCP):
            if pkt[TCP].flags & 0x01 or pkt[TCP].flags & 0x04:  # FIN or RST
                should_send = True

        if total_pkts > 0 and total_pkts % 20 == 0:
            should_send = True

        if should_send and total_pkts >= 2:
            features = flow_to_features(f, f["src_ip"])
            threading.Thread(
                target=send_to_api,
                args=(features,),
                daemon=True
            ).start()


def flush_flows():
    """Send remaining flows every 30 seconds."""
    global flows
    while capture_running:
        time.sleep(30)
        now = time.time()
        with lock:
            to_flush = [
                k for k, f in flows.items()
                if f["last"] and (now - f["last"]) > 30
                and (f["pkts_fwd"] + f["pkts_bwd"]) >= 2
            ]
            for k in to_flush:
                f = flows[k]
                features = flow_to_features(f, f["src_ip"])
                threading.Thread(
                    target=send_to_api,
                    args=(features,),
                    daemon=True
                ).start()
                del flows[k]


def start_capture(interface: str):
    global capture_running
    capture_running = True

    print(f"\n[capture] Starting on: {interface}")
    print(f"[capture] API: {API_URL}/predict")
    print(f"[capture] Press Ctrl+C to stop.\n")

    # Start flush thread
    threading.Thread(target=flush_flows, daemon=True).start()

    try:
        sniff(
            iface=interface,
            prn=process_packet,
            store=False,
            filter="ip",
            stop_filter=lambda x: not capture_running
        )
    except KeyboardInterrupt:
        print("\n[capture] Stopped.")
        capture_running = False
    except Exception as e:
        print(f"[capture] Error: {e}")
        capture_running = False


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    args = parser.parse_args()
    start_capture(args.iface)