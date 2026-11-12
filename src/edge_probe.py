"""
src/edge_probe.py — NetGuard IDS v3.5
Lightweight Edge Sensor Probe Daemon
Collects, aggregates, and streams 5-tuple flow records from remote IoT gateways
and edge sensors to the centralized NetGuard cluster.
"""

import os
import sys
import time
import json
import socket
import hmac
import hashlib
import requests
import threading
from typing import Dict, List, Optional, Any
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / "src"))

try:
    from config import AGENT_SECRET_KEY, API_URL
except ImportError:
    AGENT_SECRET_KEY = "netguard-agent-secret-key-default"
    API_URL = "http://127.0.0.1:8081"


class EdgeProbe:
    """
    Lightweight packet collector daemon running on edge nodes.
    Maintains a compact flow cache and dispatches compressed telemetry
    batches to the central NetGuard hub.
    """
    def __init__(
        self,
        hub_url: str = API_URL,
        tenant_id: str = "default",
        agent_key: str = AGENT_SECRET_KEY,
        batch_size: int = 20,
        flush_interval: float = 1.0,
        interface: str = "eth0"
    ):
        self.hub_url = hub_url.rstrip("/")
        self.tenant_id = tenant_id
        self.agent_key = agent_key
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.interface = interface

        self._flow_cache: Dict[tuple, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self.running = False
        self.total_packets_seen = 0
        self.total_flows_streamed = 0
        self._worker_thread: Optional[threading.Thread] = None

    def record_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: int,
        length: int,
        tcp_flags: int = 0
    ):
        """Aggregate a single packet into active 5-tuple micro-flows."""
        now = time.time()
        key = (src_ip, dst_ip, src_port, dst_port, protocol)
        with self._lock:
            self.total_packets_seen += 1
            if key not in self._flow_cache:
                self._flow_cache[key] = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "pkts_fwd": 1,
                    "bytes_fwd": length,
                    "start_time": now,
                    "last_time": now,
                    "tcp_flags": tcp_flags
                }
            else:
                f = self._flow_cache[key]
                f["pkts_fwd"] += 1
                f["bytes_fwd"] += length
                f["last_time"] = now
                f["tcp_flags"] |= tcp_flags

    def extract_ready_flows(self, timeout: float = 1.5) -> List[Dict[str, Any]]:
        """Extract completed or timed-out flows from local cache."""
        now = time.time()
        ready = []
        with self._lock:
            to_delete = []
            for k, f in self._flow_cache.items():
                if (now - f["last_time"] >= timeout) or (f["pkts_fwd"] >= 50):
                    ready.append({
                        "Dst Port": f["dst_port"],
                        "Protocol": f["protocol"],
                        "Flow Duration": max(1, int((f["last_time"] - f["start_time"]) * 1e6)),
                        "Tot Fwd Pkts": f["pkts_fwd"],
                        "Tot Bwd Pkts": 0,
                        "TotLen Fwd Pkts": f["bytes_fwd"],
                        "TotLen Bwd Pkts": 0,
                        "src_ip": f["src_ip"],
                        "dst_ip": f["dst_ip"],
                        "tenant_id": self.tenant_id
                    })
                    to_delete.append(k)
                    if len(ready) >= self.batch_size:
                        break
            for k in to_delete:
                del self._flow_cache[k]
        return ready

    def dispatch_batch(self, flows: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Stream a batch of flow records to central NetGuard endpoint."""
        if not flows:
            return {"success": True, "count": 0}

        endpoint = f"{self.hub_url}/sensor/stream"
        headers = {
            "Content-Type": "application/json",
            "X-Agent-Secret": self.agent_key,
            "X-Tenant-ID": self.tenant_id
        }
        payload = {
            "tenant_id": self.tenant_id,
            "interface": self.interface,
            "flows": flows
        }

        try:
            r = requests.post(endpoint, json=payload, headers=headers, timeout=5)
            if r.status_code == 200:
                self.total_flows_streamed += len(flows)
                return r.json()
            else:
                return {"success": False, "status_code": r.status_code, "error": r.text}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def start(self):
        """Start background flow flush daemon."""
        self.running = True
        def loop():
            while self.running:
                time.sleep(self.flush_interval)
                flows = self.extract_ready_flows()
                if flows:
                    self.dispatch_batch(flows)
        self._worker_thread = threading.Thread(target=loop, daemon=True)
        self._worker_thread.start()

    def stop(self):
        """Stop background worker and flush remaining records."""
        self.running = False
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)
        remaining = self.extract_ready_flows(timeout=0.0)
        if remaining:
            self.dispatch_batch(remaining)


# Global default instance
edge_probe = EdgeProbe()
