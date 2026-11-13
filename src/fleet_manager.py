"""
src/fleet_manager.py — NetGuard IDS v4.0
Distributed Edge Fleet Orchestrator
Centralized command & control hub for 100+ remote edge sensor probes.
Manages probe registration, automated heartbeats, firmware telemetry,
and dynamic policy/rule synchronization.
"""

import time
import threading
from typing import Dict, List, Optional, Any
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


class FleetManager:
    """
    Centralized controller for distributed NetGuard edge sensor fleet.
    Tracks probe health, bandwidth, and synchronizes detection policies.
    """
    def __init__(self, offline_threshold_sec: float = 60.0):
        self.offline_threshold_sec = offline_threshold_sec
        self._probes: Dict[str, Dict[str, Any]] = {}
        self._tenant_rules: Dict[str, List[Dict[str, Any]]] = {}
        self._lock = threading.Lock()

    def register_probe(
        self,
        probe_id: str,
        hostname: str,
        tenant_id: str = "default",
        ip_address: str = "unknown",
        version: str = "3.5.0-edge",
        interface: str = "eth0"
    ) -> Dict[str, Any]:
        """Register or re-authenticate an edge sensor probe."""
        now = time.time()
        with self._lock:
            self._probes[probe_id] = {
                "probe_id": probe_id,
                "hostname": hostname,
                "tenant_id": tenant_id,
                "ip_address": ip_address,
                "version": version,
                "interface": interface,
                "registered_at": now,
                "last_heartbeat": now,
                "status": "online",
                "packets_seen": 0,
                "flows_streamed": 0,
                "active_rules_version": 1
            }
            return {
                "success": True,
                "probe_id": probe_id,
                "status": "registered",
                "message": f"Edge probe '{hostname}' successfully connected to central hub."
            }

    def record_heartbeat(
        self,
        probe_id: str,
        packets_seen: int = 0,
        flows_streamed: int = 0,
        cpu_usage_pct: float = 0.0,
        ram_usage_mb: float = 0.0
    ) -> Dict[str, Any]:
        """Record telemetry heartbeat from a probe and return updated detection policies."""
        now = time.time()
        with self._lock:
            if probe_id not in self._probes:
                # Auto-register ad-hoc probe
                self._probes[probe_id] = {
                    "probe_id": probe_id,
                    "hostname": probe_id,
                    "tenant_id": "default",
                    "ip_address": "unknown",
                    "version": "3.5.0-edge",
                    "registered_at": now,
                    "last_heartbeat": now,
                    "status": "online",
                    "packets_seen": packets_seen,
                    "flows_streamed": flows_streamed
                }

            probe = self._probes[probe_id]
            probe["last_heartbeat"] = now
            probe["status"] = "online"
            probe["packets_seen"] += packets_seen
            probe["flows_streamed"] += flows_streamed
            probe["telemetry"] = {
                "cpu_pct": cpu_usage_pct,
                "ram_mb": ram_usage_mb,
                "last_seen_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
            }

            tenant = probe.get("tenant_id", "default")
            active_rules = self._tenant_rules.get(tenant, [])

            return {
                "success": True,
                "status": "healthy",
                "sync_rules": active_rules,
                "rule_count": len(active_rules),
                "server_time": now
            }

    def push_tenant_rule(self, tenant_id: str, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Push a dynamic detection policy to all probes in an organization."""
        with self._lock:
            if tenant_id not in self._tenant_rules:
                self._tenant_rules[tenant_id] = []
            rule["id"] = f"RULE-{len(self._tenant_rules[tenant_id]) + 1:03d}"
            rule["created_at"] = time.time()
            self._tenant_rules[tenant_id].append(rule)
            return {
                "success": True,
                "rule_id": rule["id"],
                "tenant_id": tenant_id,
                "total_rules": len(self._tenant_rules[tenant_id])
            }

    def get_fleet_overview(self, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        """Return comprehensive status and health across all registered probes."""
        now = time.time()
        with self._lock:
            probes_list = []
            online_count = 0
            total_packets = 0
            total_flows = 0

            for pid, p in self._probes.items():
                if tenant_id and p.get("tenant_id") != tenant_id:
                    continue

                # Compute online/offline state
                time_since = now - p["last_heartbeat"]
                is_online = time_since <= self.offline_threshold_sec
                p["status"] = "online" if is_online else "offline"
                if is_online:
                    online_count += 1

                total_packets += p.get("packets_seen", 0)
                total_flows += p.get("flows_streamed", 0)
                probes_list.append(p)

            return {
                "total_probes": len(probes_list),
                "online_probes": online_count,
                "offline_probes": len(probes_list) - online_count,
                "fleet_total_packets": total_packets,
                "fleet_total_flows": total_flows,
                "probes": probes_list
            }


# Global Singleton Fleet Manager
fleet_manager = FleetManager()
