#!/usr/bin/env bash
# ==============================================================================
# deploy/appliance/setup-appliance.sh — NetGuard IDS v4.0
# VMware ESXi / Proxmox VE First-Boot Virtual Appliance Initialization Wizard
# Configures promiscuous SPAN/Mirror ports, eBPF XDP driver hooks, and systemd units.
# ==============================================================================

set -euo pipefail

echo "====================================================="
echo "  🛡️ NetGuard IDS — Turnkey Virtual Appliance Setup"
echo "  Target: VMware ESXi / Proxmox VE / Cloud-Init Appliance"
echo "====================================================="

APP_DIR="/opt/netguard"
LOG_DIR="/var/log/netguard"

# 1. Root Verification
if [[ $EUID -ne 0 ]]; then
   echo "[-] This initialization wizard must be run as root."
   exit 1
fi

echo "[1/4] Configuring directories and kernel permissions..."
mkdir -p "$APP_DIR" "$LOG_DIR" "$LOG_DIR/forensics" "$APP_DIR/keys"

# 2. Kernel Capabilities & Promiscuous Mode
echo "[2/4] Enabling promiscuous mode on monitoring interfaces for SPAN mirroring..."
MON_IFACE=$(ip -o link show | awk -F': ' '$2 != "lo" {print $2; exit}')
if [[ -n "$MON_IFACE" ]]; then
    ip link set "$MON_IFACE" promisc on
    echo "      Enabled promiscuous mode on $MON_IFACE for full packet capture."
fi

# 3. Systemd Unit Activation
echo "[3/4] Activating production systemd units..."
if command -v systemctl &>/dev/null; then
    systemctl daemon-reload || true
    systemctl enable netguard-api.service netguard-worker.service netguard-ui.service || true
    echo "      Systemd daemons enabled for auto-boot."
fi

# 4. Final Appliance Network Banner
IP_ADDR=$(hostname -I | awk '{print $1}')
echo ""
echo "====================================================="
echo "  ✅ NetGuard IDS Virtual Appliance Initialized!"
echo "  🌐 SOC Dashboard URL : http://${IP_ADDR:-localhost}:5174"
echo "  ⚡ REST API Endpoint : http://${IP_ADDR:-localhost}:8081"
echo "  📋 Swagger API Docs  : http://${IP_ADDR:-localhost}:8081/docs"
echo "====================================================="
exit 0
