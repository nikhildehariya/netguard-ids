#!/usr/bin/env bash
# ==============================================================================
# NetGuard IDS — Automated Linux Edge Appliance Installer
# Tested on: Ubuntu 22.04 / 24.04 LTS & Raspberry Pi OS (Debian 12 ARM64)
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

INSTALL_DIR="/opt/netguard"
SERVICE_USER="netguard"

echo -e "${CYAN}======================================================${NC}"
echo -e "${CYAN}  🛡️  NetGuard IDS Linux Edge Appliance Installer       ${NC}"
echo -e "${CYAN}======================================================${NC}"

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR] Please run this installer as root (e.g. sudo bash install.sh)${NC}"
    exit 1
fi

echo -e "\n${YELLOW}[1/6] Installing Linux System Dependencies & Packet Capture Tools...${NC}"
apt-get update -y
apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    libpcap-dev \
    tcpdump \
    iptables \
    iproute2 \
    nmap \
    redis-server \
    curl \
    git \
    libpq-dev \
    build-essential

echo -e "\n${YELLOW}[2/6] Configuring Service User & Application Directory...${NC}"
if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
    useradd -r -s /bin/false -d "${INSTALL_DIR}" "${SERVICE_USER}"
    echo -e "${GREEN}Created dedicated system user: ${SERVICE_USER}${NC}"
fi

mkdir -p "${INSTALL_DIR}"
cp -r . "${INSTALL_DIR}/"
chown -R "${SERVICE_USER}:${SERVICE_USER}" "${INSTALL_DIR}"

echo -e "\n${YELLOW}[3/6] Setting Up Python Virtual Environment...${NC}"
cd "${INSTALL_DIR}"
sudo -u "${SERVICE_USER}" python3 -m venv venv
sudo -u "${SERVICE_USER}" ./venv/bin/pip install --upgrade pip
sudo -u "${SERVICE_USER}" ./venv/bin/pip install -r requirements.txt

echo -e "\n${YELLOW}[4/6] Setting Linux Network Capabilities (Raw Sockets & IPTables)...${NC}"
# Allow Python binary to sniff raw packets & manipulate iptables without full root escalation
setcap 'cap_net_raw,cap_net_admin+eip' "$(readlink -f ./venv/bin/python3)"

echo -e "\n${YELLOW}[5/6] Registering Systemd Services...${NC}"
cp deploy/systemd/netguard-api.service /etc/systemd/system/
cp deploy/systemd/netguard-worker.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable redis-server
systemctl restart redis-server
systemctl enable netguard-api.service
systemctl enable netguard-worker.service

echo -e "\n${YELLOW}[6/6] Verifying Service Health...${NC}"
systemctl restart netguard-api.service
sleep 3
if systemctl is-active --quiet netguard-api.service; then
    echo -e "${GREEN}✅ NetGuard API is active and running on port 8081!${NC}"
else
    echo -e "${RED}⚠️  NetGuard API service started with issues. Check: journalctl -u netguard-api.service -e${NC}"
fi

echo -e "\n${GREEN}======================================================${NC}"
echo -e "${GREEN}  🎉 NetGuard IDS Installation Completed Successfully! ${NC}"
echo -e "${GREEN}  Manage Services:                                     ${NC}"
echo -e "${GREEN}    sudo systemctl status netguard-api                 ${NC}"
echo -e "${GREEN}    sudo journalctl -u netguard-api -f                 ${NC}"
echo -e "${GREEN}======================================================${NC}"
