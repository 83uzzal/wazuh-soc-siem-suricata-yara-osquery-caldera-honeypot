#!/bin/bash
# ============================================================
# SOC Home Lab - One Command Installer (Production Grade)
# Wazuh 4.14 + Suricata + Cowrie + YARA + ClamAV + Osquery
# Ubuntu 22.04 / 24.04
# ============================================================

set -Eeuo pipefail

LOG_FILE="/var/log/soc_install.log"
exec > >(tee -a "$LOG_FILE") 2>&1

log() {
  echo -e "\n[INFO] $(date '+%F %T') - $1"
}

fail() {
  echo -e "\n[ERROR] $1"
  exit 1
}

trap 'fail "Installation failed at line $LINENO"' ERR

# ------------------------------------------------------------
# Root check
# ------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
  fail "Run as root: sudo ./install_all.sh"
fi

# ------------------------------------------------------------
# Detect network info
# ------------------------------------------------------------
SERVER_IP=$(hostname -I | awk '{print $1}')
PRIMARY_IF=$(ip route | awk '/default/ {print $5; exit}')

log "Server IP        : $SERVER_IP"
log "Primary Interface: $PRIMARY_IF"

# ------------------------------------------------------------
# System preparation
# ------------------------------------------------------------
log "Updating system"
apt update -y
apt install -y curl gnupg apt-transport-https \
               software-properties-common \
               ca-certificates jq git

# ------------------------------------------------------------
# Wazuh 4.14 All-in-One
# ------------------------------------------------------------
install_wazuh() {
  if systemctl list-units --type=service | grep -q wazuh-manager; then
    log "Wazuh already installed, skipping"
    return
  fi

  log "Installing Wazuh 4.14 (All-in-One)"
  curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
  bash wazuh-install.sh -a | tee /tmp/wazuh-install.log

  DASH_USER=$(grep -m1 "User:" /tmp/wazuh-install.log | awk '{print $2}')
  DASH_PASS=$(grep -m1 "Password:" /tmp/wazuh-install.log | awk '{print $2}')

  echo "$DASH_USER:$DASH_PASS" > /root/wazuh_dashboard_creds.txt
  chmod 600 /root/wazuh_dashboard_creds.txt
}

# ------------------------------------------------------------
# Suricata IDS
# ------------------------------------------------------------
install_suricata() {
  if command -v suricata &>/dev/null; then
    log "Suricata already installed"
    return
  fi

  log "Installing Suricata"
  apt install -y suricata suricata-update libpcap0.8

  log "Configuring Suricata interface"
  sed -i "s|interface: .*|interface: $PRIMARY_IF|" /etc/suricata/suricata.yaml

  log "Updating Suricata rules (runtime)"
  suricata-update

  systemctl enable suricata
  systemctl restart suricata
}

# ------------------------------------------------------------
# Integrate Suricata with Wazuh
# ------------------------------------------------------------
integrate_suricata_wazuh() {
  OSSEC_CONF="/var/ossec/etc/ossec.conf"

  log "Integrating Suricata → Wazuh"

  cp "$OSSEC_CONF" "${OSSEC_CONF}.bak.$(date +%F)" || true

  sed -i '/<!-- WAZUH_SURICATA_BEGIN -->/,/<!-- WAZUH_SURICATA_END -->/d' "$OSSEC_CONF"

  cat <<EOF >> "$OSSEC_CONF"

<!-- WAZUH_SURICATA_BEGIN -->
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/suricata/eve.json</location>
  </localfile>
</ossec_config>
<!-- WAZUH_SURICATA_END -->

EOF

  systemctl restart wazuh-manager
}

# ------------------------------------------------------------
# YARA + ClamAV
# ------------------------------------------------------------
install_yara_clamav() {
  log "Installing YARA & ClamAV"
  apt install -y yara clamav clamav-daemon

  systemctl stop clamav-freshclam || true
  freshclam
  systemctl enable clamav-daemon
  systemctl start clamav-daemon
}

# ------------------------------------------------------------
# Osquery
# ------------------------------------------------------------
install_osquery() {
  if command -v osqueryd &>/dev/null; then
    log "Osquery already installed"
    return
  fi

  log "Installing Osquery"
  curl -L https://pkg.osquery.io/deb/osquery_5.20.0-1.linux_amd64.deb -o /tmp/osquery.deb
  dpkg -i /tmp/osquery.deb

  mkdir -p /etc/osquery
  cat <<EOF > /etc/osquery/osquery.conf
{
  "options": {
    "logger_plugin": "filesystem",
    "logger_path": "/var/log/osquery",
    "utc": "true"
  },
  "schedule": {
    "system_info": {
      "query": "SELECT hostname, cpu_brand, physical_memory FROM system_info;",
      "interval": 3600
    }
  }
}
EOF

  systemctl enable osqueryd
  systemctl restart osqueryd
}

# ------------------------------------------------------------
# Cowrie SSH Honeypot
# ------------------------------------------------------------
install_cowrie() {
  if [[ -d /opt/cowrie ]]; then
    log "Cowrie already installed"
    return
  fi

  log "Installing Cowrie Honeypot"
  apt install -y git python3-venv libssl-dev libffi-dev build-essential

  git clone https://github.com/cowrie/cowrie.git /opt/cowrie
  cd /opt/cowrie
  python3 -m venv cowrie-env
  source cowrie-env/bin/activate
  pip install --upgrade pip
  pip install -r requirements.txt

  cp etc/cowrie.cfg.dist etc/cowrie.cfg
  sed -i 's/listen_port = 2222/listen_port = 22/' etc/cowrie.cfg

  adduser --disabled-password --gecos "" cowrie || true
  chown -R cowrie:cowrie /opt/cowrie

  su - cowrie -c "/opt/cowrie/bin/cowrie start"
}

# ------------------------------------------------------------
# MAIN
# ------------------------------------------------------------
log "SOC Home Lab installation started"

install_wazuh
install_suricata
integrate_suricata_wazuh
install_yara_clamav
install_osquery
install_cowrie

log "INSTALLATION COMPLETED SUCCESSFULLY"
echo "================================================="
echo " Wazuh Dashboard: https://$SERVER_IP"
echo " Credentials    : /root/wazuh_dashboard_creds.txt"
echo " Logs           : $LOG_FILE"
echo "================================================="
