#!/bin/bash
# ============================================================
# SOC Home Lab - One Command Installer (Production Grade)
# Wazuh 4.14 + Suricata + Cowrie + YARA + ClamAV + Osquery
# Ubuntu 22.04 / 24.04
# ============================================================

set -Eeuo pipefail

# --- Fix CRLF line endings for this script (GitHub copy) ---
apt update -y
apt install -y dos2unix
dos2unix "$0"

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

# ... rest of your script ...
