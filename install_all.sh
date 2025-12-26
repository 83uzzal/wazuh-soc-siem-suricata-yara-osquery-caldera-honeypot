#!/bin/bash
# ============================================================
# SOC Home Lab - One Command Installer (Production Grade)
# Wazuh 4.14 + Suricata + Cowrie + YARA + ClamAV + Osquery
# Ubuntu 22.04 / 24.04
# ============================================================

set -Eeuo pipefail

# ------------------------------------------------------------
# Root check
# ------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
  echo -e "\n[ERROR] Run as root: sudo ./install_all.sh"
  exit 1
fi

# ------------------------------------------------------------
# Fix CRLF line endings (GitHub copy) BEFORE any execution
# ------------------------------------------------------------
apt update -y
apt install -y dos2unix
dos2unix "$0"

# ------------------------------------------------------------
# Logging
# ------------------------------------------------------------
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

log "Root check and CRLF fix completed. Ready to proceed."

# ------------------------------------------------------------
# Now you can call other installation functions:
# install_wazuh
# install_suricata
# install_yara_clamav
# install_osquery
# install_cowrie
# ------------------------------------------------------------
