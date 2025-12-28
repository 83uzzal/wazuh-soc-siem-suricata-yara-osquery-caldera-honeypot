#!/bin/bash
# ============================================================
# Cowrie Honeypot Automated Installer (SYSTEMD SAFE)
# - No PID issues
# - No port binding issues
# - Survives reboot
# ============================================================

set -Eeuo pipefail

COWRIE_USER="cowrie"
COWRIE_HOME="/home/$COWRIE_USER"
COWRIE_DIR="$COWRIE_HOME/cowrie"
VENV_DIR="$COWRIE_DIR/cowrie-env"

echo "[+] Starting Cowrie installation..."

# Root check
if [[ $EUID -ne 0 ]]; then
  echo "[ERROR] Run as root"
  exit 1
fi

# System update
apt update -y --fix-missing
apt install -y git python3 python3-venv python3-pip \
               libssl-dev libffi-dev build-essential \
               libpython3-dev curl wget net-tools

# Create cowrie user
if ! id cowrie &>/dev/null; then
  adduser --disabled-password --gecos "" cowrie
fi

# Clone Cowrie (shallow)
if [ ! -d "$COWRIE_DIR" ]; then
  sudo -u cowrie git clone --depth 1 https://github.com/cowrie/cowrie.git "$COWRIE_DIR"
fi

# Python venv
sudo -u cowrie python3 -m venv "$VENV_DIR"
sudo -u cowrie "$VENV_DIR/bin/pip" install --upgrade pip wheel setuptools

# Install Cowrie
sudo -u cowrie "$VENV_DIR/bin/pip" install -e "$COWRIE_DIR"

# Config
CFG="$COWRIE_DIR/etc/cowrie.cfg"
[ ! -f "$CFG" ] && sudo -u cowrie cp "$COWRIE_DIR/etc/cowrie.cfg.dist" "$CFG"

# Enable Telnet
sudo -u cowrie sed -i 's/^#enabled = false/enabled = true/' "$CFG"

# Systemd service (CORRECT)
cat <<EOF >/etc/systemd/system/cowrie.service
[Unit]
Description=Cowrie SSH/Telnet Honeypot
After=network.target

[Service]
Type=forking
User=cowrie
WorkingDirectory=/home/cowrie/cowrie
Environment="PATH=/home/cowrie/cowrie/cowrie-env/bin:/usr/bin:/bin"
ExecStart=/home/cowrie/cowrie/cowrie-env/bin/cowrie start
ExecStop=/home/cowrie/cowrie/cowrie-env/bin/cowrie stop
PIDFile=/home/cowrie/cowrie/var/run/cowrie.pid
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

# Enable & start
systemctl daemon-reload
systemctl enable cowrie
systemctl restart cowrie

echo "[+] Installation complete"
systemctl status cowrie --no-pager
