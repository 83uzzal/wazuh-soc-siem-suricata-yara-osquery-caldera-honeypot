#!/bin/bash
# ============================================================
# Cowrie Honeypot Automated Installer with Fixed systemd Service
# Handles shallow clone, Git buffer, PID & port issues
# ============================================================

set -Eeuo pipefail

COWRIE_USER="cowrie"
COWRIE_HOME="/home/${COWRIE_USER}"
COWRIE_DIR="${COWRIE_HOME}/cowrie"
VENV_DIR="${COWRIE_DIR}/cowrie-env"
PID_FILE="${COWRIE_DIR}/var/run/cowrie.pid"

echo "[+] Starting Cowrie installation..."

# -----------------------------
# Root check
# -----------------------------
if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] Please run as root: sudo ./install_cowrie.sh"
    exit 1
fi

# -----------------------------
# Update system and install dependencies
# -----------------------------
echo "[+] Updating system packages..."
apt update -y --fix-missing
apt upgrade -y --fix-missing
apt install -y git python3 python3-pip python3-venv libssl-dev libffi-dev \
    build-essential libpython3-dev python3-minimal authbind wget curl net-tools

# -----------------------------
# Create cowrie user
# -----------------------------
if ! id "$COWRIE_USER" &>/dev/null; then
    echo "[+] Creating user: $COWRIE_USER"
    adduser --disabled-password --gecos "" $COWRIE_USER
fi

# -----------------------------
# Configure Git for large repositories
# -----------------------------
sudo -u $COWRIE_USER git config --global http.postBuffer 524288000

# -----------------------------
# Clone Cowrie repository (shallow clone)
# -----------------------------
if [ ! -d "$COWRIE_DIR" ]; then
    echo "[+] Cloning Cowrie repository (shallow clone)..."
    sudo -u $COWRIE_USER git clone --depth 1 https://github.com/cowrie/cowrie.git $COWRIE_DIR
fi

# -----------------------------
# Setup Python virtual environment
# -----------------------------
echo "[+] Setting up Python virtual environment..."
sudo -u $COWRIE_USER python3 -m venv $VENV_DIR
sudo -u $COWRIE_USER bash -c "source $VENV_DIR/bin/activate && pip install --upgrade pip setuptools wheel"

# -----------------------------
# Install Cowrie Python packages
# -----------------------------
echo "[+] Installing Cowrie dependencies..."
sudo -u $COWRIE_USER bash -c "source $VENV_DIR/bin/activate && pip install -e $COWRIE_DIR"

# -----------------------------
# Configure cowrie.cfg
# -----------------------------
CFG_FILE="$COWRIE_DIR/etc/cowrie.cfg"
if [ ! -f "$CFG_FILE" ]; then
    echo "[+] Creating cowrie.cfg from template..."
    sudo -u $COWRIE_USER cp $COWRIE_DIR/etc/cowrie.cfg.dist $CFG_FILE
fi

# Enable Telnet support
sudo -u $COWRIE_USER sed -i 's/^#enabled = false/enabled = true/' $CFG_FILE

# -----------------------------
# Remove stale PID file
# -----------------------------
if [ -f "$PID_FILE" ]; then
    echo "[+] Removing stale PID file..."
    sudo -u $COWRIE_USER rm -f $PID_FILE
fi

# -----------------------------
# Create systemd service (fixed for forking)
# -----------------------------
SERVICE_FILE="/etc/systemd/system/cowrie.service"
echo "[+] Creating systemd service..."
cat <<EOF > $SERVICE_FILE
[Unit]
Description=Cowrie SSH/Telnet Honeypot
After=network.target

[Service]
Type=forking
User=$COWRIE_USER
WorkingDirectory=$COWRIE_DIR
Environment="PATH=$VENV_DIR/bin:/usr/bin:/bin"
ExecStart=$VENV_DIR/bin/cowrie start
ExecStop=$VENV_DIR/bin/cowrie stop
PIDFile=$PID_FILE
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

# -----------------------------
# Reload systemd and start Cowrie
# -----------------------------
echo "[+] Reloading systemd daemon..."
systemctl daemon-reload
systemctl enable cowrie
systemctl start cowrie

# -----------------------------
# Show status
# -----------------------------
echo "[+] Cowrie installation completed."
echo "[INFO] Check status with: sudo systemctl status cowrie"
echo "[INFO] SSH Honeypot : Port 2222"
echo "[INFO] Telnet Honeypot: Port 2223"
