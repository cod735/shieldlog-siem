#!/bin/bash

echo "=================================================="
echo "  PySIEM — Installer"
echo "=================================================="

# Check running as root
if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Please run as root: sudo bash install.sh"
    exit 1
fi

# Get the real user who ran sudo
REAL_USER="${SUDO_USER:-$USER}"
PROJECT_DIR="/home/$REAL_USER/pysiem"

echo "[*] Installing for user: $REAL_USER"
echo "[*] Project directory: $PROJECT_DIR"

# Step 1 — Install Python venv if missing
echo "[*] Checking Python..."
apt install python3-venv python3-pip -y > /dev/null 2>&1
echo "[OK] Python ready"

# Step 2 — Create virtual environment if missing
if [ ! -d "$PROJECT_DIR/venv" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv "$PROJECT_DIR/venv"
    echo "[OK] Virtual environment created"
else
    echo "[OK] Virtual environment already exists"
fi

# Step 3 — Install Flask
echo "[*] Installing Flask..."
"$PROJECT_DIR/venv/bin/pip" install flask > /dev/null 2>&1
echo "[OK] Flask installed"

# Step 4 — Create systemd service
echo "[*] Creating systemd service..."

cat > /etc/systemd/system/pysiem.service << EOF
[Unit]
Description=PySIEM Security Monitor
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$PROJECT_DIR
ExecStart=$PROJECT_DIR/venv/bin/python3 $PROJECT_DIR/main.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

echo "[OK] Service file created"

# Step 5 — Enable and start
echo "[*] Enabling PySIEM to start on boot..."
systemctl daemon-reload
systemctl enable pysiem > /dev/null 2>&1
systemctl restart pysiem
echo "[OK] PySIEM service enabled and started"

# Step 6 — Verify
sleep 2
STATUS=$(systemctl is-active pysiem)

echo ""
echo "=================================================="
if [ "$STATUS" = "active" ]; then
    echo "  PySIEM installed successfully"
    echo "  Status  : RUNNING"
    echo "  Dashboard: http://localhost:5000"
    echo "  Auto-start on boot: YES"
else
    echo "  Something went wrong — check: sudo systemctl status pysiem"
fi
echo "=================================================="
