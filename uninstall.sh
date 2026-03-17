#!/bin/bash

if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Please run as root: sudo bash uninstall.sh"
    exit 1
fi

echo "[*] Stopping PySIEM service..."
systemctl stop pysiem
systemctl disable pysiem
rm -f /etc/systemd/system/pysiem.service
systemctl daemon-reload

echo ""
echo "=================================================="
echo "  PySIEM uninstalled successfully"
echo "  Project folder remains at ~/pysiem"
echo "=================================================="
