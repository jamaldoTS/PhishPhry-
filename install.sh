#!/bin/bash

echo "[+] Creating virtual environment 'phishphry-env'..."
python3 -m venv phishphry-env

echo "[+] Activating virtual environment..."
source phishphry-env/bin/activate

echo "[+] Upgrading pip..."
pip install --upgrade pip

echo "[+] Installing required Python packages..."
pip install pyqt6 pyqt6-webengine requests python-whois dnspython

echo "[+] Making 'run.sh' executable..."
chmod +x run.sh

echo "[+] Installation complete."
echo ""
echo "To run PhishPhry later:"
echo "  ./run.sh"
