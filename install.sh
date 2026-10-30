#!/bin/bash
# hEX Command Center - Universal Linux Installer

set -e

echo "Starting hEX Command Center Installation..."

# 1. Detect OS and Install Dependencies
if command -v apt-get &> /dev/null; then
    echo "Debian/Ubuntu detected."
    sudo apt-get update
    sudo apt-get install -y python3 python3-venv python3-pip ffmpeg curl wget policycoreutils
elif command -v dnf &> /dev/null; then
    echo "Fedora/RHEL detected."
    sudo dnf install -y python3 python3-pip ffmpeg curl wget policycoreutils-python-utils
elif command -v pacman &> /dev/null; then
    echo "Arch Linux detected."
    sudo pacman -Sy --noconfirm python python-pip ffmpeg curl wget
else
    echo "Unsupported package manager. Please install python3, ffmpeg, and curl manually."
    exit 1
fi

# 2. Setup Python Virtual Environment
echo "Setting up Python environment..."
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. Install go2rtc
echo "Installing go2rtc..."
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then
    GO2RTC_URL="https://github.com/AlexxIT/go2rtc/releases/latest/download/go2rtc_linux_amd64"
elif [ "$ARCH" = "aarch64" ]; then
    GO2RTC_URL="https://github.com/AlexxIT/go2rtc/releases/latest/download/go2rtc_linux_arm64"
else
    GO2RTC_URL="https://github.com/AlexxIT/go2rtc/releases/latest/download/go2rtc_linux_arm"
fi

wget -q $GO2RTC_URL -O go2rtc
chmod +x go2rtc

# 4. Create Config File
if [ ! -f config.py ]; then
    cp config.example.py config.py
    echo "Created config.py. Please edit it with your credentials."
fi

# 5. Setup Systemd Services
echo "Creating systemd services..."
DASHBOARD_DIR=$(pwd)

cat << SERVICE_EOF | sudo tee /etc/systemd/system/hex-dashboard.service > /dev/null
[Unit]
Description=hEX Command Center
After=network-online.target
Wants=network-online.target

[Service]
User=$USER
Group=$USER
WorkingDirectory=$DASHBOARD_DIR
ExecStart=$DASHBOARD_DIR/venv/bin/python $DASHBOARD_DIR/app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE_EOF

cat << SERVICE_EOF | sudo tee /etc/systemd/system/go2rtc.service > /dev/null
[Unit]
Description=go2rtc Media Server
After=network.target

[Service]
User=$USER
WorkingDirectory=$DASHBOARD_DIR
ExecStart=$DASHBOARD_DIR/go2rtc
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE_EOF

# 6. Enable and Start
sudo systemctl daemon-reload
sudo systemctl enable --now go2rtc
sudo systemctl enable --now hex-dashboard

echo "Installation Complete!"
echo "1. Edit config.py with your router and Discord/Telegram credentials."
echo "2. Restart the dashboard: sudo systemctl restart hex-dashboard"
echo "3. Access it at http://localhost:5000"
