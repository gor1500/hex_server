# Installation Guide

This guide covers the full setup of the hEX Command Center, from router configuration to running the dashboard 24/7.

## Prerequisites
- A MikroTik router (tested on hEX RB750Gr3) running RouterOS 7.x.
- A Linux server (Debian, Ubuntu, Fedora, or Arch) to host the dashboard.
- Network access between the server and the router.

## Step 1: Router Configuration
1. Open WinBox or SSH into your MikroTik router.
2. Open the terminal and paste the contents of `router_setup.rsc`.
3. This enables the REST API on port 443, configures the honeypot, sets up Netwatch for auto-recovery, and applies basic firewall rules.

## Step 2: Dashboard Installation (Automated)
The easiest way to install is using the provided script:
chmod +x install.sh
./install.sh

## Step 3: Dashboard Installation (Manual)
If you prefer to install manually:
1. Install system dependencies:
   sudo apt install python3 python3-venv ffmpeg curl (or equivalent for your distro)
2. Clone the repository and enter the directory:
   git clone https://github.com/gor1500/hex_server.git && cd hex_server
3. Create the virtual environment:
   python3 -m venv venv && source venv/bin/activate
4. Install Python requirements:
   pip install -r requirements.txt
5. Download go2rtc:
   wget https://github.com/AlexxIT/go2rtc/releases/latest/download/go2rtc_linux_amd64 -O go2rtc && chmod +x go2rtc

## Step 4: Configuration
1. Copy the example config:
   cp config.example.py config.py
2. Edit config.py and fill in:
   - Your MikroTik IP, Username, and Password.
   - Your Discord Webhook URL (for logs).
   - Your Telegram Bot Token and Chat ID (for emergencies).
   - Your Wi-Fi SSIDs and Passwords (for the QR code generator).

## Step 5: Running the Application
Start the dashboard:
python app.py
Access it at http://localhost:5000. The default login is admin / admin (change this in config.py).

## Troubleshooting
- Router API 401: Ensure you enabled www-ssl in RouterOS and that your user has API permissions.
- Cameras show black: Make sure FFmpeg is installed. Check the camera RTSP URL by running ffprobe -i "rtsp://user:pass@IP:554/..." in the terminal.
- No live stream: Ensure go2rtc is running (systemctl status go2rtc) and that your firewall allows port 1984.
