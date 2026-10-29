# hEX Command Center

A comprehensive, self-hosted dashboard and alerting system for MikroTik routers. Built with Python (Flask) and SQLite.

## Features
- Real-time Telemetry: Tracks CPU, RAM, temperature, ping, and WAN bandwidth.
- Security and Bans: Manual and automatic IP banning via firewall rules.
- Live Camera Viewer: Integrates with go2rtc to provide WebRTC streams.
- Smart Alerts: Routes emergencies to Telegram and standard logs to Discord.
- Periodic Reports: Sends hourly and daily summaries.

## Prerequisites
- A MikroTik router with the REST API enabled.
- Python 3.10+
- FFmpeg (for camera snapshots)
- go2rtc (for live camera streams)

## Installation

1. Clone the repository:
   git clone https://github.com/gor1500/hex_server.git
   cd hex_server

2. Create and activate a virtual environment:
   python3 -m venv venv
   source venv/bin/activate

3. Install dependencies:
   pip install -r requirements.txt

4. Create your configuration file:
   cp config.example.py config.py
   Edit config.py and fill in your credentials.

5. Run the application:
   python app.py
