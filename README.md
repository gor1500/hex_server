# hEX Command Center

A comprehensive, self-hosted dashboard, alerting system, and camera viewer for MikroTik routers. Built with Python (Flask), SQLite, and go2rtc.

## Features
- Real-time Telemetry: Tracks CPU, RAM, temperature, ping, and WAN bandwidth.
- Security and Bans: Manual and automatic IP banning via firewall rules. Includes a honeypot integration.
- Live Camera Viewer: Integrates with go2rtc to provide low-latency WebRTC streams.
- Smart Alerts: Routes emergencies to Telegram and standard logs to Discord.
- Periodic Reports: Sends hourly and daily summaries.
- Bedtime Scheduler: Automatically blocks Wi-Fi at set times.

## Quick Start

1. Configure your MikroTik router using the provided script:
   Paste the contents of `router_setup.rsc` into your MikroTik terminal.

2. Run the universal installation script on your Linux server:
   chmod +x install.sh
   ./install.sh

3. Edit `config.py` with your router and notification credentials.

4. Access the dashboard at http://localhost:5000.

For a detailed, step-by-step guide, see [INSTALL.md](INSTALL.md).

## Architecture
- Frontend: HTML/CSS/JS (Vanilla, Chart.js).
- Backend: Python Flask.
- Database: SQLite (WAL mode for concurrency).
- Camera Streaming: go2rtc (WebRTC).
- Snapshot Engine: FFmpeg.
