#!/usr/bin/env python3
import os
import sys
import re
import io
import json
import time
import socket
import sqlite3
import fcntl
import signal
import secrets
import subprocess
import threading
import atexit
import urllib.parse
import paramiko
import queue
import base64

from datetime import datetime
from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, send_file, Response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import requests
import urllib3
import qrcode
import speedtest
import config
from camera_manager import init_camera_db, add_camera, update_camera, get_cameras, delete_camera

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

def _load_secret_key():
    key_file = "secret.key"
    if os.path.exists(key_file):
        with open(key_file, "r") as f:
            k = f.read().strip()
        if k: return k
    k = secrets.token_hex(32)
    with open(key_file, "w") as f:
        f.write(k)
    try: os.chmod(key_file, 0o600)
    except OSError: pass
    return k

app.secret_key = getattr(config, "SECRET_KEY", "") or _load_secret_key()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class User(UserMixin):
    def __init__(self, id): self.id = id

@login_manager.user_loader
def load_user(user_id):
    if user_id == "admin": return User("admin")
    return None

BASE_URL = f"https://{config.ROUTER_IP}/rest"
AUTH = (config.ROUTER_USER, config.ROUTER_PASS)
DEVICES_FILE = "data/devices.json"
DB_FILE = "data/speedtest.db"
BANS_FILE = "data/bans.json"
IFACES_FILE = "data/interfaces.json"
STATE_FILE = "data/state.json"
LOCK_FILE = "data/dashboard.lock"
PENDING_FILE = "data/pending_discord.json"
TELEMETRY_WRITE_INTERVAL = 10

latest_telemetry = {
    "system": None, "interfaces": [], "bedtime": False, "bedtime_time": "-",
    "speed": {"rx": 0, "tx": 0}, "panic": False, "camera_kill": False, "camera_alerts": False,
    "temp": "--", "ping": 0,
}

_state = {
    "last_honeypot_log_id": None,
    "last_reboot_log_id": None,
    "last_uptime_seconds": None,
    "last_hourly_sent": 0,
    "last_daily_sent": 0,
    "last_cleanup": 0,
    "last_shutdown": 0,
    "last_shutdown_reason": "",
    "camera_alerts": False
}

MAC_VENDORS = {
    "70:85:C2": "Intel", "44:5C:E9": "Samsung", "54:BA:D9": "Intelbras",
    "C8:E7:D8": "Mercusys", "64:D1:54": "MikroTik", "00:0C:43": "MediaTek",
    "3C:37:12": "Apple", "F0:18:98": "Apple", "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
}

def _atomic_write_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w") as f: json.dump(data, f)
    os.replace(tmp, path)

def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f: _state.update(json.load(f))
        except Exception: pass

def save_state():
    try: _atomic_write_json(STATE_FILE, _state)
    except Exception: pass

def init_db():
    conn = sqlite3.connect(DB_FILE, timeout=5)
    try:
        c = conn.cursor()
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        c.execute("PRAGMA busy_timeout=5000")
        c.execute("CREATE TABLE IF NOT EXISTS speedtests (timestamp INTEGER, download REAL, upload REAL, ping REAL)")
        c.execute("CREATE TABLE IF NOT EXISTS telemetry (timestamp INTEGER, cpu REAL, ram REAL, wan_rx REAL, wan_tx REAL, ping REAL)")
        c.execute("CREATE TABLE IF NOT EXISTS incidents (timestamp INTEGER, type TEXT, detail TEXT, severity TEXT)")
        conn.commit()
    finally: conn.close()

def load_ifaces():
    default_ifaces = {
        "ether1": "WAN (Huawei ONT - Viaband)", "ether2": "LAN (Fedora PC)",
        "ether3": "LAN (Room Archer AP)", "ether4": "LAN (Attic Switch / Cameras)",
        "ether5": "LAN (Raspberry Pi)", "pppoe-wan": "WAN (PPPoE Viaband)", "bridge": "LAN (Local Network)",
    }
    if os.path.exists(IFACES_FILE):
        with open(IFACES_FILE, "r") as f: saved = json.load(f); default_ifaces.update(saved)
    return default_ifaces

def save_ifaces(data): _atomic_write_json(IFACES_FILE, data)

def load_bans():
    if os.path.exists(BANS_FILE):
        with open(BANS_FILE, "r") as f: return json.load(f)
    return {"active": {}, "history": {}}

def save_bans(data): _atomic_write_json(BANS_FILE, data)

def get_mikrotik_data(endpoint):
    try:
        response = requests.get(f"{BASE_URL}/{endpoint}", auth=AUTH, verify=False, timeout=3)
        response.raise_for_status()
        return response.json()
    except Exception: return None

def rule_exists(comment):
    rules = get_mikrotik_data("ip/firewall/filter")
    if not rules: return False
    return any(r.get("comment") == comment for r in rules)

def add_rule(chain, in_iface, out_iface, comment, src_address=None, idempotent=True):
    if idempotent and rule_exists(comment): return True
    json_data = {"chain": chain, "action": "drop", "comment": comment}
    if in_iface: json_data["in-bridge-port"] = in_iface
    if out_iface: json_data["out-interface"] = out_iface
    if src_address: json_data["src-address"] = src_address
    try:
        requests.put(f"{BASE_URL}/ip/firewall/filter", auth=AUTH, json=json_data, verify=False, timeout=3)
        return True
    except Exception: return False

def remove_rule(comment):
    rules = get_mikrotik_data("ip/firewall/filter")
    if not rules: return False
    removed = False
    for rule in rules:
        if rule.get("comment") == comment:
            try: requests.delete(f"{BASE_URL}/ip/firewall/filter/{rule.get('.id')}", auth=AUTH, verify=False, timeout=3); removed = True
            except Exception: pass
    return removed

def ban_ip(ip, reason):
    add_rule("forward", None, "pppoe-wan", f"BLOCK-{ip}", src_address=ip, idempotent=True)
    bans = load_bans()
    now = int(time.time())
    if ip not in bans["active"]: bans["active"][ip] = {"reason": reason, "time": now}
    bans["history"][ip] = {"reason": reason, "time": now}
    save_bans(bans)

def unban_ip(ip):
    remove_rule(f"BLOCK-{ip}")
    bans = load_bans()
    bans["active"].pop(ip, None)
    save_bans(bans)

def send_discord_raw(title, message="", color=3447003, ping=False, fields=None):
    webhook_url = getattr(config, "DISCORD_WEBHOOK_URL", "")
    if not webhook_url or webhook_url == "YOUR_DISCORD_WEBHOOK_URL_HERE": return None
    url = webhook_url + "?wait=true"
    content = f"@everyone\n**{title}**" if ping else ""
    embed = {"title": title, "color": color}
    if message: embed["description"] = message
    if fields: embed["fields"] = fields
    data = {"content": content, "allowed_mentions": {"parse": ["everyone"]} if ping else {"parse": []}, "embeds": [embed]}
    try:
        r = requests.post(url, json=data, timeout=5)
        if r.status_code == 200: return r.json().get("id")
    except Exception: pass
    return None

def send_telegram_raw(title, message):
    token = getattr(config, "TELEGRAM_TOKEN", "")
    chat_id = getattr(config, "TELEGRAM_CHAT_ID", "")
    if not token or not chat_id or token == "YOUR_TELEGRAM_TOKEN_HERE": return False
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": f"*{title}*\n{message}", "parse_mode": "Markdown"}
    try:
        r = requests.post(url, json=payload, timeout=5)
        return r.status_code == 200
    except Exception: return False

def record_incident(incident_type, detail, severity="info"):
    try:
        conn = sqlite3.connect(DB_FILE, timeout=5)
        try:
            conn.execute("PRAGMA busy_timeout=5000")
            conn.execute("INSERT INTO incidents VALUES (?, ?, ?, ?)", (int(time.time()), incident_type, detail, severity))
            conn.commit()
        finally: conn.close()
    except Exception as e: print(f"Incident record failed: {e}")

def send_emergency(title, message, color=15158332, severity="emergency"):
    record_incident(title, message, severity)
    if send_telegram_raw(title, message): return True
    if send_discord_raw(title, f"[Telegram fallback] {message}", color, ping=True): return True
    return False

def send_info(title, message, color=3447003, severity="info"):
    record_incident(title, message, severity)
    return send_discord_raw(title, message, color, ping=False) is not None

def handle_shutdown(signum, frame):
    _state["last_shutdown"] = int(time.time())
    _state["last_shutdown_reason"] = "clean"
    save_state()
    print("Shutdown signal received, state saved.")
    sys.exit(0)

def startup_catchup():
    last_shutdown = _state.get("last_shutdown", 0)
    last_hb = 0
    try:
        with open("data/heartbeat", "r") as f:
            last_hb = int(f.read().strip())
    except Exception:
        pass
    last_seen = max(last_shutdown, last_hb)
    if last_seen == 0:
        return
    now = int(time.time())
    offline = now - last_seen
    if offline < 120:
        _state["last_shutdown"] = 0
        _state["last_shutdown_reason"] = ""
        save_state()
        return
    clean = _state.get("last_shutdown_reason", "") == "clean"
    hours = offline // 3600
    minutes = (offline % 3600) // 60
    if clean:
        label = "Dashboard Host Online"
        msg = f"Rebooted cleanly. Offline for **{hours}h {minutes}m**."
        try:
            send_discord_raw(f"[INFO] {label}", msg, 3066993)
        except Exception:
            pass
    else:
        label = "Dashboard Host Online (CRASHED)"
        msg = f"Previous session crashed. Offline for **{hours}h {minutes}m**."
        try:
            send_discord_raw(f"[URGENT] {label}", msg, 15105570, ping=True)
        except Exception:
            pass
    _state["last_shutdown"] = 0
    _state["last_shutdown_reason"] = ""
    save_state()

signal.signal(signal.SIGTERM, handle_shutdown)
atexit.register(lambda: handle_shutdown(None, None) if os.environ.get("WERKZEUG_RUN_MAIN") == "true" else None)

def get_bedtime_state():
    rules = get_mikrotik_data("ip/firewall/filter")
    if not rules: return False
    for r in rules:
        if r.get("comment") == "Bedtime for Wi-Fi":
            return r.get("disabled", "false") == "false"
    return False

def sync_go2rtc():
    cams = get_cameras(app.secret_key)
    yaml_content = "streams:\n"
    for c in cams:
        safe_user = urllib.parse.quote(c['username']) if c['username'] else ""
        safe_pass = urllib.parse.quote(c['password']) if c['password'] else ""
        auth_url = c['rtsp_url'].replace("rtsp://", f"rtsp://{safe_user}:{safe_pass}@") if safe_user and safe_pass else c['rtsp_url']
        if "/101" in auth_url: auth_url = auth_url.replace("/101", "/102")
        yaml_content += f"  cam_{c['id']}:\n    - {auth_url}\n"
        try:
            requests.put(f"http://127.0.0.1:1984/api/streams?name=cam_{c['id']}", data={"src": auth_url}, timeout=2)
        except Exception: pass
    with open("data/go2rtc.yaml", "w") as f:
        f.write(yaml_content)

@app.route("/api/scan_cameras")
@login_required
def scan_cameras():
    nat_rules = get_mikrotik_data("ip/firewall/nat")
    nat_map = {}
    if nat_rules:
        for rule in nat_rules:
            if rule.get("action") == "netmap" and rule.get("chain") == "dstnat":
                dst = rule.get("dst-address")
                to_addr = rule.get("to-addresses")
                if dst and to_addr:
                    nat_map[to_addr.split("/")[0]] = dst.split("/")[0]
    for physical_ip in nat_map.keys():
        try: subprocess.run(["ping", "-c", "1", "-W", "1", physical_ip], capture_output=True, timeout=2)
        except: pass
    arp_table = get_mikrotik_data("ip/arp")
    if not arp_table: return jsonify([])
    cam_vendors = {
        "4C:F5:DC": "Hikvision / HiLook", "C0:56:E3": "Hikvision", "44:19:B6": "Hikvision",
        "BC:AD:28": "Hikvision", "28:57:BE": "Hikvision",
        "58:10:8C": "Intelbras", "54:BA:D9": "Intelbras",
        "3C:EF:8C": "Dahua / Intelbras", "4C:11:BF": "Dahua", "90:02:A9": "Dahua"
    }
    found_cams = {}
    for entry in arp_table:
        ip = entry.get("address")
        mac = entry.get("mac-address", "").upper()
        if not ip or not mac: continue
        prefix = mac[:8]
        if prefix in cam_vendors:
            vendor = cam_vendors[prefix]
            if ip in nat_map:
                final_ip = nat_map[ip]
                nat_status = f"NAT Active (Mapped to {final_ip})"
            elif ip in nat_map.values():
                final_ip = ip
                nat_status = "Direct (Proxy ARP)"
            else:
                final_ip = ip
                nat_status = "Direct (No NAT)"
            rtsp_path = "/Streaming/Channels/101" if "Hikvision" in vendor or "HiLook" in vendor else "/cam/realmonitor?channel=1&subtype=0"
            rtsp_url = f"rtsp://{final_ip}:554{rtsp_path}"
            if mac not in found_cams or "NAT Active" in nat_status:
                found_cams[mac] = {
                    "ip": ip, "final_ip": final_ip, "mac": mac,
                    "vendor": vendor, "rtsp_url": rtsp_url, "nat_status": nat_status
                }
    return jsonify(list(found_cams.values()))

@app.route("/api/cameras", methods=["GET", "POST", "DELETE", "PUT"])
@login_required
def manage_cameras():
    if request.method == "POST":
        data = request.json
        add_camera(data['name'], data['rtsp_url'], data['username'], data['password'], app.secret_key)
        sync_go2rtc()
        return jsonify({"status": "success"})
    elif request.method == "PUT":
        data = request.json
        update_camera(data['id'], data['name'], data['rtsp_url'], data['username'], data['password'], app.secret_key)
        sync_go2rtc()
        return jsonify({"status": "success"})
    elif request.method == "DELETE":
        delete_camera(request.json.get('id'))
        sync_go2rtc()
        return jsonify({"status": "success"})
    else:
        cams = get_cameras(app.secret_key)
        safe_cams = [{"id": c["id"], "name": c["name"], "rtsp_url": c["rtsp_url"], "username": c["username"]} for c in cams]
        return jsonify(safe_cams)

@app.route("/api/camera_snapshot/<int:cam_id>")
@login_required
def camera_snapshot(cam_id):
    cams = get_cameras(app.secret_key)
    cam = next((c for c in cams if c["id"] == cam_id), None)
    if not cam: return "Camera not found", 404
    safe_user = urllib.parse.quote(cam['username']) if cam['username'] else ""
    safe_pass = urllib.parse.quote(cam['password']) if cam['password'] else ""
    auth_url = cam['rtsp_url'].replace("rtsp://", f"rtsp://{safe_user}:{safe_pass}@") if safe_user and safe_pass else cam['rtsp_url']
    snap_url = auth_url.replace("/101", "/102")
    out_file = f"/tmp/cam_snap_{cam_id}.jpg"
    cmd = ["/usr/bin/ffmpeg", "-y", "-loglevel", "error", "-rtsp_transport", "tcp", "-i", snap_url, "-vf", "scale=320:-1", "-frames:v", "1", "-update", "1", "-q:v", "5", "-f", "image2", out_file]
    try: subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    except subprocess.TimeoutExpired: pass
    if os.path.exists(out_file): return send_file(out_file, mimetype='image/jpeg')
    return send_file(io.BytesIO(b'\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff\x21\xf9\x04\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b'), mimetype='image/gif')

@app.route("/api/camera_test/<int:cam_id>")
@login_required
def camera_test(cam_id):
    cams = get_cameras(app.secret_key)
    cam = next((c for c in cams if c["id"] == cam_id), None)
    if not cam: return "Camera not found", 404
    safe_user = urllib.parse.quote(cam['username']) if cam['username'] else ""
    safe_pass = urllib.parse.quote(cam['password']) if cam['password'] else ""
    auth_url = cam['rtsp_url'].replace("rtsp://", f"rtsp://{safe_user}:{safe_pass}@") if safe_user and safe_pass else cam['rtsp_url']
    cmd = ["/usr/bin/ffmpeg", "-y", "-rtsp_transport", "tcp", "-i", auth_url, "-frames:v", "1", "-update", "1", "-f", "image2", f"/tmp/cam_test_{cam_id}.jpg"]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    return f"<h1>Camera Test</h1><p><b>URL Used:</b> {auth_url}</p><p><b>Return Code:</b> {result.returncode}</p><h3>FFMPEG Output:</h3><pre>{result.stderr.decode()}</pre>"

def run_speedtest():
    try:
        st = speedtest.Speedtest(); st.get_servers(); st.get_best_server()
        download = round(st.download() / 1_000_000, 2); upload = round(st.upload() / 1_000_000, 2); ping = round(st.results.ping, 2)
        conn = sqlite3.connect(DB_FILE, timeout=5)
        try:
            conn.execute("PRAGMA busy_timeout=5000")
            conn.execute("INSERT INTO speedtests VALUES (?, ?, ?, ?)", (int(time.time()), download, upload, ping))
            conn.commit()
        finally: conn.close()
        if download < 50.0: send_info("[WARNING] Slow Internet", f"Speed dropped below 50 Mbps.\nDownload: {download} Mbps\nUpload: {upload} Mbps", 15105570, severity="warning")
    except Exception as e: print(f"Speedtest failed: {e}")

def monitor_speedtest():
    time.sleep(10)
    while True: run_speedtest(); time.sleep(900)

_last_heartbeat_write = 0

def _write_heartbeat():
    global _last_heartbeat_write
    now = int(time.time())
    if now - _last_heartbeat_write < 60:
        return
    try:
        with open("data/heartbeat", "w") as f:
            f.write(str(now))
        _last_heartbeat_write = now
    except Exception:
        pass

def send_daily_report():
    now = int(time.time())
    day_ago = now - 86400
    try:
        conn = sqlite3.connect(DB_FILE, timeout=5)
        try:
            c = conn.cursor()
            c.execute("SELECT COUNT(*), AVG(cpu), AVG(ram), AVG(ping) FROM telemetry WHERE timestamp >= ?", (day_ago,))
            tele_row = c.fetchone()
            c.execute("SELECT COUNT(*), AVG(download), AVG(upload) FROM speedtests WHERE timestamp >= ?", (day_ago,))
            speed_row = c.fetchone()
            c.execute("SELECT COUNT(*) FROM incidents WHERE timestamp >= ?", (day_ago,))
            incidents = c.fetchone()[0]
        finally:
            conn.close()
        fields = [
            {"name": "Telemetry samples", "value": str(tele_row[0]), "inline": True},
            {"name": "Avg CPU", "value": f"{tele_row[1]:.1f}%" if tele_row[1] else "n/a", "inline": True},
            {"name": "Avg Ping", "value": f"{tele_row[3]:.1f} ms" if tele_row[3] else "n/a", "inline": True},
            {"name": "Speedtests", "value": str(speed_row[0]), "inline": True},
            {"name": "Avg Download", "value": f"{speed_row[1]:.1f} Mbps" if speed_row[1] else "n/a", "inline": True},
            {"name": "Avg Upload", "value": f"{speed_row[2]:.1f} Mbps" if speed_row[2] else "n/a", "inline": True},
            {"name": "Incidents", "value": str(incidents), "inline": True},
        ]
        send_discord_raw("[INFO] Daily Report", "", 3447003, fields=fields)
    except Exception as e:
        print(f"Daily report failed: {e}")
    _state["last_daily_sent"] = now
    save_state()

def _maybe_send_daily_report():
    now = datetime.now()
    last = _state.get("last_daily_sent", 0)
    last_dt = datetime.fromtimestamp(last) if last else None
    if now.hour >= 8 and (last_dt is None or last_dt.date() < now.date()):
        send_daily_report()

_camera_alert_state = {}
_wan_ip_state = None

def _check_cameras():
    global _camera_alert_state
    alerts_enabled = _state.get("camera_alerts", False)
    if not alerts_enabled:
        return
    cams = get_cameras(app.secret_key)
    for cam in cams:
        cid = cam["id"]
        safe_user = urllib.parse.quote(cam['username']) if cam['username'] else ""
        safe_pass = urllib.parse.quote(cam['password']) if cam['password'] else ""
        auth_url = cam['rtsp_url'].replace("rtsp://", f"rtsp://{safe_user}:{safe_pass}@") if safe_user and safe_pass else cam['rtsp_url']
        snap_url = auth_url.replace("/101", "/102")
        cmd = ["/usr/bin/ffmpeg", "-y", "-loglevel", "error", "-rtsp_transport", "tcp", "-i", snap_url, "-frames:v", "1", "-f", "null", "-"]
        try:
            res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            online = res.returncode == 0
        except Exception:
            online = False
        was_online = _camera_alert_state.get(cid, True)
        if not online and was_online:
            send_discord_raw(f"[ALERT] Camera Offline: {cam['name']}", f"Camera {cam['name']} is not responding.", 15105570, ping=True)
            _camera_alert_state[cid] = False
        elif online and not was_online:
            send_discord_raw(f"[INFO] Camera Online: {cam['name']}", f"Camera {cam['name']} is back online.", 3066993)
            _camera_alert_state[cid] = True

def _check_honeypot():
    global _state
    logs = get_mikrotik_data("log")
    if not logs:
        return
    for l in logs:
        if "HONEYPOT-ALERT" in l.get("message", ""):
            msg = l.get("message")
            if _state.get("last_honeypot_log_id") == msg:
                continue
            _state["last_honeypot_log_id"] = msg
            save_state()
            send_discord_raw("[WARNING] Honeypot Triggered", f"Honeypot port 22 hit. Log: {msg}", 15105570, ping=True)

def _check_hourly_report():
    now = datetime.now()
    if now.minute != 0:
        return
    last = _state.get("last_hourly_sent", 0)
    if int(time.time()) - last < 3600:
        return
    _state["last_hourly_sent"] = int(time.time())
    save_state()
    now_ts = int(time.time())
    hour_ago = now_ts - 3600
    try:
        conn = sqlite3.connect(DB_FILE, timeout=5)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM speedtests WHERE timestamp >= ? AND download < 50.0", (hour_ago,))
        slow_count = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM incidents WHERE timestamp >= ?", (hour_ago,))
        inc_count = c.fetchone()[0]
        conn.close()
        if slow_count > 0 or inc_count > 0:
            send_discord_raw("[INFO] Hourly Report", f"Notable events in the last hour:\nSlow Speedtests: {slow_count}\nIncidents: {inc_count}", 3447003)
    except Exception:
        pass

def _check_wan_ip():
    global _wan_ip_state
    ip = get_mikrotik_data("ip/cloud")
    if ip and isinstance(ip, list) and len(ip) > 0:
        current_ip = ip[0].get("public-address", "")
        if current_ip and _wan_ip_state and current_ip != _wan_ip_state:
            send_discord_raw("[INFO] WAN IP Changed", f"New WAN IP: {current_ip}", 3447003)
        _wan_ip_state = current_ip

@app.route("/api/update_interface", methods=["POST"])
@login_required
def update_interface():
    data = request.json
    name = data.get("name")
    desc = data.get("description", "")
    if not name:
        return jsonify({"status": "error"})
    ifaces = load_ifaces()
    ifaces[name] = desc
    save_ifaces(ifaces)
    return jsonify({"status": "success"})

@app.route("/api/toggle_camera_alerts", methods=["POST"])
@login_required
def toggle_camera_alerts():
    action = request.json.get("action")
    _state["camera_alerts"] = (action == "enable")
    latest_telemetry["camera_alerts"] = _state["camera_alerts"]
    save_state()
    return jsonify({"status": "success"})

def monitor_telemetry():
    last_rx = 0; last_tx = 0; last_time = time.time(); last_write = 0; last_honeypot = 0; last_wan = 0; last_cam = 0
    while True:
        try:
            res = get_mikrotik_data("system/resource")
            if res:
                sys_data = res[0] if isinstance(res, list) else res
                latest_telemetry["system"] = {
                    "uptime": sys_data.get("uptime", "-"), "cpu_load": int(sys_data.get("cpu-load", 0)),
                    "free_memory": int(sys_data.get("free-memory", 0)) // 1024 // 1024,
                    "total_memory": int(sys_data.get("total-memory", 0)) // 1024 // 1024,
                    "board_name": sys_data.get("board-name", "-"), "version": sys_data.get("version", "-"),
                }
            health = get_mikrotik_data("system/health")
            if health and isinstance(health, list):
                for item in health:
                    if item.get("name") == "temperature": latest_telemetry["temp"] = item.get("value", "--"); break
            ifaces = get_mikrotik_data("interface")
            if ifaces:
                ifaces_list = []
                for iface in ifaces:
                    if iface.get("type") in ["ether", "pppoe-out", "bridge"]:
                        ifaces_list.append({
                            "name": iface.get("name"), "rx": int(iface.get("rx-byte", 0)),
                            "tx": int(iface.get("tx-byte", 0)), "running": iface.get("running") == "true", "speed": iface.get("speed", "-"),
                        })
                        if iface.get("name") == "pppoe-wan":
                            cur_rx = int(iface.get("rx-byte", 0)); cur_tx = int(iface.get("tx-byte", 0)); now = time.time(); dt = now - last_time
                            if last_rx != 0 and dt > 0:
                                rx = max(0, round(((cur_rx - last_rx) * 8) / dt / 1_000_000, 2)); tx = max(0, round(((cur_tx - last_tx) * 8) / dt / 1_000_000, 2))
                                latest_telemetry["speed"] = {"rx": rx, "tx": tx}
                            last_rx, last_tx, last_time = cur_rx, cur_tx, now
                descs = load_ifaces()
                for iface in ifaces_list: iface["description"] = descs.get(iface["name"], "Unknown")
                latest_telemetry["interfaces"] = ifaces_list
            ping_res = subprocess.run(["ping", "-c", "1", "-W", "1", "1.1.1.1"], capture_output=True, text=True, timeout=2)
            ping_ms = 0
            if ping_res.returncode == 0:
                for line in ping_res.stdout.split("\n"):
                    if "time=" in line:
                        try: ping_ms = float(line.split("time=")[1].split(" ")[0])
                        except Exception: pass
                        break
            latest_telemetry["ping"] = ping_ms
            now_i = int(time.time())
            if now_i - last_write >= TELEMETRY_WRITE_INTERVAL:
                last_write = now_i
                try:
                    sysinfo = latest_telemetry["system"]
                    cpu = sysinfo["cpu_load"] if sysinfo else 0
                    ram = (sysinfo["total_memory"] - sysinfo["free_memory"]) if sysinfo else 0
                    conn = sqlite3.connect(DB_FILE, timeout=5)
                    try:
                        conn.execute("PRAGMA busy_timeout=5000")
                        conn.execute("INSERT INTO telemetry VALUES (?, ?, ?, ?, ?, ?)", (now_i, cpu, ram, latest_telemetry["speed"]["rx"], latest_telemetry["speed"]["tx"], latest_telemetry["ping"]))
                        conn.commit()
                    finally: conn.close()
                except Exception: pass
        except Exception: pass
        
        now_i = int(time.time())
        
        if now_i - last_honeypot >= 60:
            _check_honeypot()
            last_honeypot = now_i
            
        if now_i - last_wan >= 600:
            _check_wan_ip()
            last_wan = now_i
            
        if now_i - last_cam >= 30:
            _check_cameras()
            last_cam = now_i
            
        _write_heartbeat()
        _maybe_send_daily_report()
        _check_hourly_report()
        time.sleep(2)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        dash_user = (getattr(config, "DASH_USER", "admin") or "admin").strip()
        dash_pass = (getattr(config, "DASH_PASS", "admin") or "admin").strip()
        if request.form.get("username", "").strip() == dash_user and request.form.get("password", "").strip() == dash_pass:
            login_user(User("admin"))
            return redirect(url_for("index"))
        else: flash("Invalid credentials")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout(): logout_user(); return redirect(url_for("login"))

@app.route("/")
@login_required
def index(): return render_template("index.html")

@app.route("/api/stats")
@login_required
def stats(): return jsonify(latest_telemetry)

@app.route("/api/telemetry_history")
@login_required
def telemetry_history():
    time_range = request.args.get("range", "1h"); now = int(time.time())
    if time_range == "1m": start = now - 60; step = 1
    elif time_range == "5m": start = now - 300; step = 1
    elif time_range == "10m": start = now - 600; step = 1
    elif time_range == "30m": start = now - 1800; step = 5
    elif time_range == "1h": start = now - 3600; step = 10
    elif time_range == "6h": start = now - 21600; step = 30
    elif time_range == "24h": start = now - 86400; step = 300
    elif time_range == "7d": start = now - 604800; step = 3600
    else: start = now - 3600; step = 10
    conn = sqlite3.connect(DB_FILE, timeout=5); c = conn.cursor()
    c.execute(f"SELECT (timestamp / {step}) * {step} as t, AVG(cpu), AVG(ram), AVG(wan_rx), AVG(wan_tx), AVG(ping) FROM telemetry WHERE timestamp >= ? GROUP BY t ORDER BY t ASC", (start,))
    rows = c.fetchall(); conn.close()
    data_dict = {}
    for r in rows:
        data_dict[r[0]] = {"cpu": round(r[1], 1) if r[1] is not None else None, "ram": round(r[2], 1) if r[2] is not None else None, "rx": round(r[3], 2) if r[3] is not None else None, "tx": round(r[4], 2) if r[4] is not None else None, "ping": round(r[5], 1) if r[5] is not None else None}
    labels, cpu, ram, rx, tx, ping = [], [], [], [], [], []
    current = (start // step) * step
    while current <= now:
        if step >= 3600: fmt = "%d/%m %H:%M"
        elif step >= 60: fmt = "%H:%M"
        else: fmt = "%H:%M:%S"
        labels.append(datetime.fromtimestamp(current).strftime(fmt))
        if current in data_dict:
            d = data_dict[current]
            cpu.append(d["cpu"]); ram.append(d["ram"]); rx.append(d["rx"]); tx.append(d["tx"]); ping.append(d["ping"])
        else:
            cpu.append(None); ram.append(None); rx.append(None); tx.append(None); ping.append(None)
        current += step
    return jsonify({"labels": labels, "cpu": cpu, "ram": ram, "speedDown": rx, "speedUp": tx, "ping": ping})

@app.route("/api/speedtest_history")
@login_required
def speedtest_history():
    time_range = request.args.get("range", "1h"); now = int(time.time())
    if time_range == "1m": start = now - 60; step = 1
    elif time_range == "5m": start = now - 300; step = 1
    elif time_range == "10m": start = now - 600; step = 1
    elif time_range == "30m": start = now - 1800; step = 5
    elif time_range == "1h": start = now - 3600; step = 10
    elif time_range == "6h": start = now - 21600; step = 30
    elif time_range == "24h": start = now - 86400; step = 300
    elif time_range == "7d": start = now - 604800; step = 3600
    else: start = now - 3600; step = 10
    conn = sqlite3.connect(DB_FILE, timeout=5); c = conn.cursor()
    c.execute(f"SELECT (timestamp / {step}) * {step} as t, AVG(download), AVG(upload) FROM speedtests WHERE timestamp >= ? GROUP BY t ORDER BY t ASC", (start,))
    rows = c.fetchall(); conn.close()
    data_dict = {}
    for r in rows:
        data_dict[r[0]] = {"download": round(r[1], 2) if r[1] is not None else None, "upload": round(r[2], 2) if r[2] is not None else None}
    labels, download, upload = [], [], []
    current = (start // step) * step
    while current <= now:
        if step >= 3600: fmt = "%d/%m %H:%M"
        elif step >= 60: fmt = "%H:%M"
        else: fmt = "%H:%M:%S"
        labels.append(datetime.fromtimestamp(current).strftime(fmt))
        if current in data_dict:
            d = data_dict[current]
            download.append(d["download"]); upload.append(d["upload"])
        else:
            download.append(None); upload.append(None)
        current += step
    return jsonify({"labels": labels, "download": download, "upload": upload})

@app.route("/api/connections")
@login_required
def connections():
    conns = get_mikrotik_data("ip/firewall/connection")
    leases = get_mikrotik_data("ip/dhcp-server/lease")
    arp = get_mikrotik_data("ip/arp")
    bridge_hosts = get_mikrotik_data("interface/bridge/host")
    rules = get_mikrotik_data("ip/firewall/filter")
    custom_names = {}
    if os.path.exists(DEVICES_FILE):
        with open(DEVICES_FILE, "r") as f: custom_names = json.load(f)
    devices = {}
    blocked_ips = set()
    if rules:
        for r in rules:
            c = r.get("comment") or ""
            if c.startswith("BLOCK-"): blocked_ips.add(c.replace("BLOCK-", ""))
    if leases:
        for l in leases:
            ip = l.get("address"); mac = l.get("mac-address", "-").upper()
            if not ip or not mac: continue
            if mac not in devices:
                devices[mac] = {"mac": mac, "ip": ip, "hostname": l.get("host-name", "Unknown"), "connections": [], "total": 0, "all_ips": set()}
            devices[mac]["all_ips"].add(ip)
    if arp:
        for a in arp:
            ip = a.get("address"); mac = a.get("mac-address", "-").upper()
            if not ip or not mac or ip.startswith("192.168.88.255"): continue
            if mac not in devices:
                devices[mac] = {"mac": mac, "ip": ip, "hostname": "Unknown", "connections": [], "total": 0, "all_ips": set()}
            devices[mac]["all_ips"].add(ip)
            if devices[mac]["hostname"] == "Unknown" and a.get("comment"): devices[mac]["hostname"] = a.get("comment")
    ip_to_mac = {}
    for mac, dev in devices.items():
        for ip in dev["all_ips"]: ip_to_mac[ip] = mac
    if conns:
        for c in conns:
            src_ip = c.get("src-address", "").split(":")[0]; dst_ip = c.get("dst-address", "").split(":")[0]
            dst_port = c.get("dst-port", "-"); proto = c.get("protocol", "tcp")
            if src_ip in ip_to_mac and not dst_ip.startswith("192.168.88."):
                mac = ip_to_mac[src_ip]
                conn_key = (dst_ip, dst_port, proto)
                existing = next((item for item in devices[mac]["connections"] if (item["dst"], item["port"], item["proto"]) == conn_key), None)
                if existing: existing["count"] += 1
                else: devices[mac]["connections"].append({"dst": dst_ip, "port": dst_port, "proto": proto, "count": 1})
                devices[mac]["total"] += 1; devices[mac]["ip"] = src_ip
    mac_port = {}
    if bridge_hosts:
        for h in bridge_hosts:
            mac = h.get("mac-address", "").upper()
            if h.get("local") == "false" and h.get("interface") != "bridge": mac_port[mac] = h.get("interface")
    final_list = []
    for mac, dev in devices.items():
        port = mac_port.get(mac, "WiFi/Idle"); ip = dev["ip"]
        if mac in custom_names: display_name = custom_names[mac]; is_trusted = True
        elif dev["hostname"] != "Unknown": display_name = dev["hostname"]; is_trusted = True
        else: display_name = MAC_VENDORS.get(mac.upper()[0:8], "Unknown Vendor"); is_trusted = False
        dev["connections"].sort(key=lambda x: x["count"], reverse=True)
        is_blocked = any(ip in blocked_ips for ip in dev["all_ips"])
        final_list.append({"device": display_name, "ip": ip, "mac": mac, "port": port, "trusted": is_trusted, "connections": dev["connections"], "total": dev["total"], "blocked": is_blocked})
    grouped_by_name = {}; unknown_devices = []
    for dev in final_list:
        if dev["device"] not in ["Unknown", "Randomized MAC (Phone/Tablet)"] and "Unknown Vendor" not in dev["device"]:
            grouped_by_name.setdefault(dev["device"], []).append(dev)
        else: unknown_devices.append(dev)
    merged_devices = []
    for name, group in grouped_by_name.items():
        active_devices = [d for d in group if d["total"] > 0]
        if len(active_devices) == 1:
            primary = active_devices[0]
            for d in group:
                if d is not primary:
                    primary["total"] += d["total"]; primary["connections"].extend(d["connections"])
                    primary["mac"] += f" (Ghost: {d['mac']})"
            merged_devices.append(primary)
        else: merged_devices.extend(group)
    merged_devices.extend(unknown_devices)
    for dev in merged_devices:
        grouped_conns = {}
        for conn in dev["connections"]:
            ck = (conn["dst"], conn["port"], conn["proto"])
            if ck in grouped_conns: grouped_conns[ck]["count"] += conn["count"]
            else: grouped_conns[ck] = conn
        dev["connections"] = sorted(grouped_conns.values(), key=lambda x: x["count"], reverse=True)
    sorted_devices = sorted(merged_devices, key=lambda x: (-x["total"], not x["trusted"]))
    return jsonify(sorted_devices)

@app.route("/api/block_device", methods=["POST"])
@login_required
def block_device():
    ip = request.json.get("ip"); action = request.json.get("action")
    if action == "block": ban_ip(ip, "Manual UI")
    else: unban_ip(ip)
    return jsonify({"status": "success"})

@app.route("/api/rename_device", methods=["POST"])
@login_required
def rename_device():
    mac = request.json.get("mac"); name = request.json.get("name")
    if not mac: return jsonify({"status": "error"})
    custom_names = {}
    if os.path.exists(DEVICES_FILE):
        with open(DEVICES_FILE, "r") as f: custom_names = json.load(f)
    if name: custom_names[mac] = name
    else: custom_names.pop(mac, None)
    _atomic_write_json(DEVICES_FILE, custom_names)
    return jsonify({"status": "success"})

@app.route("/api/device_action", methods=["POST"])
@login_required
def device_action():
    data = request.json; action = data.get("action"); ip = data.get("ip"); mac = data.get("mac")
    if action == "ping":
        try:
            res = subprocess.run(["ping", "-c", "2", "-W", "2", ip], capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                for line in res.stdout.split("\n"):
                    if "rtt min/avg/max/mdev" in line: return jsonify({"result": f"Online - {line.split('/')[4]} ms avg"})
                return jsonify({"result": "Online"})
            return jsonify({"result": "Offline (No response)"})
        except Exception: return jsonify({"result": "Ping failed"})
    elif action == "scan":
        open_ports = []
        for port in [22, 53, 80, 443, 8080, 8291, 8728]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM); sock.settimeout(1.0)
                if sock.connect_ex((ip, port)) == 0: open_ports.append(str(port))
                sock.close()
            except Exception: pass
        if open_ports: return jsonify({"result": f"Open Ports: {', '.join(open_ports)}"})
        return jsonify({"result": "No common ports open"})
    elif action == "wol":
        ssh_cmd = f'ssh admin@{config.ROUTER_IP} "/tool wol mac={mac} interface=bridge"'
        try: subprocess.Popen(ssh_cmd, shell=True); return jsonify({"result": "Magic packet sent"})
        except Exception: return jsonify({"result": "Failed to send WoL"})
    return jsonify({"result": "Unknown action"})

@app.route("/api/lookup_ip", methods=["POST"])
@login_required
def lookup_ip():
    target_ip = request.json.get("ip")
    if not target_ip: return jsonify({"domain": "Invalid IP"})
    dns_cache = get_mikrotik_data("ip/dns/cache")
    if dns_cache:
        for entry in dns_cache:
            if entry.get("data") and target_ip in entry.get("data"): return jsonify({"domain": entry.get("name")})
    return jsonify({"domain": "Unknown (Expired or DoH)"})

@app.route("/api/logs")
@login_required
def logs():
    logs_data = get_mikrotik_data("log")
    if not logs_data: return jsonify([])
    return jsonify([{"time": l.get("time", ""), "topics": l.get("topics", ""), "message": l.get("message", "")} for l in reversed(logs_data[:150])])

@app.route("/api/events")
@login_required
def get_events():
    try:
        conn = sqlite3.connect(DB_FILE, timeout=5); c = conn.cursor()
        c.execute("SELECT timestamp, type, detail, severity FROM incidents ORDER BY timestamp DESC LIMIT 100")
        rows = c.fetchall(); conn.close()
        events = []
        for r in rows:
            events.append({"raw_time": r[0], "time": datetime.fromtimestamp(r[0]).strftime("%d/%m %H:%M:%S"), "type": r[1], "detail": r[2], "severity": r[3]})
        return jsonify(events)
    except Exception: return jsonify([])

@app.route("/api/events/delete", methods=["POST"])
@login_required
def delete_event():
    ts = request.json.get("timestamp")
    if ts:
        conn = sqlite3.connect(DB_FILE, timeout=5); conn.execute("DELETE FROM incidents WHERE timestamp = ?", (ts,)); conn.commit(); conn.close()
    return jsonify({"status": "success"})

@app.route("/api/events/clear", methods=["POST"])
@login_required
def clear_events():
    conn = sqlite3.connect(DB_FILE, timeout=5); conn.execute("DELETE FROM incidents"); conn.commit(); conn.close()
    return jsonify({"status": "success"})

@app.route("/api/speedtest/run", methods=["POST"])
@login_required
def trigger_speedtest():
    threading.Thread(target=run_speedtest).start()
    return jsonify({"status": "started"})

@app.route("/api/report", methods=["POST"])
@login_required
def trigger_report():
    now = int(time.time()); window_start = now - 3600
    label = "Manual Report " + datetime.fromtimestamp(window_start).strftime("%H:%M") + " - " + datetime.fromtimestamp(now).strftime("%H:%M")
    lbl, color, fields = "Manual Report", 3447003, []
    send_discord_raw(lbl, "", color, ping=False, fields=fields)
    return jsonify({"status": "success"})

@app.route("/api/backup", methods=["POST"])
@login_required
def trigger_backup():
    try: subprocess.Popen(["/home/oliveira/rb_auto_backup.sh"]); return jsonify({"status": "success"})
    except Exception as e: return jsonify({"status": "error", "message": str(e)})

@app.route("/api/panic", methods=["POST"])
@login_required
def panic():
    action = request.json.get("action")
    if action == "enable":
        if not rule_exists("PANIC-BLOCK"):
            send_emergency("[ALERT] PANIC BUTTON PRESSED", "Internet access will be blocked for all devices.")
            time.sleep(1); add_rule("forward", None, "pppoe-wan", "PANIC-BLOCK", idempotent=True)
    else:
        remove_rule("PANIC-BLOCK")
        send_emergency("[RESTORED] Internet Restored", "Internet access has been restored.", 3066993)
    return jsonify({"status": "success"})

@app.route("/api/test_alert", methods=["POST"])
@login_required
def test_alert():
    send_emergency("[TEST] Critical Alert", "This is an emergency test message. Telegram only.", 15158332)
    send_emergency("[TEST] Warning", "This is an emergency warning test. Telegram only.", 15105570)
    discord_ids = []
    for title, msg, color in [("[TEST] Info", "Info test message. Discord only.", 3447003), ("[TEST] Success", "Success test message. Discord only.", 3066993), ("[TEST] System", "System notification test. Discord only.", 10181046)]:
        mid = send_discord_raw(title, msg, color, ping=False)
        if mid: discord_ids.append(mid)
        record_incident(title, msg, "success" if "Success" in title else "info")
    def cleanup():
        time.sleep(20)
        for mid in discord_ids:
            webhook_url = getattr(config, "DISCORD_WEBHOOK_URL", "")
            if webhook_url: requests.delete(f"{webhook_url}/messages/{mid}", timeout=3)
    threading.Thread(target=cleanup).start()
    return jsonify({"status": "success"})

@app.route("/api/camera", methods=["POST"])
@login_required
def camera_toggle():
    action = request.json.get("action")
    if action == "enable": add_rule("forward", "ether4", "pppoe-wan", "CAMERA-KILL", idempotent=True)
    else: remove_rule("CAMERA-KILL")
    return jsonify({"status": "success"})

@app.route("/api/bedtime", methods=["POST"])
@login_required
def toggle_bedtime():
    action = request.json.get("action"); rules = get_mikrotik_data("ip/firewall/filter")
    if rules:
        for rule in rules:
            if rule.get("comment") == "Bedtime for Wi-Fi":
                requests.patch(f"{BASE_URL}/ip/firewall/filter/{rule.get('.id')}", auth=AUTH, json={"disabled": "true" if action == "disable" else "false"}, verify=False)
                latest_telemetry["bedtime"] = (action == "enable")
                return jsonify({"status": "success"})
    return jsonify({"status": "error"})

@app.route("/api/bedtime_schedule", methods=["POST"])
@login_required
def update_bedtime_schedule():
    data = request.json; start = data.get("start"); end = data.get("end"); days = data.get("days")
    if not start or not end: return jsonify({"status": "error", "message": "Missing time"})
    def fmt_time(t):
        p = t.split(":"); return f"{int(p[0]):02d}:{int(p[1]):02d}:00"
    if days == "every" or not days: days = "mon,tue,wed,thu,fri,sat,sun"
    time_str = f"{fmt_time(start)}-{fmt_time(end)},{days}"
    rules = get_mikrotik_data("ip/firewall/filter")
    if rules:
        for rule in rules:
            if rule.get("comment") == "Bedtime for Wi-Fi":
                r = requests.patch(f"{BASE_URL}/ip/firewall/filter/{rule.get('.id')}", auth=AUTH, json={"time": time_str}, verify=False)
                if r.status_code == 200:
                    latest_telemetry["bedtime_time"] = f"{start} - {end} (Every Day)" if days == "mon,tue,wed,thu,fri,sat,sun" else f"{start} - {end} ({days})"
                    return jsonify({"status": "success"})
                return jsonify({"status": "error", "message": r.text})
    return jsonify({"status": "error", "message": "Rule not found"})

@app.route("/api/reboot", methods=["POST"])
@login_required
def reboot_router():
    try: requests.post(f"{BASE_URL}/system/reboot", auth=AUTH, verify=False, timeout=1)
    except Exception: pass
    return jsonify({"status": "success"})

@app.route("/api/restart-server", methods=["POST"])
@login_required
def restart_server():
    def restart(): time.sleep(0.5); os.kill(os.getpid(), signal.SIGTERM)
    threading.Thread(target=restart).start()
    return jsonify({"status": "success"})

ssh_client = None
ssh_channel = None
ssh_queue = queue.Queue()

def init_ssh_shell():
    global ssh_client, ssh_channel
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(config.ROUTER_IP, username=config.ROUTER_USER, password=config.ROUTER_PASS, timeout=5)
        ssh_channel = ssh_client.invoke_shell(width=150, height=50)
        ssh_channel.settimeout(0.1)
        
        def reader():
            while True:
                try:
                    if ssh_channel.recv_ready():
                        data = ssh_channel.recv(4096)
                        b64_data = base64.b64encode(data).decode('ascii')
                        ssh_queue.put(b64_data)
                    else:
                        time.sleep(0.05)
                except Exception:
                    break
        threading.Thread(target=reader, daemon=True).start()
    except Exception as e:
        print(f"SSH Terminal init failed: {e}")

@app.route("/api/terminal/stream")
@login_required
def terminal_stream():
    def generate():
        while True:
            try:
                data = ssh_queue.get(timeout=1)
                yield "data: " + data + "\n\n"
            except queue.Empty:
                yield ": ping\n\n"
            except GeneratorExit:
                break
    return Response(generate(), mimetype="text/event-stream")

@app.route("/api/terminal/input", methods=["POST"])
@login_required
def terminal_input():
    global ssh_client, ssh_channel
    if not ssh_client or not ssh_client.get_transport() or not ssh_client.get_transport().is_active():
        init_ssh_shell()
    
    data = request.json.get("data", "")
    try:
        if ssh_channel:
            ssh_channel.send(data)
    except Exception:
        pass
    return jsonify({"status": "success"})

@app.route("/api/terminal/resize", methods=["POST"])
@login_required
def terminal_resize():
    cols = request.json.get("cols", 80)
    rows = request.json.get("rows", 24)
    try:
        if ssh_channel:
            ssh_channel.resize_pty(width=cols, height=rows)
    except Exception:
        pass
    return jsonify({"status": "success"})


@app.route("/api/sync/check")
@login_required
def sync_check():
    diffs = []
    rules = get_mikrotik_data("ip/firewall/filter")
    if rules is None: return jsonify({"error": "Router unreachable"})
    
    router_panic = any(r.get("comment") == "PANIC-BLOCK" for r in rules)
    router_camera = any(r.get("comment") == "CAMERA-KILL" for r in rules)
    router_bedtime = False
    for r in rules:
        if r.get("comment") == "Bedtime for Wi-Fi":
            router_bedtime = r.get("disabled", "false") == "false"
            break
            
    if _state.get("panic", False) != router_panic:
        diffs.append({"key": "panic", "db": _state.get("panic"), "rb": router_panic})
    if _state.get("camera_kill", False) != router_camera:
        diffs.append({"key": "camera_kill", "db": _state.get("camera_kill"), "rb": router_camera})
    if _state.get("bedtime", False) != router_bedtime:
        diffs.append({"key": "bedtime", "db": _state.get("bedtime"), "rb": router_bedtime})
        
    return jsonify(diffs)

@app.route("/api/sync/push", methods=["POST"])
@login_required
def sync_push():
    if _state.get("panic"): add_rule("forward", None, "pppoe-wan", "PANIC-BLOCK", idempotent=True)
    else: remove_rule("PANIC-BLOCK")
    
    if _state.get("camera_kill"): add_rule("forward", "ether4", "pppoe-wan", "CAMERA-KILL", idempotent=True)
    else: remove_rule("CAMERA-KILL")
    
    rules = get_mikrotik_data("ip/firewall/filter")
    if rules:
        for r in rules:
            if r.get("comment") == "Bedtime for Wi-Fi":
                requests.patch(f"{BASE_URL}/ip/firewall/filter/{r.get('.id')}", auth=AUTH, json={"disabled": "false" if _state.get("bedtime") else "true"}, verify=False)
    return jsonify({"status": "success"})

@app.route("/api/sync/pull", methods=["POST"])
@login_required
def sync_pull():
    rules = get_mikrotik_data("ip/firewall/filter")
    if rules:
        _state["panic"] = any(r.get("comment") == "PANIC-BLOCK" for r in rules)
        _state["camera_kill"] = any(r.get("comment") == "CAMERA-KILL" for r in rules)
        for r in rules:
            if r.get("comment") == "Bedtime for Wi-Fi":
                _state["bedtime"] = r.get("disabled", "false") == "false"
                break
    save_state()
    
    latest_telemetry["panic"] = _state["panic"]
    latest_telemetry["camera_kill"] = _state["camera_kill"]
    latest_telemetry["bedtime"] = _state["bedtime"]
    return jsonify({"status": "success"})

def acquire_lock():
    f = open(LOCK_FILE, "w")
    try:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB); f.write(str(os.getpid())); f.flush(); return f
    except BlockingIOError: print("Another dashboard instance is already running. Exiting."); sys.exit(1)

if __name__ == "__main__":
    os.makedirs("data", exist_ok=True)
    lock_handle = acquire_lock()
    load_state()
    init_db()
    init_camera_db()
    startup_catchup()
    sync_go2rtc()
    try:
        latest_telemetry["panic"] = rule_exists("PANIC-BLOCK")
        latest_telemetry["camera_kill"] = rule_exists("CAMERA-KILL")
        latest_telemetry["bedtime"] = get_bedtime_state()
        latest_telemetry["camera_alerts"] = _state.get("camera_alerts", False)
    except Exception as e:
        print(f"State sync at startup failed: {e}")
    threading.Thread(target=init_ssh_shell, daemon=True).start()
    threading.Thread(target=monitor_telemetry, daemon=True).start()
    threading.Thread(target=monitor_speedtest, daemon=True).start()
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)
