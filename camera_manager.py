import sqlite3
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

DB_FILE = "cameras.db"

def init_camera_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS cameras 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  name TEXT NOT NULL, 
                  rtsp_url TEXT NOT NULL, 
                  username TEXT, 
                  password BLOB)''')
    conn.commit()
    conn.close()

def get_fernet(secret_key):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b'hex_dashboard_salt', iterations=100000)
    key = base64.urlsafe_b64encode(kdf.derive(secret_key.encode()))
    return Fernet(key)

def add_camera(name, rtsp_url, username, password, secret_key):
    f = get_fernet(secret_key)
    encrypted_pw = f.encrypt(password.encode()) if password else None
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO cameras (name, rtsp_url, username, password) VALUES (?, ?, ?, ?)", 
              (name, rtsp_url, username, encrypted_pw))
    conn.commit()
    conn.close()

def update_camera(cam_id, name, rtsp_url, username, password, secret_key):
    f = get_fernet(secret_key)
    encrypted_pw = f.encrypt(password.encode()) if password else None
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    if encrypted_pw:
        c.execute("UPDATE cameras SET name=?, rtsp_url=?, username=?, password=? WHERE id=?", 
                  (name, rtsp_url, username, encrypted_pw, cam_id))
    else:
        c.execute("UPDATE cameras SET name=?, rtsp_url=?, username=? WHERE id=?", 
                  (name, rtsp_url, username, cam_id))
    conn.commit()
    conn.close()

def get_cameras(secret_key):
    f = get_fernet(secret_key)
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, name, rtsp_url, username, password FROM cameras")
    rows = c.fetchall()
    conn.close()
    
    cams = []
    for r in rows:
        pw = f.decrypt(r[4]).decode() if r[4] else ""
        cams.append({"id": r[0], "name": r[1], "rtsp_url": r[2], "username": r[3], "password": pw})
    return cams

def delete_camera(cam_id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM cameras WHERE id = ?", (cam_id,))
    conn.commit()
    conn.close()
