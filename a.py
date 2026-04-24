import psutil
import socket
import requests
import time
import json
import os
from datetime import datetime
from winotify import Notification

# ---------------- CONFIG ----------------
BASELINE_FILE = "baseline.json"
LOG_FILE = "alerts.json"
TRUSTED_IP_FILE = "trusted_ips.txt"
TRUSTED_PROG_FILE = "trusted_programs.txt"

ABUSE_API_KEY = "361b22beee998fbbf32c3856bd6019095668db8db40f26c0e2b57f1c1d863230f2c53f7b5a13f210"  # put your key or leave empty

TRUSTED_ORGS = [
    "google", "cloudflare", "fastly", "akamai",
    "amazon", "microsoft", "meta", "telecom"
]

CHECK_INTERVAL = 5
ALERT_THRESHOLD = 4

# ---------------- HELPERS ----------------

def load_json(path):
    if not os.path.exists(path):
        return {}
    with open(path, "r") as f:
        return json.load(f)

def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def load_set(path):
    if not os.path.exists(path):
        return set()
    with open(path, "r") as f:
        return set(line.strip().lower() for line in f if line.strip())

# ---------------- API ----------------

def get_ip_info(ip):
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=3)
        data = r.json()
        return {
            "org": data.get("org", "Unknown"),
            "country": data.get("country", "Unknown")
        }
    except:
        return {"org": "Unknown", "country": "Unknown"}

def get_abuse_score(ip):
    if not ABUSE_API_KEY:
        return 0
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSE_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=3
        )
        return r.json()["data"]["abuseConfidenceScore"]
    except:
        return 0

# ---------------- AI LOGIC ----------------
def calculate_score(proc, ip, info, abuse_score, baseline, trusted_ips, trusted_progs):
    score = 0

    pname = proc.lower()
    country = info["country"]
    org = (info.get("org") or "").lower()

    BROWSERS = ["brave.exe", "chrome.exe", "msedge.exe", "firefox.exe"]

    # HARD TRUST
    if pname in trusted_progs:
        return 0
    if ip in trusted_ips:
        return 0

    # STRONG TRUST: clean + known infra
    if abuse_score == 0 and any(t in org for t in TRUSTED_ORGS):
        return 0

    # BASELINE (less aggressive)
    if pname not in baseline:
        score += 1
    else:
        if ip not in baseline[pname]["ips"]:
            score += 1  # reduced from 2
        if country not in baseline[pname]["countries"]:
            score += 1  # reduced from 2

    # BROWSER RELAXATION
    if pname in BROWSERS:
        score -= 2  # browsers generate tons of connections

    # REPUTATION (only strong signals matter)
    if abuse_score >= 75:
        score += 4
    elif abuse_score >= 50:
        score += 2

    # SUSPICIOUS ORG (only if unknown AND abuse present)
    if org == "unknown" and abuse_score > 25:
        score += 2

    return max(score, 0)

def update_baseline(proc, ip, info, baseline):
    if proc not in baseline:
        baseline[proc] = {
            "ips": [],
            "countries": []
        }

    if ip not in baseline[proc]["ips"]:
        baseline[proc]["ips"].append(ip)

    if info["country"] not in baseline[proc]["countries"]:
        baseline[proc]["countries"].append(info["country"])

# ---------------- ALERT ----------------

def alert(entry):
    print("\n🚨 ALERT:", entry)

    # Windows notification
    try:
        toast = Notification(
            app_id="AI Sniffer",
            title="Suspicious Connection",
            msg=f"{entry['process']} → {entry['ip']}",
            duration="short"
        )
        toast.show()
    except:
        pass  # don't crash if notifications fail

    # Save logs
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            try:
                logs = json.load(f)
            except:
                logs = []

    logs.append(entry)
    save_json(LOG_FILE, logs)

# ---------------- MAIN ----------------

def monitor():
    baseline = load_json(BASELINE_FILE)
    seen = set()

    while True:
        try:
            trusted_ips = load_set(TRUSTED_IP_FILE)
            trusted_progs = load_set(TRUSTED_PROG_FILE)

            for conn in psutil.net_connections(kind='inet'):
                if not conn.raddr or conn.status != "ESTABLISHED":
                    continue

                ip = conn.raddr.ip

                try:
                    proc = psutil.Process(conn.pid)
                    pname = proc.name()
                except:
                    pname = "unknown"

                key = f"{pname}|{ip}"

                if key in seen:
                    continue

                seen.add(key)

                info = get_ip_info(ip)
                abuse_score = get_abuse_score(ip)

                score = calculate_score(
                    pname, ip, info, abuse_score,
                    baseline, trusted_ips, trusted_progs
                )

                # learn baseline
                update_baseline(pname, ip, info, baseline)
                save_json(BASELINE_FILE, baseline)

                if score >= ALERT_THRESHOLD:
                    entry = {
                        "time": str(datetime.now()),
                        "process": pname,
                        "ip": ip,
                        "org": info["org"],
                        "country": info["country"],
                        "abuse_score": abuse_score,
                        "risk": score
                    }
                    alert(entry)

        except Exception as e:
            print("Error:", e)

        time.sleep(CHECK_INTERVAL)

# ---------------- RUN ----------------

if __name__ == "__main__":
    monitor()
