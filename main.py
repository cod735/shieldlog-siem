import json
import time
import threading
import os
from datetime import datetime
from flask import Flask, jsonify, render_template
from parser import parse_log_line
from detections import run_all_detections

# ============================================================
# CONFIGURATION
# ============================================================
LOG_FILE     = "/var/log/auth.log"
ALERTS_FILE  = "alerts.json"
HOST         = "0.0.0.0"
PORT         = 5000

# ============================================================
# IN-MEMORY ALERT STORE
# keeps last 500 alerts in memory for fast dashboard access
# ============================================================
alerts_store = []
alerts_lock  = threading.Lock()

# ============================================================
# ALERT SAVING
# ============================================================
def save_alert(alert):
    clean_alert = {k: v for k, v in alert.items() if k != "event"}
    
    with alerts_lock:
        alerts_store.append(clean_alert)
        if len(alerts_store) > 500:
            alerts_store.pop(0)
    
    try:
        existing = []
        if os.path.exists(ALERTS_FILE) and os.path.getsize(ALERTS_FILE) > 0:
            with open(ALERTS_FILE, 'r') as f:
                existing = json.load(f)
    except:
        existing = []
    
    existing.append(clean_alert)
    
    with open(ALERTS_FILE, 'w') as f:
        json.dump(existing, f, indent=2, default=str)

# ============================================================
# LOG WATCHER — runs in background thread
# tails auth.log and processes every new line
# ============================================================
def watch_log():
    print(f"[*] Watching {LOG_FILE} for suspicious activity...")
    
    try:
        with open(LOG_FILE, 'r') as f:
            f.seek(0, 2)
            
            while True:
                line = f.readline()
                
                if not line:
                    time.sleep(0.5)
                    continue
                
                event = parse_log_line(line)
                if not event:
                    continue
                
                alerts = run_all_detections(event)
                
                for alert in alerts:
                    save_alert(alert)
                    severity = alert.get("severity", "INFO")
                    rule     = alert.get("rule", "UNKNOWN")
                    detail   = alert.get("detail", "")
                    print(f"[ALERT] [{severity}] {rule} — {detail}")
    
    except PermissionError:
        print(f"[ERROR] Cannot read {LOG_FILE}")
        print(f"[ERROR] Run with: sudo python3 main.py")
    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {LOG_FILE}")
        print(f"[ERROR] Check the LOG_FILE path in main.py")

# ============================================================
# FLASK APP
# ============================================================
app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/alerts')
def get_alerts():
    with alerts_lock:
        sorted_alerts = sorted(
            alerts_store,
            key=lambda x: x.get("timestamp", ""),
            reverse=True
        )
    return jsonify(sorted_alerts)

@app.route('/api/stats')
def get_stats():
    with alerts_lock:
        total    = len(alerts_store)
        critical = sum(1 for a in alerts_store if a.get("severity") == "CRITICAL")
        high     = sum(1 for a in alerts_store if a.get("severity") == "HIGH")
        medium   = sum(1 for a in alerts_store if a.get("severity") == "MEDIUM")
        low      = sum(1 for a in alerts_store if a.get("severity") == "LOW")
        
        unique_ips = set()
        for a in alerts_store:
            detail = a.get("detail", "")
            import re
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', detail)
            if ip_match:
                unique_ips.add(ip_match.group(1))
        
        rules = {}
        for a in alerts_store:
            rule = a.get("rule", "UNKNOWN")
            rules[rule] = rules.get(rule, 0) + 1
        
        top_rules = sorted(rules.items(), key=lambda x: x[1], reverse=True)[:5]
    
    return jsonify({
        "total":      total,
        "critical":   critical,
        "high":       high,
        "medium":     medium,
        "low":        low,
        "unique_ips": len(unique_ips),
        "top_rules":  top_rules,
        "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

@app.route('/api/clear')
def clear_alerts():
    with alerts_lock:
        alerts_store.clear()
    with open(ALERTS_FILE, 'w') as f:
        json.dump([], f)
    return jsonify({"status": "cleared"})

# ============================================================
# STARTUP
# ============================================================
if __name__ == "__main__":
    print("=" * 55)
    print("  PySIEM — Python Security Information & Event Manager")
    print("=" * 55)
    print(f"  Log file  : {LOG_FILE}")
    print(f"  Alerts    : {ALERTS_FILE}")
    print(f"  Dashboard : http://localhost:{PORT}")
    print("=" * 55)
    
    watcher_thread = threading.Thread(target=watch_log, daemon=True)
    watcher_thread.start()
    
    app.run(host=HOST, port=PORT, debug=False)