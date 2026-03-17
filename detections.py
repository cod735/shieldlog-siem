import re
from datetime import datetime, timedelta
from collections import defaultdict

# ============================================================
# STATE STORAGE — memory between log lines during one session
# ============================================================
failed_logins_by_ip     = defaultdict(list)   # ip -> [timestamps]
failed_logins_by_user   = defaultdict(list)   # username -> [ip list]
distributed_failures    = defaultdict(list)   # timewindow -> [ips]
sudo_failures_by_user   = defaultdict(int)    # username -> count
login_history_by_user   = defaultdict(set)    # username -> set of known IPs
login_times_by_user     = defaultdict(list)   # username -> [timestamps]
session_opened          = defaultdict(int)    # username -> open session count
hourly_login_counts     = defaultdict(list)   # date_hour -> [timestamps]
multi_service_by_ip     = defaultdict(list)   # ip -> [(timestamp, service)]

# ============================================================
# HELPER FUNCTIONS
# ============================================================
def extract_ip(message):
    match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', message)
    return match.group(1) if match else None

def extract_user(message):
    match = re.search(r'for (\S+) from', message)
    return match.group(1) if match else None

def extract_sudo_user(message):
    match = re.match(r'(\S+)\s+:', message)
    return match.group(1) if match else None

def clean_window(timestamp_list, seconds=60):
    cutoff = datetime.now() - timedelta(seconds=seconds)
    return [t for t in timestamp_list if t > cutoff]

def severity_label(severity):
    labels = {"HIGH": "[HIGH]", "MEDIUM": "[MEDIUM]", "LOW": "[LOW]", "CRITICAL": "[CRITICAL]"}
    return labels.get(severity, "[INFO]")

def make_alert(rule, mitre, severity, detail, event):
    return {
        "rule": rule,
        "mitre": mitre,
        "severity": severity,
        "detail": detail,
        "timestamp": str(event.get("timestamp", "unknown")),
        "host": event.get("host", "unknown"),
        "raw": event.get("raw", ""),
        "event": event
    }

# ============================================================
# CATEGORY 1 — AUTHENTICATION ATTACKS
# ============================================================
def detect_brute_force_ssh(event):
    if "Failed password" not in event["message"]:
        return None
    ip = extract_ip(event["message"])
    if not ip:
        return None
    now = datetime.now()
    failed_logins_by_ip[ip].append(now)
    failed_logins_by_ip[ip] = clean_window(failed_logins_by_ip[ip], 60)
    count = len(failed_logins_by_ip[ip])
    if count >= 5:
        return make_alert(
            "BRUTE_FORCE_SSH", "T1110.001",
            "CRITICAL" if count >= 10 else "HIGH",
            f"{count} failed SSH logins from {ip} in 60 seconds",
            event
        )
    return None

def detect_distributed_brute_force(event):
    if "Failed password" not in event["message"]:
        return None
    ip = extract_ip(event["message"])
    if not ip:
        return None
    now = datetime.now()
    window_key = now.strftime("%Y-%m-%d-%H-%M")
    if ip not in distributed_failures[window_key]:
        distributed_failures[window_key].append(ip)
    unique_ips = len(distributed_failures[window_key])
    if unique_ips >= 5:
        return make_alert(
            "DISTRIBUTED_BRUTE_FORCE", "T1110.003", "CRITICAL",
            f"Failed logins from {unique_ips} different IPs in the same minute — coordinated attack",
            event
        )
    return None

def detect_root_login_attempt(event):
    msg = event["message"]
    if ("Failed password for root" in msg or "Invalid user root" in msg):
        ip = extract_ip(msg)
        return make_alert(
            "ROOT_LOGIN_ATTEMPT", "T1078.003", "HIGH",
            f"Direct root login attempt from {ip} — root SSH should always be disabled",
            event
        )
    return None

def detect_invalid_user(event):
    if "Invalid user" not in event["message"]:
        return None
    match = re.search(r'Invalid user (\S+) from (\S+)', event["message"])
    if not match:
        return None
    username, ip = match.group(1), match.group(2)
    return make_alert(
        "INVALID_USER_LOGIN", "T1110.001", "MEDIUM",
        f"Login attempt for non-existent user '{username}' from {ip} — username enumeration",
        event
    )

def detect_off_hours_login(event):
    msg = event["message"]
    if "Accepted password" not in msg and "Accepted publickey" not in msg:
        return None
    if event["timestamp"] is None:
        return None
    hour = event["timestamp"].hour
    if hour >= 22 or hour < 6:
        ip = extract_ip(msg)
        user = extract_user(msg)
        return make_alert(
            "OFF_HOURS_LOGIN", "T1078", "MEDIUM",
            f"Successful login by '{user}' at {event['timestamp'].strftime('%H:%M')} from {ip} — outside business hours",
            event
        )
    return None

def detect_new_ip_login(event):
    msg = event["message"]
    if "Accepted password" not in msg and "Accepted publickey" not in msg:
        return None
    ip = extract_ip(msg)
    user = extract_user(msg)
    if not ip or not user:
        return None
    if ip not in login_history_by_user[user] and len(login_history_by_user[user]) > 0:
        alert = make_alert(
            "LOGIN_FROM_NEW_IP", "T1078", "MEDIUM",
            f"User '{user}' logged in from new IP {ip} — known IPs: {', '.join(login_history_by_user[user])}",
            event
        )
        login_history_by_user[user].add(ip)
        return alert
    login_history_by_user[user].add(ip)
    return None

def detect_credential_stuffing(event):
    if "Failed password" not in event["message"]:
        return None
    ip = extract_ip(event["message"])
    user = extract_user(event["message"])
    if not ip or not user:
        return None
    failed_logins_by_user[ip].append(user)
    recent_users = failed_logins_by_user[ip][-20:]
    unique_users = len(set(recent_users))
    if unique_users >= 3:
        return make_alert(
            "CREDENTIAL_STUFFING", "T1110.003", "HIGH",
            f"IP {ip} tried {unique_users} different usernames — credential stuffing attack",
            event
        )
    return None

# ============================================================
# CATEGORY 2 — PRIVILEGE ESCALATION
# ============================================================
def detect_suspicious_sudo(event):
    if "sudo" not in event["service"].lower():
        return None
    suspicious = ["/bin/bash", "/bin/sh", "su -", "su\n", "visudo", "passwd", "/bin/zsh", "sudo -i", "sudo -s"]
    for cmd in suspicious:
        if cmd in event["message"]:
            user = extract_sudo_user(event["message"])
            return make_alert(
                "SUSPICIOUS_SUDO", "T1548.003", "HIGH",
                f"User '{user}' ran dangerous sudo command: {event['message'].strip()}",
                event
            )
    return None

def detect_sudo_failure(event):
    if "sudo" not in event["service"].lower():
        return None
    if "incorrect password attempt" not in event["message"].lower() and "authentication failure" not in event["message"].lower():
        return None
    user = extract_sudo_user(event["message"])
    if not user:
        return None
    sudo_failures_by_user[user] += 1
    if sudo_failures_by_user[user] >= 3:
        return make_alert(
            "REPEATED_SUDO_FAILURE", "T1548.003", "MEDIUM",
            f"User '{user}' failed sudo {sudo_failures_by_user[user]} times — unauthorized escalation attempt",
            event
        )
    return None

def detect_sudo_group_add(event):
    msg = event["message"]
    if "usermod" in msg and ("sudo" in msg or "wheel" in msg or "admin" in msg):
        match = re.search(r'COMMAND=.*usermod.*-.*G.*?(sudo|wheel|admin).*?(\S+)', msg)
        target = match.group(2) if match else "unknown"
        return make_alert(
            "USER_ADDED_TO_SUDO_GROUP", "T1098", "CRITICAL",
            f"User added to privileged group — grants permanent root access: {msg.strip()}",
            event
        )
    return None

# ============================================================
# CATEGORY 3 — PERSISTENCE
# ============================================================
def detect_new_user_created(event):
    msg = event["message"].lower()
    if "new user" not in msg and "useradd" not in msg and "adduser" not in msg:
        return None
    name_match = re.search(r'name=(\S+)', event["message"])
    username = name_match.group(1).rstrip(',') if name_match else "unknown"
    return make_alert(
        "NEW_USER_CREATED", "T1136.001", "HIGH",
        f"New user account '{username}' created — potential backdoor account",
        event
    )

def detect_password_changed(event):
    if "sudo" not in event["service"].lower():
        return None
    if "COMMAND" not in event["message"]:
        return None
    if "passwd" in event["message"] and "visudo" not in event["message"]:
        user = extract_sudo_user(event["message"])
        return make_alert(
            "PASSWORD_CHANGED", "T1098.001", "MEDIUM",
            f"Password change command executed by '{user}': {event['message'].strip()}",
            event
        )
    return None

def detect_ssh_key_activity(event):
    msg = event["message"].lower()
    keywords = ["authorized_keys", ".ssh/authorized", "ssh-keygen", "ssh-copy-id"]
    for kw in keywords:
        if kw in msg:
            return make_alert(
                "SSH_KEY_ACTIVITY", "T1098.004", "HIGH",
                f"SSH key file activity detected — attacker may be installing persistent SSH access: {event['message'].strip()}",
                event
            )
    return None

def detect_cron_modification(event):
    msg = event["message"].lower()
    if "cron" not in event["service"].lower():
        return None
    if "session opened" in msg and "root" in msg:
        hour = event["timestamp"].hour if event["timestamp"] else -1
        if hour not in [0, 5, 10, 15, 17, 20, 25, 30, 35, 40, 45, 50, 55]:
            return make_alert(
                "UNUSUAL_CRON_ACTIVITY", "T1053.003", "MEDIUM",
                f"CRON session opened for root at unusual time — possible scheduled persistence",
                event
            )
    return None

# ============================================================
# CATEGORY 4 — RECONNAISSANCE
# ============================================================
def detect_rapid_logins(event):
    msg = event["message"]
    if "Accepted password" not in msg and "Accepted publickey" not in msg:
        return None
    user = extract_user(msg)
    if not user:
        return None
    now = datetime.now()
    login_times_by_user[user].append(now)
    login_times_by_user[user] = clean_window(login_times_by_user[user], 120)
    count = len(login_times_by_user[user])
    if count >= 3:
        return make_alert(
            "RAPID_SUCCESSIVE_LOGINS", "T1078", "MEDIUM",
            f"User '{user}' logged in {count} times in 2 minutes — automated tool suspected",
            event
        )
    return None

def detect_multi_service_scan(event):
    ip = extract_ip(event["message"])
    if not ip:
        return None
    service = event.get("service", "")
    now = datetime.now()
    multi_service_by_ip[ip].append((now, service))
    cutoff = now - timedelta(minutes=5)
    multi_service_by_ip[ip] = [(t, s) for t, s in multi_service_by_ip[ip] if t > cutoff]
    unique_services = set(s for _, s in multi_service_by_ip[ip])
    if len(unique_services) >= 3:
        return make_alert(
            "MULTI_SERVICE_SCAN", "T1046", "HIGH",
            f"IP {ip} accessed {len(unique_services)} different services in 5 min: {', '.join(unique_services)}",
            event
        )
    return None

# ============================================================
# CATEGORY 5 — ANOMALY AND BEHAVIORAL
# ============================================================
def detect_session_never_closed(event):
    msg = event["message"].lower()
    service = event.get("service", "")
    user_match = re.search(r'for user (\S+)', msg)
    if not user_match:
        return None
    user = user_match.group(1).rstrip('(')
    if "session opened" in msg:
        session_opened[user] += 1
    elif "session closed" in msg:
        if session_opened[user] > 0:
            session_opened[user] -= 1
    if session_opened[user] >= 10:
        return make_alert(
            "UNCLOSED_SESSIONS", "T1078", "MEDIUM",
            f"User '{user}' has {session_opened[user]} sessions opened with no matching close — suspicious activity",
            event
        )
    return None

def detect_login_spike(event):
    msg = event["message"]
    if "Failed password" not in msg and "Accepted" not in msg:
        return None
    if event["timestamp"] is None:
        return None
    hour_key = event["timestamp"].strftime("%Y-%m-%d-%H")
    hourly_login_counts[hour_key].append(datetime.now())
    current_count = len(hourly_login_counts[hour_key])
    if current_count >= 20:
        return make_alert(
            "LOGIN_SPIKE_ANOMALY", "T1078", "HIGH",
            f"{current_count} login events in the current hour — abnormal spike detected",
            event
        )
    return None

# ============================================================
# MASTER FUNCTION — runs all detections on every event
# ============================================================
ALL_DETECTIONS = [
    detect_brute_force_ssh,
    detect_distributed_brute_force,
    detect_root_login_attempt,
    detect_invalid_user,
    detect_off_hours_login,
    detect_new_ip_login,
    detect_credential_stuffing,
    detect_suspicious_sudo,
    detect_sudo_failure,
    detect_sudo_group_add,
    detect_new_user_created,
    detect_password_changed,
    detect_ssh_key_activity,
    detect_cron_modification,
    detect_rapid_logins,
    detect_multi_service_scan,
    detect_session_never_closed,
    detect_login_spike,
]

def run_all_detections(event):
    alerts = []
    for detection in ALL_DETECTIONS:
        try:
            result = detection(event)
            if result:
                alerts.append(result)
        except Exception as e:
            pass
    return alerts

# ============================================================
# TEST — run directly to verify all rules fire correctly
# ============================================================
if __name__ == "__main__":
    from parser import parse_log_line

    test_lines = [
        "2026-03-16T02:30:01.000000+05:00 abbaskhan-VMware sshd: Failed password for root from 10.0.0.5 port 22 ssh2",
        "2026-03-16T02:30:04.000000+05:00 abbaskhan-VMware sshd: Failed password for root from 10.0.0.5 port 22 ssh2",
        "2026-03-16T02:30:07.000000+05:00 abbaskhan-VMware sshd: Failed password for root from 10.0.0.5 port 22 ssh2",
        "2026-03-16T02:30:10.000000+05:00 abbaskhan-VMware sshd: Failed password for root from 10.0.0.5 port 22 ssh2",
        "2026-03-16T02:30:13.000000+05:00 abbaskhan-VMware sshd: Failed password for root from 10.0.0.5 port 22 ssh2",
        "2026-03-16T02:30:01.000000+05:00 abbaskhan-VMware sshd: Failed password for admin from 10.0.0.6 port 22 ssh2",
        "2026-03-16T02:30:02.000000+05:00 abbaskhan-VMware sshd: Failed password for admin from 10.0.0.7 port 22 ssh2",
        "2026-03-16T02:30:03.000000+05:00 abbaskhan-VMware sshd: Failed password for admin from 10.0.0.8 port 22 ssh2",
        "2026-03-16T02:30:04.000000+05:00 abbaskhan-VMware sshd: Failed password for admin from 10.0.0.9 port 22 ssh2",
        "2026-03-16T02:30:05.000000+05:00 abbaskhan-VMware sshd: Failed password for admin from 10.0.0.10 port 22 ssh2",
        "2026-03-16T02:30:01.000000+05:00 abbaskhan-VMware sshd: Failed password for root from 10.0.0.5 port 22 ssh2",
        "2026-03-16T02:30:02.000000+05:00 abbaskhan-VMware sshd: Failed password for admin from 10.0.0.5 port 22 ssh2",
        "2026-03-16T02:30:03.000000+05:00 abbaskhan-VMware sshd: Failed password for ubuntu from 10.0.0.5 port 22 ssh2",
        "2026-03-16T02:30:01.000000+05:00 abbaskhan-VMware sshd: Invalid user ghost from 10.0.0.55 port 22",
        "2026-03-16T03:15:00.000000+05:00 abbaskhan-VMware sshd: Accepted password for admin from 203.0.113.42 port 44321 ssh2",
        "2026-03-16T14:30:00.000000+05:00 abbaskhan-VMware sudo: abbaskhan : TTY=pts/0 ; COMMAND=/bin/bash",
        "2026-03-16T14:31:00.000000+05:00 abbaskhan-VMware sudo: abbaskhan : TTY=pts/0 ; COMMAND=/usr/bin/passwd root",
        "2026-03-16T14:32:00.000000+05:00 abbaskhan-VMware useradd: new user: name=backdoor, UID=1001, GID=1001",
        "2026-03-16T14:33:00.000000+05:00 abbaskhan-VMware sudo: abbaskhan : TTY=pts/0 ; COMMAND=/usr/sbin/usermod -aG sudo backdoor",
        "2026-03-16T14:34:00.000000+05:00 abbaskhan-VMware sudo: abbaskhan : TTY=pts/0 ; COMMAND=/usr/bin/ssh-keygen",
    ]

    print("=" * 65)
    print("  ADVANCED DETECTION ENGINE TEST — 18 rules across 5 categories")
    print("=" * 65)

    total_alerts = 0
    for line in test_lines:
        event = parse_log_line(line)
        if not event:
            continue
        alerts = run_all_detections(event)
        for alert in alerts:
            total_alerts += 1
            print(f"\n{severity_label(alert['severity'])} {alert['rule']}")
            print(f"  MITRE   : {alert['mitre']}")
            print(f"  DETAIL  : {alert['detail']}")
            print(f"  TIME    : {alert['timestamp']}")

    print("\n" + "=" * 65)
    print(f"  Total alerts fired: {total_alerts}")
    print("=" * 65)
    