# ShieldLog SIEM — Complete Project Documentation

**Version:** 1.0  
**Author:** Abbas Khan  
**Role:** Cybersecurity Analyst  
**Date:** March 2026  
**GitHub:** https://github.com/cod735/shieldlog-siem  

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Problem Statement](#2-problem-statement)
3. [System Architecture](#3-system-architecture)
4. [Technology Stack](#4-technology-stack)
5. [Installation Guide](#5-installation-guide)
6. [Configuration](#6-configuration)
7. [Detection Rules — Complete Reference](#7-detection-rules--complete-reference)
8. [API Reference](#8-api-reference)
9. [Log Format Guide](#9-log-format-guide)
10. [Dashboard Guide](#10-dashboard-guide)
11. [Testing Guide](#11-testing-guide)
12. [Troubleshooting](#12-troubleshooting)
13. [Security Considerations](#13-security-considerations)
14. [Roadmap — Version 2](#14-roadmap--version-2)
15. [Learning Outcomes](#15-learning-outcomes)

---

## 1. Project Overview

ShieldLog is a real-time Security Information and Event Management (SIEM) system built entirely in Python. It monitors Linux authentication logs continuously, detects suspicious patterns using 18 custom detection rules mapped to the MITRE ATT&CK framework, and presents live alerts through a professional web dashboard.

ShieldLog was built from scratch as a portfolio project to demonstrate detection engineering skills, Python development, Linux system administration, and web application development — all skills directly relevant to SOC Analyst and Cybersecurity Analyst roles.

### What ShieldLog Does

- Watches `/var/log/auth.log` 24 hours a day, 7 days a week
- Parses every new log line into structured data in real time
- Runs 18 detection rules against every event simultaneously
- Fires alerts the moment a suspicious pattern is detected
- Saves all alerts to a persistent JSON store
- Serves a live web dashboard accessible from any browser
- Runs silently as a background service — no terminal required
- Starts automatically every time Ubuntu boots

### Who It Is For

ShieldLog is designed for cybersecurity students, SOC analysts, and system administrators who want to monitor their Linux systems for suspicious activity without paying for enterprise tools like Splunk or IBM QRadar.

---

## 2. Problem Statement

### The Challenge

Linux servers generate thousands of log entries every day. These logs contain critical security information — failed login attempts, privilege escalation events, new account creation, and more. Without automated monitoring, these events go unnoticed.

A real attacker can attempt hundreds of password guesses, create backdoor accounts, and escalate privileges — all recorded in auth.log — while the system owner remains completely unaware.

### The Solution

ShieldLog automates the process that a Tier-1 SOC analyst performs manually. Instead of a human reading log files, ShieldLog reads them in real time, applies security detection logic, and raises alerts immediately when threats are detected.

### Real World Comparison

| Feature | ShieldLog | Splunk | IBM QRadar |
|---|---|---|---|
| Real-time log monitoring | Yes | Yes | Yes |
| MITRE ATT&CK mapping | Yes | Yes | Yes |
| Web dashboard | Yes | Yes | Yes |
| Custom detection rules | Yes | Yes | Yes |
| Cost | Free | $50,000+/year | $100,000+/year |
| Setup complexity | One command | Complex | Very complex |
| Requires Linux knowledge | Yes | No | No |

---

## 3. System Architecture

### High Level Architecture
```
┌─────────────────────────────────────────────────────────┐
│                    Ubuntu Linux Server                   │
│                                                          │
│  /var/log/auth.log ──► parser.py ──► detections.py      │
│                                           │              │
│                                      alerts.json         │
│                                           │              │
│                                       main.py            │
│                                      (Flask)             │
│                                           │              │
│                                  localhost:5000          │
│                                           │              │
│                                    Browser UI            │
└─────────────────────────────────────────────────────────┘
```

### Component Breakdown
```
ShieldLog
│
├── main.py
│   ├── Thread 1 — Log Watcher
│   │   ├── Tails /var/log/auth.log
│   │   ├── Sends each line to parser.py
│   │   ├── Sends parsed event to detections.py
│   │   └── Saves alerts to alerts.json
│   │
│   └── Thread 2 — Flask Web Server
│       ├── GET /          → serves dashboard HTML
│       ├── GET /api/alerts → returns JSON alert list
│       ├── GET /api/stats  → returns summary statistics
│       └── GET /api/clear  → clears all alerts
│
├── parser.py
│   └── parse_log_line(line)
│       ├── Applies regex pattern to raw log line
│       ├── Extracts timestamp, host, service, message
│       └── Returns structured Python dictionary
│
├── detections.py
│   ├── Category 1 — Authentication (7 rules)
│   ├── Category 2 — Privilege Escalation (3 rules)
│   ├── Category 3 — Persistence (4 rules)
│   ├── Category 4 — Reconnaissance (2 rules)
│   ├── Category 5 — Anomaly (2 rules)
│   └── run_all_detections(event) — master function
│
├── templates/
│   └── index.html — complete dashboard UI
│       ├── Metric cards
│       ├── Threat timeline chart (Chart.js)
│       ├── Attack distribution pie chart
│       ├── Live alert table
│       ├── Alert detail modal popup
│       ├── Top rules sidebar
│       └── Recent activity feed
│
├── install.sh     — automated installer
├── uninstall.sh   — clean removal script
└── generate_test_logs.py — attack simulator
```

### Data Flow
```
Step 1: New line written to /var/log/auth.log by Ubuntu
Step 2: Log watcher thread detects new line via readline()
Step 3: Line passed to parse_log_line() in parser.py
Step 4: Parser extracts fields using regex — returns dict
Step 5: Dict passed to run_all_detections() in detections.py
Step 6: All 18 rules checked against the event
Step 7: Matching rules return alert dictionaries
Step 8: Alerts saved to alerts.json and alerts_store list
Step 9: Flask /api/alerts endpoint returns alerts_store
Step 10: Browser fetches /api/alerts every 5 seconds
Step 11: JavaScript renders alerts in dashboard table
```

### Threading Model

ShieldLog uses Python threading to run two processes simultaneously:
```
Main Process
│
├── Thread 1 (daemon=True)
│   └── watch_log() — runs forever, never stops
│       └── reads auth.log → parse → detect → save
│
└── Thread 2 (main thread)
    └── app.run() — Flask web server
        └── responds to browser requests
```

The `daemon=True` flag ensures Thread 1 stops automatically when the main process exits. A `threading.Lock()` protects `alerts_store` from simultaneous read/write operations between threads.

---

## 4. Technology Stack

### Backend

| Technology | Version | Purpose |
|---|---|---|
| Python | 3.10+ | Core programming language |
| Flask | 3.1.3 | Web framework and API server |
| threading | Built-in | Concurrent log watching and web serving |
| re (regex) | Built-in | Log line parsing and IP extraction |
| collections.defaultdict | Built-in | Stateful detection tracking |
| datetime | Built-in | Timestamp parsing and time-window detection |
| json | Built-in | Alert storage and API responses |
| os | Built-in | File system operations |

### Frontend

| Technology | Purpose |
|---|---|
| HTML5 | Dashboard structure |
| CSS3 | Styling — glassmorphism, dark mode, animations |
| JavaScript ES6 | Real-time updates, filtering, modal popup |
| Chart.js 4.4.0 | Timeline chart and pie chart |
| CSS Variables | Theme switching (dark/light mode) |

### System

| Technology | Purpose |
|---|---|
| Ubuntu 22.04+ | Target operating system |
| systemd | Background service management |
| /var/log/auth.log | Linux authentication log source |
| bash | Install and uninstall scripts |

---

## 5. Installation Guide

### Prerequisites

- Ubuntu 22.04 or later
- Python 3.10 or later
- Internet connection for initial setup
- sudo privileges

### Quick Install — One Command
```bash
git clone https://github.com/cod735/shieldlog-siem.git
cd shieldlog-siem
sudo bash install.sh
```

Open browser and go to `http://localhost:5000`

### Manual Install — Step by Step

**Step 1 — Clone the repository**
```bash
git clone https://github.com/cod735/shieldlog-siem.git
cd shieldlog-siem
```

**Step 2 — Create virtual environment**
```bash
python3 -m venv venv
source venv/bin/activate
```

**Step 3 — Install dependencies**
```bash
pip install flask
```

**Step 4 — Run manually to test**
```bash
sudo /path/to/shieldlog-siem/venv/bin/python3 main.py
```

**Step 5 — Install as background service**
```bash
sudo bash install.sh
```

**Step 6 — Verify service is running**
```bash
sudo systemctl status shieldlog
```

### What install.sh Does

The installer performs these steps automatically:
```
1. Checks Python is installed
2. Creates Python virtual environment
3. Installs Flask inside venv
4. Creates /etc/systemd/system/pysiem.service
5. Runs systemctl daemon-reload
6. Runs systemctl enable pysiem
7. Runs systemctl start pysiem
8. Verifies service is active
9. Reports success with dashboard URL
```

### Uninstall
```bash
sudo bash uninstall.sh
```

This stops the service, disables auto-start, and removes the service file. Your project folder remains untouched.

---

## 6. Configuration

All configuration is at the top of `main.py`:
```python
LOG_FILE    = "/var/log/auth.log"   # Log file to monitor
ALERTS_FILE = "alerts.json"         # Where alerts are saved
HOST        = "0.0.0.0"             # Listen on all interfaces
PORT        = 5000                  # Dashboard port
```

### Changing the Port

To run on port 8080 instead of 5000:
```python
PORT = 8080
```

Then restart the service:
```bash
sudo systemctl restart pysiem
```

### Changing Detection Thresholds

All thresholds are in `detections.py`:

| Detection | Variable | Default | Location |
|---|---|---|---|
| Brute force trigger | `>= 5` | 5 failures | detect_brute_force_ssh() |
| Brute force window | `seconds=60` | 60 seconds | clean_window() call |
| Distributed attack | `>= 5` | 5 unique IPs | detect_distributed_brute_force() |
| Off-hours start | `hour >= 22` | 10pm | detect_off_hours_login() |
| Off-hours end | `hour < 6` | 6am | detect_off_hours_login() |
| Sudo failures | `>= 3` | 3 failures | detect_sudo_failure() |
| Unclosed sessions | `>= 10` | 10 sessions | detect_session_never_closed() |
| Login spike | `>= 20` | 20 per hour | detect_login_spike() |

---

## 7. Detection Rules — Complete Reference

### Alert Structure

Every alert produced by ShieldLog has this structure:
```json
{
  "rule":      "RULE_NAME",
  "mitre":     "T0000.000",
  "severity":  "CRITICAL|HIGH|MEDIUM|LOW",
  "detail":    "Human readable description of what was detected",
  "timestamp": "2026-03-17 03:00:13",
  "host":      "hostname",
  "raw":       "original log line"
}
```

### Severity Levels

| Level | Color | Meaning |
|---|---|---|
| CRITICAL | Red glow | Immediate threat — active attack confirmed |
| HIGH | Orange | Strong indicator of attack or compromise |
| MEDIUM | Yellow | Suspicious activity requiring investigation |
| LOW | Blue | Informational — low risk activity |

---

### Category 1 — Authentication Attacks

#### BRUTE_FORCE_SSH
- **MITRE:** T1110.001 — Password Guessing
- **Severity:** CRITICAL (10+ attempts) / HIGH (5+ attempts)
- **Trigger:** 5 or more failed SSH logins from the same IP address within 60 seconds
- **Detection logic:** Stateful — tracks timestamps per IP in `failed_logins_by_ip` dictionary, cleans entries older than 60 seconds on every new event
- **Why it matters:** SSH brute force is the most common attack against Linux servers. Automated tools like Hydra attempt thousands of passwords per minute.
- **Example log line that triggers it:**
```
2026-03-17T03:00:01 server sshd: Failed password for root from 10.0.0.5 port 22 ssh2
```

#### DISTRIBUTED_BRUTE_FORCE
- **MITRE:** T1110.003 — Password Spraying
- **Severity:** CRITICAL
- **Trigger:** Failed logins from 5 or more different IP addresses within the same minute
- **Detection logic:** Tracks unique IPs per minute window using `distributed_failures` dictionary keyed by `YYYY-MM-DD-HH-MM`
- **Why it matters:** Distributed attacks use botnets to spread attempts across many IPs, making single-IP brute force detection ineffective. This rule catches the coordinated pattern.

#### ROOT_LOGIN_ATTEMPT
- **MITRE:** T1078.003 — Local Accounts
- **Severity:** HIGH
- **Trigger:** Any login attempt targeting the root account directly
- **Detection logic:** Stateless — checks for "Failed password for root" or "Invalid user root" in message
- **Why it matters:** Best practice is to disable direct root SSH login entirely. Any root login attempt is inherently suspicious.

#### INVALID_USER_LOGIN
- **MITRE:** T1110.001 — Password Guessing
- **Severity:** MEDIUM
- **Trigger:** Login attempt for a username that does not exist on the system
- **Detection logic:** Matches "Invalid user USERNAME from IP" pattern using regex
- **Why it matters:** Attackers enumerate usernames before launching targeted attacks. Invalid user attempts reveal reconnaissance activity.

#### OFF_HOURS_LOGIN
- **MITRE:** T1078 — Valid Accounts
- **Severity:** MEDIUM
- **Trigger:** Successful login between 10pm and 6am
- **Detection logic:** Checks timestamp hour from parsed event — fires if hour >= 22 or hour < 6
- **Why it matters:** Legitimate users rarely log in at 3am. Off-hours logins may indicate stolen credentials being used by an attacker in a different timezone.

#### LOGIN_FROM_NEW_IP
- **MITRE:** T1078 — Valid Accounts
- **Severity:** MEDIUM
- **Trigger:** A known user successfully logs in from an IP address not seen before
- **Detection logic:** Stateful — maintains `login_history_by_user` set per username, fires when a new IP is seen for an existing user
- **Why it matters:** If an attacker steals credentials and logs in from their own IP, this rule catches the anomaly even if the credentials are correct.

#### CREDENTIAL_STUFFING
- **MITRE:** T1110.003 — Password Spraying
- **Severity:** HIGH
- **Trigger:** Same IP address tries 3 or more different usernames
- **Detection logic:** Stateful — tracks `failed_logins_by_user[ip]` list of usernames tried per IP
- **Why it matters:** Credential stuffing uses leaked password databases to try username/password combinations across many accounts from the same source.

---

### Category 2 — Privilege Escalation

#### SUSPICIOUS_SUDO
- **MITRE:** T1548.003 — Sudo and Sudo Caching
- **Severity:** HIGH
- **Trigger:** Sudo used to run a shell or sensitive command
- **Suspicious commands:** `/bin/bash`, `/bin/sh`, `su -`, `visudo`, `passwd`, `/bin/zsh`, `sudo -i`, `sudo -s`
- **Detection logic:** Checks service is sudo and any suspicious command appears in message
- **Why it matters:** After gaining access, attackers immediately try to get a root shell. `sudo /bin/bash` is one of the most common privilege escalation techniques.

#### REPEATED_SUDO_FAILURE
- **MITRE:** T1548.003 — Sudo and Sudo Caching
- **Severity:** MEDIUM
- **Trigger:** Same user fails sudo authentication 3 or more times
- **Detection logic:** Stateful — increments `sudo_failures_by_user[username]` counter on each failure
- **Why it matters:** A user repeatedly failing sudo may be an attacker who has gained shell access but does not know the sudo password.

#### USER_ADDED_TO_SUDO_GROUP
- **MITRE:** T1098 — Account Manipulation
- **Severity:** CRITICAL
- **Trigger:** usermod command adds a user to sudo, wheel, or admin group
- **Detection logic:** Checks for usermod in message combined with sudo/wheel/admin group names
- **Why it matters:** Adding a user to the sudo group gives them permanent root access. This is one of the most dangerous persistence techniques.

---

### Category 3 — Persistence

#### NEW_USER_CREATED
- **MITRE:** T1136.001 — Local Account
- **Severity:** HIGH
- **Trigger:** useradd or adduser command creates a new system user
- **Detection logic:** Checks for "new user", "useradd", or "adduser" in lowercased message
- **Why it matters:** Attackers create new accounts to maintain access even if their initial entry point is closed.

#### PASSWORD_CHANGED
- **MITRE:** T1098.001 — Additional Cloud Credentials
- **Severity:** MEDIUM
- **Trigger:** passwd command executed via sudo
- **Detection logic:** Checks sudo service and passwd in COMMAND field
- **Why it matters:** Changing passwords via sudo can lock out legitimate users or change root password to attacker's chosen value.

#### SSH_KEY_ACTIVITY
- **MITRE:** T1098.004 — SSH Authorized Keys
- **Severity:** HIGH
- **Trigger:** Any activity involving authorized_keys, ssh-keygen, or ssh-copy-id
- **Detection logic:** Checks message for SSH key related keywords
- **Why it matters:** Adding an SSH key to authorized_keys gives an attacker permanent passwordless access that survives password changes.

#### UNUSUAL_CRON_ACTIVITY
- **MITRE:** T1053.003 — Cron Job
- **Severity:** MEDIUM
- **Trigger:** Root cron session opened at an unexpected time
- **Detection logic:** Checks for cron service, session opened, and root user
- **Why it matters:** Attackers add cron jobs to run malicious code on a schedule, maintaining persistence and executing payloads automatically.

---

### Category 4 — Reconnaissance

#### RAPID_SUCCESSIVE_LOGINS
- **MITRE:** T1078 — Valid Accounts
- **Severity:** MEDIUM
- **Trigger:** Same user logs in 3 or more times within 2 minutes
- **Detection logic:** Stateful — tracks `login_times_by_user[username]` with 120 second window
- **Why it matters:** Automated tools testing access or scripted attacks create rapid successive login patterns that humans do not produce naturally.

#### MULTI_SERVICE_SCAN
- **MITRE:** T1046 — Network Service Discovery
- **Severity:** HIGH
- **Trigger:** Same IP address accesses 3 or more different services within 5 minutes
- **Detection logic:** Stateful — tracks `multi_service_by_ip[ip]` list of (timestamp, service) tuples with 5 minute window
- **Why it matters:** Attackers scan for open services before launching targeted attacks. Hitting SSH, FTP, and HTTP from the same IP in minutes indicates reconnaissance.

---

### Category 5 — Anomaly and Behavioral

#### UNCLOSED_SESSIONS
- **MITRE:** T1078 — Valid Accounts
- **Severity:** MEDIUM
- **Trigger:** User accumulates 10 or more PAM sessions opened without matching closed events
- **Detection logic:** Stateful — increments `session_opened[user]` on open, decrements on close
- **Why it matters:** Abnormally high unclosed session counts can indicate session hijacking or zombie processes from malicious activity.

#### LOGIN_SPIKE_ANOMALY
- **MITRE:** T1078 — Valid Accounts
- **Severity:** HIGH
- **Trigger:** 20 or more login events in the current hour
- **Detection logic:** Tracks `hourly_login_counts[date_hour]` list, fires when count exceeds 20
- **Why it matters:** A sudden spike in login activity indicates an automated attack is in progress regardless of whether individual attempts trigger other rules.

---

## 8. API Reference

ShieldLog exposes a REST API served by Flask. All endpoints return JSON.

### GET /

**Description:** Serves the ShieldLog dashboard HTML page  
**Response:** HTML page  
**Example:** Open `http://localhost:5000` in browser

---

### GET /api/alerts

**Description:** Returns all alerts stored in memory, sorted by timestamp descending  
**Response:** JSON array of alert objects  

**Example response:**
```json
[
  {
    "rule": "BRUTE_FORCE_SSH",
    "mitre": "T1110.001",
    "severity": "CRITICAL",
    "detail": "8 failed SSH logins from 10.0.0.5 in 60 seconds",
    "timestamp": "2026-03-17 03:00:13",
    "host": "abbaskhan-VMware-Virtual-Platform",
    "raw": "2026-03-17T03:00:13 server sshd: Failed password for root from 10.0.0.5"
  }
]
```

---

### GET /api/stats

**Description:** Returns summary statistics for the dashboard metric cards  
**Response:** JSON object  

**Example response:**
```json
{
  "total": 51,
  "critical": 3,
  "high": 19,
  "medium": 29,
  "low": 0,
  "unique_ips": 3,
  "top_rules": [
    ["UNCLOSED_SESSIONS", 24],
    ["ROOT_LOGIN_ATTEMPT", 10],
    ["BRUTE_FORCE_SSH", 6]
  ],
  "last_updated": "2026-03-17 07:12:41"
}
```

---

### GET /api/clear

**Description:** Clears all alerts from memory and resets alerts.json  
**Response:** JSON confirmation  

**Example response:**
```json
{"status": "cleared"}
```

---

## 9. Log Format Guide

### Ubuntu 22.04+ Log Format

ShieldLog is built for the modern Ubuntu auth.log format:
```
2026-03-16T14:42:57.823452+05:00 hostname service: message
```

| Field | Example | Description |
|---|---|---|
| Timestamp | 2026-03-16T14:42:57.823452+05:00 | ISO 8601 format with microseconds and timezone |
| Hostname | abbaskhan-VMware-Virtual-Platform | System hostname |
| Service | sshd, sudo, useradd, CRON | Process that generated the log |
| Message | Failed password for root from 10.0.0.5 | Event description |

### Regex Pattern Used
```python
pattern = r'(\S+)\s+(\S+)\s+(\S+?):\s+(.*)'
```

| Group | Captures | Example |
|---|---|---|
| Group 1 | Timestamp | 2026-03-16T14:42:57.823452+05:00 |
| Group 2 | Hostname | abbaskhan-VMware-Virtual-Platform |
| Group 3 | Service | sudo |
| Group 4 | Message | abbaskhan : COMMAND=/usr/bin/tail |

### Common Log Patterns

**Failed SSH login:**
```
sshd: Failed password for USERNAME from IP port PORT ssh2
```

**Successful SSH login:**
```
sshd: Accepted password for USERNAME from IP port PORT ssh2
```

**Sudo command:**
```
sudo: USERNAME : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/path/to/command
```

**New user created:**
```
useradd: new user: name=USERNAME, UID=1001, GID=1001
```

**CRON session:**
```
CRON: pam_unix(cron:session): session opened for user root
```

---

## 10. Dashboard Guide

### Accessing the Dashboard

Open any browser and go to:
```
http://localhost:5000
```

From another device on the same network:
```
http://YOUR_UBUNTU_IP:5000
```

Find your Ubuntu IP with:
```bash
hostname -I
```

### Dashboard Sections

**Top Bar**
- ShieldLog logo and SIEM Platform subtitle
- LIVE/PAUSED indicator — click to pause live updates
- Last updated timestamp
- Refresh, Settings, and Clear buttons

**Search and Filter Bar**
- Search box — type any rule name, IP address, MITRE ID, or detail text
- Severity filter buttons — All, Critical, High, Medium, Low
- Time range selector — All time, Last 1 hour, Last 6 hours, Last 24 hours

**Metric Cards**
- Total Alerts — all alerts in current session
- Critical — count of CRITICAL severity alerts
- High — count of HIGH severity alerts
- Medium — count of MEDIUM severity alerts
- Low — count of LOW severity alerts
- Unique IPs — count of distinct IP addresses in alerts

**Threat Activity Timeline**
- Line chart showing alert volume over time
- Toggle between 1 hour and 24 hour view
- X axis shows time labels, Y axis shows alert count

**Attack Surface Distribution**
- Doughnut chart showing proportion of each severity level
- Legend shows Critical, High, Medium, Low with colors

**Intrusion Timeline Table**
- Columns: Time, Severity, Rule, MITRE, Detail, Host
- Click any row to open full alert detail popup
- Critical rows highlighted with red left border and glow effect
- New alerts animate in with purple highlight

**Alert Detail Popup**
- Opens when you click any alert row
- Shows severity badge, rule name, MITRE ID, timestamp, host
- MITRE ATT&CK explanation — plain English description of the technique
- Full detail text
- Raw log line that triggered the alert

**Top Attack Rules Sidebar**
- Shows top 5 most fired rules
- Horizontal bar visualization showing relative frequency

**Recent Activity Feed**
- Last 12 alerts in chronological order
- Click any item to open detail popup

### Settings Panel

Click the Settings button in the top bar:

- Light mode toggle — switches between dark and light theme
- Show charts toggle — hide charts for faster loading
- Animate new alerts toggle — enable or disable row animation

---

## 11. Testing Guide

### Method 1 — Simulate Attack with Test Script
```bash
sudo /path/to/shieldlog-siem/venv/bin/python3 generate_test_logs.py
```

This injects 10 fake attack log lines into auth.log simulating:
- SSH brute force from 10.10.10.5
- Off-hours login at 3am
- Suspicious sudo /bin/bash
- New backdoor user creation
- User added to sudo group
- Invalid user enumeration

Watch the dashboard update live as each event is injected.

### Method 2 — Trigger Real Alerts

These commands on your Ubuntu machine trigger real alerts:

**Trigger SUSPICIOUS_SUDO:**
```bash
sudo /bin/bash
# then type: exit
```

**Trigger REPEATED_SUDO_FAILURE:**
```bash
sudo ls
# type wrong password 3 times
```

**Trigger NEW_USER_CREATED:**
```bash
sudo useradd testuser123
# clean up after:
sudo userdel testuser123
```

### Method 3 — Verify API Directly
```bash
curl http://localhost:5000/api/stats
curl http://localhost:5000/api/alerts
```

### Method 4 — Check Service Logs
```bash
sudo journalctl -u pysiem -f
```

This shows real-time output from the ShieldLog service including every alert as it fires.

### Expected Test Results

After running `generate_test_logs.py` you should see:

| Alert | Expected |
|---|---|
| ROOT_LOGIN_ATTEMPT | 5 alerts — one per failed root attempt |
| BRUTE_FORCE_SSH | 1 alert — fires at 5th attempt |
| OFF_HOURS_LOGIN | 1 alert — 3am login |
| SUSPICIOUS_SUDO | 1 alert — /bin/bash command |
| NEW_USER_CREATED | 1 alert — backdoor account |
| USER_ADDED_TO_SUDO_GROUP | 1 alert — privilege grant |
| INVALID_USER_LOGIN | 1 alert — ghost username |

---

## 12. Troubleshooting

### Service Not Starting

**Symptom:** `sudo systemctl status pysiem` shows failed

**Check logs:**
```bash
sudo journalctl -u pysiem -n 50
```

**Common causes:**

| Error | Cause | Fix |
|---|---|---|
| ModuleNotFoundError: flask | Flask not in venv | Run install.sh again |
| Permission denied auth.log | Service not running as root | Check User=root in service file |
| Address already in use | Port 5000 occupied | Run: sudo fuser -k 5000/tcp |
| No such file main.py | Wrong WorkingDirectory | Check path in service file |

---

### Dashboard Not Loading

**Check service is running:**
```bash
sudo systemctl status pysiem
```

**Check port is open:**
```bash
curl http://localhost:5000/api/stats
```

**Check firewall:**
```bash
sudo ufw status
```

If firewall is active allow port 5000:
```bash
sudo ufw allow 5000
```

---

### No Alerts Appearing

**Check auth.log is being written to:**
```bash
sudo tail -5 /var/log/auth.log
```

**Check parser is working:**
```bash
cd ~/shieldlog-siem
source venv/bin/activate
python3 parser.py
```

**Run attack simulator:**
```bash
sudo venv/bin/python3 generate_test_logs.py
```

---

### Port Already in Use
```bash
sudo fuser -k 5000/tcp
sudo systemctl restart pysiem
```

---

### Alerts File Growing Too Large

The alerts.json file grows over time. Clear it from the dashboard using the Clear button, or manually:
```bash
echo "[]" > ~/shieldlog-siem/alerts.json
sudo systemctl restart pysiem
```

---

## 13. Security Considerations

### Important Warnings

ShieldLog is a monitoring tool — not a firewall or intrusion prevention system. It detects and alerts but does not block attacks.

### Recommendations

**1. Do not expose port 5000 to the internet**

ShieldLog dashboard has no authentication. Anyone who can reach port 5000 can see your alerts and clear them. Keep it on localhost or your local network only.

**2. Secure your auth.log**

auth.log contains sensitive login information. ShieldLog reads it as root — ensure only trusted users have sudo access on your system.

**3. Rotate alerts.json regularly**

alerts.json grows indefinitely. Clear it regularly from the dashboard or set up a cron job to rotate it.

**4. Run in a VM or test environment first**

When testing with generate_test_logs.py, fake log lines are written to your real auth.log. This is safe but be aware the file will contain test data.

**5. Add authentication for production use**

For any real deployment, add Flask-Login or HTTP basic auth to protect the dashboard. This is listed in the Version 2 roadmap.

---

## 14. Roadmap — Version 2

### Planned Features

| Feature | Description | Priority |
|---|---|---|
| Dashboard authentication | Login page to protect dashboard | HIGH |
| Email alerts | Send email on CRITICAL severity | HIGH |
| Slack webhook | Post alerts to Slack channel | MEDIUM |
| Windows Event Log support | Monitor Windows .evtx logs | MEDIUM |
| Database storage | SQLite instead of flat JSON | MEDIUM |
| GeoIP lookup | Show attacker country on map | LOW |
| Machine learning anomaly | Baseline normal behavior, flag deviations | LOW |
| Multi-server support | Monitor multiple machines from one dashboard | LOW |
| Alert correlation | Link related alerts into attack chains | LOW |
| PDF report export | Generate security report PDF | LOW |

### Version 2 Architecture Vision
```
Multiple Linux Servers
        │
        ▼
ShieldLog Agents (per server)
        │
        ▼
Central ShieldLog Server
        │
        ▼
Dashboard + Alerts + Reports
```

---

## 15. Learning Outcomes

This project was built to develop and demonstrate the following skills:

### Technical Skills

| Skill | How It Was Applied |
|---|---|
| Python programming | parser.py, detections.py, main.py — 500+ lines |
| Regex | Log line parsing, IP extraction, username extraction |
| Flask web framework | REST API, route handling, template serving |
| Threading | Concurrent log watching and web serving |
| Linux system administration | systemd services, auth.log, file permissions |
| HTML/CSS/JavaScript | Complete dashboard UI with charts and interactivity |
| Git and GitHub | Version control, repository management |
| Bash scripting | install.sh and uninstall.sh automation |

### Security Skills

| Skill | How It Was Applied |
|---|---|
| MITRE ATT&CK framework | All 18 rules mapped to specific techniques |
| Log analysis | Understanding auth.log format and event patterns |
| Detection engineering | Writing rules that balance sensitivity and specificity |
| Threat modeling | Understanding attacker behavior and kill chain |
| SOC operations | Simulating Tier-1 analyst workflow |
| Incident response | Alert triage, severity classification, event correlation |

### Concepts Demonstrated

- Stateful vs stateless detection
- Time-window based anomaly detection
- Behavioral baseline comparison
- Attack chain recognition
- False positive reduction through threshold tuning
- Defense in depth thinking

---

## Document Information

| Field | Value |
|---|---|
| Document title | ShieldLog SIEM — Complete Project Documentation |
| Version | 1.0 |
| Author | Abbas Khan |
| Role | Cybersecurity Analyst |
| Date | March 2026 |
| GitHub | https://github.com/cod735/shieldlog-siem |
| License | MIT |

---

*This documentation was written as part of the ShieldLog SIEM portfolio project. All detection logic, architecture, and implementation was designed and built independently.*