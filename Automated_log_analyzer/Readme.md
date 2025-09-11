# 🛠️ Automated Log Analyzer & Alerting

A Python-based tool that helps IT admins avoid drowning in logs by **automatically scanning log files**, detecting incidents, and **sending alerts** in real-time.

---

## 🚀 Features
- 📂 Collects logs from **local directories/files** or **remote servers** (via SSH/SFTP using `paramiko`).
- 🔎 Parses logs with **regex** to detect:
  - Failed logins (brute force, invalid users)
  - Service crashes / critical errors
  - Suspicious activity (firewall drops, SQL injection attempts, directory traversal, etc.)
- 💾 Stores results in:
  - **SQLite** database (`events.db`)
  - **CSV** file (`events.csv`)
- 🔔 Sends alerts when thresholds are crossed:
  - **Email** (via SMTP — e.g. Gmail with App Passwords)
  - **Slack** (via Incoming Webhook)
- ⏱️ Runs continuously with `schedule` (scans every N seconds).
- ✅ Handles log rotation & checkpoints (won’t re-scan old lines).

---

## 📦 Installation

### 1. Clone the repo
```bash
git clone https://github.com/yourusername/log-analyzer.git
cd log-analyzer
```
### 2. Create a virtual environment
```bash
python3 -m venv venv
source venv/bin/activate
```
### 3. Install dependencies
```bash
pip install -r requirements.txt
```
If you don’t have requirements.txt yet, the main deps are:

```bash
paramiko
schedule
```
### 4. Configuration
Open log_analyzer.py and edit the CONFIG block near the top:

Local mode
```bash
"MODE": "local",
"LOCAL_PATHS": ["./test.log"],
```
Remote mode
```bash
"MODE": "remote",
"REMOTE_HOSTS": [
    {
        "host": "example.com",
        "port": 22,
        "username": "ubuntu",
        "key_filename": "/home/user/.ssh/id_rsa",
        "paths": ["/var/log/auth.log", "/var/log/syslog"],
    }
],
```
Alerts (Email / Slack)
```bash
"ALERTS": {
    "EMAIL": {
        "ENABLED": True,
        "SMTP_HOST": "smtp.gmail.com",
        "SMTP_PORT": 587,
        "FROM": "youraddress@gmail.com",
        "TO": ["alerts@example.com"],
        "USERNAME": "youraddress@gmail.com",
        "PASSWORD": "your-app-password",  # App Password, not your Gmail login
        "USE_TLS": True,
    },
    "SLACK": {
        "ENABLED": True,
        "WEBHOOK_URL": "https://hooks.slack.com/services/XXX/YYY/ZZZ",
    },
},
```
👉 Gmail users: You must enable 2-Step Verification and generate an App Password.

### 5. Usage
Run the analyzer
```bash
python log_analyzer.py
```
You’ll see periodic scan summaries:

csharp
```bash
[12:34:56] scanning...
[scan] new events this cycle: 4  | counts {'FAILED_LOGIN': 2, 'CRASH': 1, 'SUSPICIOUS': 1}
[ALERT]
[Log Analyzer] Threshold exceeded at 2025-09-08 12:34:56 UTC
- FAILED_LOGIN: 5 (>= 5)  e.g., localhost:./test.log
```
Data storage
- SQLite: ./data/events.db (table events)

- CSV: ./data/events.csv

### 6. Testing with a Sample Log
For quick testing, create a file test.log with the following lines:

```bash
Sep  8 12:15:23 myserver sshd[12345]: Failed password for invalid user admin from 192.168.1.50 port 54022 ssh2
Sep  8 12:21:02 myserver kernel: [12345.67] segmentation fault at 0000000000000000 ip 00007f5c1d2e sp 00007fff
Sep  8 12:25:07 myserver apache2[4444]: GET /index.php?id=1' OR '1'='1 HTTP/1.1" 200 1234 "-" "Mozilla"
```
Point your config to ["./test.log"] and watch the alerts trigger.

### 7. Alert Thresholds
Configured in CONFIG["THRESHOLDS"]:

```bash
"THRESHOLDS": {
    "FAILED_LOGIN": 5,
    "CRASH": 1,
    "SUSPICIOUS": 3,
},
```
If a category count in one scan cycle meets/exceeds its threshold → alert is sent.

### 8. Troubleshooting
externally-managed-environment error → Use a virtualenv:

```bash
python3 -m venv venv && source venv/bin/activate
pip install paramiko schedule
```
Gmail rejects password → You must use an App Password (not your main password).

No alerts showing → Lower thresholds to 1 for quick testing.


### 9. Future Ideas
- GeoIP lookup for failed login IPs

- Dashboard integration (Grafana / Kibana)

- Dockerized deployment

