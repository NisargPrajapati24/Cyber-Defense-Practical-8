# Log Parameter Classifier

A Django-based SIEM-style application that accepts raw logs and categorizes/extracts parameters without Splunk.

## Features
- Paste raw logs or upload `.log`, `.txt`, `.csv`
- Categories: HTTP, SSH, DNS, DHCP, FTP, SMTP, TUNNEL, WINDOWS/SYSMON, LINUX/SYSLOG, GENERIC
- Extracts timestamp, source/destination IP, ports, user, HTTP method/URL/status, EventID/action
- Rule-based security indicators and severity/score
- Results dashboard and CSV export
- `/health/` endpoint

## Run on Windows
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python manage.py runserver
```
Open http://127.0.0.1:8000/

If PowerShell blocks activation, run the command without activation:
```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe manage.py runserver
```

## Run on Linux/Kali
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python manage.py runserver
```

## Architecture
`Browser -> Django View -> Parser/Classifier -> Structured records -> Dashboard/CSV`

The classifier is intentionally deterministic and explainable. It is a foundation that can later be upgraded with ML, threat-intelligence enrichment, Sigma/YARA-style rules, or a database/SIEM connector.
