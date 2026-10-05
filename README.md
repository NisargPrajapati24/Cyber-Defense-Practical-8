# Cyber Defense Practical 8

## Log Parameter Classification and Analysis System

A Django-based cybersecurity application that analyzes raw log files, automatically categorizes log events, extracts important parameters, and identifies potentially suspicious activities.

The application is designed as a practical **Cyber Defense / SIEM log-analysis project**, where different types of raw security logs can be submitted and transformed into structured, human-readable security events.

---

## 📌 Practical Objective

**To create an application that can categorize various parameters of passed logs.**

The application accepts raw logs as input and performs:

* Log type/category identification
* Parameter extraction
* Event classification
* Security indicator detection
* Severity assessment
* Risk scoring
* Statistical analysis
* CSV export

---

## 🛡️ Features

### 1. Log Upload

Users can upload log files such as:

* `.log`
* `.txt`
* `.csv`

The application reads the uploaded logs and processes individual events.

### 2. Raw Log Input

Logs can also be provided directly through the web interface.

Example:

```text
1331901011.840000	CTHcOo3BARDOPDjYue	192.168.202.68	53633	192.168.28.254	22	failure	INBOUND	SSH-2.0-OpenSSH_5.0	SSH-1.99-Cisco-1.25	-	-	-	-	-
```

The application converts the raw event into structured parameters.

---

## 🔍 Supported Log Categories

The classifier is designed to identify several common log categories:

| Category       | Description                                       |
| -------------- | ------------------------------------------------- |
| SSH            | Secure Shell connection and authentication events |
| HTTP           | Web requests and HTTP response events             |
| DNS            | DNS queries and responses                         |
| DHCP           | DHCP network configuration events                 |
| FTP            | File Transfer Protocol activity                   |
| SMTP           | Email-related network activity                    |
| Tunnel         | Tunnel/network tunneling events                   |
| Syslog/Linux   | Linux and generic system logs                     |
| Windows/Sysmon | Windows security and Sysmon events                |
| Generic        | Logs that cannot be confidently categorized       |

---

## 📊 Parameters Extracted

Depending on the log format, the application extracts parameters such as:

* Timestamp
* Source IP
* Destination IP
* Source Port
* Destination Port
* Username
* HTTP Method
* URL
* HTTP Status
* Event ID
* Event/Action
* Security Indicators
* Severity
* Risk Score
* Raw Log

For example, an SSH event can be represented as:

```text
Category       : SSH
Timestamp      : 1331901011.840000
Source IP      : 192.168.202.68
Source Port    : 53633
Destination IP : 192.168.28.254
Destination Port: 22
Action         : failure
Direction      : INBOUND
```

---

## 🚨 Security Detection

The application performs basic security analysis against the processed logs.

It can identify indicators such as:

* Failed authentication
* Brute-force activity
* SQL injection patterns
* Path traversal
* Command execution
* Suspicious commands
* Scanning activity
* Suspicious HTTP requests
* HTTP errors
* Suspicious tools or payloads

Detected events are assigned a severity level.

### Severity Levels

```text
INFO
LOW
MEDIUM
HIGH
CRITICAL
```

A numerical security/risk score is also associated with suspicious events.

---

## 📈 Analysis Dashboard

After processing the logs, the application displays:

* Total number of events
* Number of suspicious events
* Number of detected categories
* High/Critical events
* Category distribution
* Severity distribution
* Top source IP addresses
* Detailed event information

Example:

```text
Total Events       : 7143
Suspicious Events  : 752

Categories:
    SSH            : 6303
    HTTP           : 840

Severity:
    INFO           : 6391
    MEDIUM         : 752
```

---

## 🏗️ System Architecture

```text
                ┌────────────────────┐
                │      Raw Logs      │
                └─────────┬──────────┘
                          │
                          ▼
                ┌────────────────────┐
                │    Django Web UI   │
                └─────────┬──────────┘
                          │
                          ▼
                ┌────────────────────┐
                │  Log Normalization │
                └─────────┬──────────┘
                          │
                          ▼
                ┌────────────────────┐
                │ Category Detection │
                └─────────┬──────────┘
                          │
                          ▼
                ┌────────────────────┐
                │ Parameter Parser   │
                └─────────┬──────────┘
                          │
                          ▼
                ┌────────────────────┐
                │ Security Analysis  │
                └─────────┬──────────┘
                          │
                          ▼
                ┌────────────────────┐
                │ Severity + Scoring │
                └─────────┬──────────┘
                          │
                          ▼
                ┌────────────────────┐
                │ Analysis Dashboard │
                └────────────────────┘
```

---

## 💻 Technologies Used

* **Python**
* **Django**
* **HTML5**
* **CSS3**
* **JavaScript**
* **Regular Expressions**
* **CSV**
* **SQLite/Django**
* **Cybersecurity log-analysis techniques**

---

## 📁 Project Structure

```text
Log_Parameter_Classifier_Django/
│
├── manage.py
├── requirements.txt
├── README.md
│
├── logclassifier/
│   ├── admin.py
│   ├── apps.py
│   ├── models.py
│   ├── urls.py
│   ├── views.py
│   │
│   ├── templates/
│   │   └── logclassifier/
│   │       ├── index.html
│   │       └── results.html
│   │
│   └── static/
│       └── logclassifier/
│           └── style.css
│
├── logclassifier_project/
│   ├── settings.py
│   ├── urls.py
│   ├── asgi.py
│   └── wsgi.py
│
└── sample_data/
    └── demo_logs.txt
```

---

# ⚙️ Installation

## 1. Clone the Repository

```bash
git clone <YOUR_REPOSITORY_URL>
```

Move into the project directory:

```bash
cd Log_Parameter_Classifier_Django
```

---

## 2. Create a Virtual Environment

### Windows

```powershell
py -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\activate
```

### Linux/macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

---

## 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 4. Apply Django Migrations

```bash
python manage.py migrate
```

---

## 5. Start the Development Server

```bash
python manage.py runserver
```

The application will be available at:

```text
http://127.0.0.1:8000/
```

---

# 🚀 How to Use

### Step 1

Open the application:

```text
http://127.0.0.1:8000/
```

### Step 2

Upload a log file or paste raw logs into the input field.

### Step 3

Submit the logs for analysis.

### Step 4

The application will:

```text
Read Logs
    ↓
Identify Log Type
    ↓
Extract Parameters
    ↓
Analyze Security Indicators
    ↓
Calculate Severity
    ↓
Generate Risk Score
    ↓
Display Results
```

### Step 5

Review the generated analysis dashboard.

The processed results can also be exported as CSV.

---

# 🧪 Example

### Input

```text
1331901011.840000	CTHcOo3BARDOPDjYue	192.168.202.68	53633	192.168.28.254	22	failure	INBOUND	SSH-2.0-OpenSSH_5.0	SSH-1.99-Cisco-1.25	-	-	-	-	-
```

### Output

```text
Category        : SSH
Source IP       : 192.168.202.68
Source Port     : 53633
Destination IP  : 192.168.28.254
Destination Port: 22
Action          : failure
Direction       : INBOUND
Severity        : INFO
```

If multiple failed authentication events originate from the same source, the application can flag the activity for further investigation.

---

# 🔐 Cybersecurity Use Case

The application demonstrates a simplified **SIEM log-processing pipeline**.

In a real SOC environment, logs from multiple sources are collected and normalized before being analyzed for suspicious behavior.

This project demonstrates the same fundamental workflow:

```text
Log Collection
      ↓
Log Parsing
      ↓
Normalization
      ↓
Categorization
      ↓
Parameter Extraction
      ↓
Detection Rules
      ↓
Severity Assignment
      ↓
Security Investigation
```

---

# 🎯 Learning Outcomes

After completing this practical, you should understand:

1. What security logs are.
2. Why log normalization is important.
3. How different log formats contain different parameters.
4. How IP addresses and ports can be extracted from logs.
5. How log categories can be identified.
6. How security indicators can be detected.
7. How severity can be assigned to events.
8. How raw logs can be transformed into structured security data.
9. How a basic SIEM-style log analysis system works.
10. How Django can be used to build a cybersecurity analysis interface.

---

# 📚 Practical Information

**Practical:** 8
**Subject:** Cyber Defense
**Project:** Log Parameter Classification and Analysis System
**Framework:** Django
**Language:** Python

---

## 👨‍💻 Author

**Nisarg Prajapati**

Computer Science Engineering — Cyber Security

---

## ⚠️ Disclaimer

This project is intended for **educational and cybersecurity laboratory purposes**.

Only analyze logs that you are authorized to access and investigate.

---

## ⭐ Acknowledgement

The project uses publicly available sample log data for learning and cybersecurity log-analysis purposes.

If you find this project useful, consider giving the repository a ⭐.
