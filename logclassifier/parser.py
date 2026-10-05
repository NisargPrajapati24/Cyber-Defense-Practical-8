import re
from collections import Counter
from urllib.parse import urlparse

IP_RE = re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])')
PORT_RE = re.compile(r'(?i)\b(?:port|dst_port|dport|src_port|sport)\s*[=:]?\s*(\d{1,5})\b')
USER_RE = re.compile(r'(?i)\b(?:user|username|account|uid)=?[\s:]([A-Za-z0-9_.@-]+)')
TIME_PATTERNS = [
    re.compile(r'\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b'),
    re.compile(r'\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b'),
    re.compile(r'\b\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}\b'),
]

CATEGORY_RULES = {
    'HTTP': [r'\bGET\b', r'\bPOST\b', r'\bPUT\b', r'\bDELETE\b', r'HTTP/\d', r'\b(?:200|201|204|301|302|400|401|403|404|500|502|503)\b'],
    'SSH': [r'\bsshd\b', r'\bssh\b', r'OpenSSH', r'Nmap-SSH', r'Failed password', r'Accepted (?:password|publickey)', r'authentication failure'],
    'DNS': [r'\bdns\b', r'\bquery\b', r'\b(?:A|AAAA|MX|TXT|CNAME|NS)\b', r'\bport\s*53\b'],
    'DHCP': [r'\bdhcp\b', r'\bDISCOVER\b', r'\bOFFER\b', r'\bREQUEST\b', r'\bACK\b', r'\blease\b'],
    'FTP': [r'\bftp\b', r'\bUSER\b', r'\bPASS\b', r'\bRETR\b', r'\bSTOR\b', r'\b230\s+Login'],
    'SMTP': [r'\bsmtp\b', r'\bMAIL FROM\b', r'\bRCPT TO\b', r'\b(?:HELO|EHLO)\b'],
    'TUNNEL': [r'\bGRE\b', r'\b(?:tunnel|encap|encapsulation)\b', r'\b(?:IPv4|IPv6)\b'],
    'WINDOWS/SYSMON': [r'\bSysmon\b', r'EventID\s*[=:]\s*\d+', r'NewProcessId', r'Image=', r'ParentImage='],
    'LINUX/SYSLOG': [r'\b(?:sshd|sudo|cron|systemd|kernel)\b', r'\b(?:auth|daemon|kern|user)\b'],
}

SUSPICIOUS = [
    ('CRITICAL', r'(?i)\b(?:mimikatz|meterpreter|cobaltstrike|ransomware|powershell\s+-enc|encodedcommand)\b', 'Known high-risk tool/technique keyword'),
    ('HIGH', r'(?i)\b(?:failed password|authentication failure|invalid user)\b', 'Authentication failure'),
    ('HIGH', r'(?i)(?:union\s+select|or\s+1\s*=\s*1|drop\s+table|select.+from.+where)', 'Possible SQL injection pattern'),
    ('HIGH', r'(?i)(?:\.\./\.\./|%2e%2e%2f|/etc/passwd|cmd\.exe|powershell\.exe)', 'Possible path traversal or command execution'),
    ('MEDIUM', r'(?i)\b(?:401|403|404|500|502|503)\b', 'HTTP error response'),
    ('MEDIUM', r'(?i)\b(?:scan|nmap|brute.?force|port.?scan)\b', 'Scanning/brute-force indicator'),
    ('LOW', r'(?i)\b(?:denied|blocked|rejected|unauthorized)\b', 'Access-control event'),
]

def valid_ip(ip):
    try:
        return len(ip.split('.')) == 4 and all(0 <= int(x) <= 255 for x in ip.split('.'))
    except Exception:
        return False

def extract_timestamp(raw):
    for p in TIME_PATTERNS:
        m = p.search(raw)
        if m: return m.group(0)
    return ''

def classify_category(raw):
    scores = Counter()
    for cat, patterns in CATEGORY_RULES.items():
        for pat in patterns:
            if re.search(pat, raw, re.I): scores[cat] += 1
    return scores.most_common(1)[0][0] if scores else 'GENERIC'

def extract_method_status_url(raw):
    method = ''
    status = ''
    url = ''
    m = re.search(r'\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT)\s+(\S+)(?:\s+HTTP/\d(?:\.\d)?)?', raw, re.I)
    if m:
        method, url = m.group(1).upper(), m.group(2)
        # Prefer the HTTP status immediately following the request line.
        tail = raw[m.end():]
        s = re.search(r'\b([1-5]\d{2})\b', tail)
        if s:
            status = s.group(1)
    return method, url, status

def extract_ssh_fields(raw):
    """Parse the positional SSH records used by the supplied dataset.

    Format observed in the sample:
    timestamp\tuid\tsrc_ip\tsrc_port\tdst_ip\tdst_port\taction\tdirection\t...
    """
    parts = raw.split('\t')
    if len(parts) < 7:
        return '', '', '', '', ''
    if not valid_ip(parts[2]) or not parts[3].isdigit() or not valid_ip(parts[4]) or not parts[5].isdigit():
        return '', '', '', '', ''
    timestamp = parts[0]
    src_ip, src_port = parts[2], parts[3]
    dst_ip, dst_port = parts[4], parts[5]
    action = parts[6]
    ports = f'{src_port} → {dst_port}'
    return timestamp, src_ip, dst_ip, ports, action

def extract_event(raw):
    for pat in [r'(?i)EventID\s*[=:]\s*(\d+)', r'(?i)event(?:_id)?\s*[=:]\s*([A-Za-z0-9_-]+)', r'(?i)\b(action|event|operation)\s*[=:]\s*([A-Za-z0-9_.-]+)']:
        m = re.search(pat, raw)
        if m: return m.group(m.lastindex)
    return ''

def analyze_line(raw, line_no=1):
    raw = raw.strip('\n')
    ips = [ip for ip in IP_RE.findall(raw) if valid_ip(ip)]
    method, url, status = extract_method_status_url(raw)
    ports = PORT_RE.findall(raw)
    user_m = USER_RE.search(raw)
    ssh_timestamp, ssh_src, ssh_dst, ssh_ports, ssh_action = extract_ssh_fields(raw)
    indicators = []
    severity = 'INFO'
    score = 0
    for sev, pat, reason in SUSPICIOUS:
        if re.search(pat, raw):
            indicators.append(reason)
            weight = {'LOW': 10, 'MEDIUM': 25, 'HIGH': 45, 'CRITICAL': 70}[sev]
            score = max(score, weight)
            if weight > {'INFO':0,'LOW':10,'MEDIUM':25,'HIGH':45,'CRITICAL':70}[severity]: severity = sev
    if status in {'401','403'}:
        score = max(score, 35); severity = 'MEDIUM' if severity == 'INFO' else severity
    if len(ips) >= 2:
        src_ip, dst_ip = ips[0], ips[1]
    elif ips:
        src_ip, dst_ip = ips[0], ''
    else:
        src_ip = dst_ip = ''
    category = classify_category(raw)
    if category == 'SSH' and ssh_src:
        src_ip, dst_ip = ssh_src, ssh_dst
        ports = ssh_ports
        status = ssh_action
    timestamp = ssh_timestamp or extract_timestamp(raw)
    if category == 'GENERIC' and url:
        category = 'HTTP'
    return {
        'line': line_no,
        'timestamp': timestamp,
        'category': category,
        'severity': severity,
        'score': score,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'ports': ports if isinstance(ports, str) else ', '.join(ports),
        'user': user_m.group(1) if user_m else '',
        'method': method,
        'url': url,
        'status': status,
        'event': extract_event(raw),
        'indicators': indicators,
        'raw': raw,
    }

def analyze_text(text):
    lines = [x for x in text.splitlines() if x.strip()]
    records = [analyze_line(line, i) for i, line in enumerate(lines, 1)]
    return build_summary(records), records

def build_summary(records):
    cats = Counter(r['category'] for r in records)
    sevs = Counter(r['severity'] for r in records)
    ips = Counter(r['src_ip'] for r in records if r['src_ip'])
    return {
        'total': len(records),
        'categories': dict(cats),
        'severities': dict(sevs),
        'top_src_ips': ips.most_common(10),
        'suspicious': sum(1 for r in records if r['severity'] in {'MEDIUM','HIGH','CRITICAL'}),
    }
