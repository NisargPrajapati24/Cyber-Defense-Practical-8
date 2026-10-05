import csv, io, json
from django.http import JsonResponse, HttpResponse
from django.shortcuts import render
from .parser import analyze_text

def index(request):
    return render(request, 'logclassifier/index.html', {'demo': DEMO_LOG})

def analyze(request):
    if request.method != 'POST': return JsonResponse({'error':'POST required'}, status=405)
    text = request.POST.get('raw_logs', '')
    if request.FILES.get('log_file'):
        f = request.FILES['log_file']
        text = f.read().decode('utf-8', errors='replace')
    if not text.strip(): return JsonResponse({'error':'No log data supplied.'}, status=400)
    summary, records = analyze_text(text)
    if request.POST.get('format') == 'json':
        return JsonResponse({'summary': summary, 'records': records})
    if request.POST.get('format') == 'csv':
        out = io.StringIO(); fields = ['line','timestamp','category','severity','score','src_ip','dst_ip','ports','user','method','url','status','event','indicators','raw']
        w = csv.DictWriter(out, fieldnames=fields); w.writeheader()
        for r in records:
            row = r.copy(); row['indicators'] = '; '.join(r['indicators']); w.writerow(row)
        resp = HttpResponse(out.getvalue(), content_type='text/csv'); resp['Content-Disposition']='attachment; filename="classified_logs.csv"'; return resp
    return render(request, 'logclassifier/results.html', {
        'summary': summary,
        'records': records,
        'raw_logs': text,
        'high_critical': summary['severities'].get('HIGH', 0) + summary['severities'].get('CRITICAL', 0),
    })

def health(request):
    return JsonResponse({'status':'ok','service':'Log Parameter Classifier'})

DEMO_LOG = '''2026-10-04 10:01:02 192.168.1.10 - - "GET /index.html HTTP/1.1" 200 5321
2026-10-04 10:02:11 192.168.1.25 sshd[1221]: Failed password for invalid user admin from 10.10.10.44 port 49211 ssh2
2026-10-04 10:03:44 10.10.10.44 DNS query example.com type A response 93.184.216.34 port 53
2026-10-04 10:04:18 192.168.1.50 DHCP REQUEST 192.168.1.50 client_identifier=AA:BB:CC:DD:EE:FF
2026-10-04 10:05:30 smtp MAIL FROM:<alice@example.com> RCPT TO:<bob@example.com> 250 OK
2026-10-04 10:06:09 192.168.1.70 FTP USER admin PASS test123 230 Login successful
2026-10-04 10:07:33 10.0.0.5 GET /../../../../etc/passwd HTTP/1.1 403
2026-10-04 10:08:12 Sysmon EventID=1 Image=C:\\Windows\\System32\\cmd.exe ParentImage=C:\\Windows\\explorer.exe User=user1
'''
