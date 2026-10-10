"""Real log sensors: parse sshd, nginx/apache access logs and Suricata eve.json lines; detect with per-IP sliding windows."""
import json, os, re, time
from collections import defaultdict, deque

SSH = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\d{1,3}(?:\.\d{1,3}){3})")
WEB = re.compile(r'^(\d{1,3}(?:\.\d{1,3}){3}) \S+ \S+ \[[^\]]+\] "(\S+) (\S+)[^"]*" (\d{3}) ')
ATTACK = re.compile(r"(?i)(union(\s|%20|\+)+select|(\'|%27)(\s|%20|\+)*(or|and)(\s|%20|\+)|information_schema|sleep\(\d+\)|<script|%3cscript|\.\./\.\./|%2e%2e%2f|/etc/passwd|cmd\.exe|wp-login\.php.*xmlrpc)")

def parse(kind, line):
    line = line.strip()
    if kind == "ssh" and (m := SSH.search(line)): return dict(kind="ssh", user=m[1], ip=m[2], line=line)
    if kind == "web" and (m := WEB.match(line)): return dict(kind="web", ip=m[1], method=m[2], path=m[3], status=int(m[4]), line=line)
    if kind == "suricata":
        try: j = json.loads(line)
        except ValueError: return None
        if j.get("event_type") == "alert":
            a = j.get("alert", {}); return dict(kind="suricata", ip=j.get("src_ip"), dst=j.get("dest_ip"), sig=a.get("signature", "IDS alert"), sev=a.get("severity", 2), line=line)
    return None

class LogDetector:
    def __init__(s):
        s.w = defaultdict(deque); s.seen = {}
        s.ssh_n, s.scan_n, s.cool = int(os.getenv("SSH_FAILS", 5)), int(os.getenv("SCAN_4XX", 20)), 120
    def _win(s, key, span):
        w = s.w[key]; t = time.time()
        while w and t - w[0] > span: w.popleft()
        return w
    def _once(s, key):
        if time.time() - s.seen.get(key, 0) < s.cool: return False
        s.seen[key] = time.time(); return True
    def feed(s, ev):
        k, ip, t, out = ev["kind"], ev["ip"], time.time(), []
        def alert(fam, why, conf=.95, n=1, sev=None): out.append(dict(family=fam, source=k, ips=[ip] if ip else [], count=n, conf=conf, why=why, t0=t, sev=sev))
        if k == "ssh":
            w = s._win("ssh" + ip, 60); w.append(t)
            if len(w) >= s.ssh_n and s._once("ssh" + ip): alert("Credential Access", [f"{len(w)} failed SSH logins from {ip} in 60s (user '{ev['user']}')"], n=len(w))
        elif k == "web":
            if ATTACK.search(ev["path"]) and s._once("web" + ip + ev["path"][:30]): alert("Web Attack", [f"Attack signature in request {ev['method']} {ev['path'][:120]}"], .9)
            if ev["status"] in (401, 403, 404):
                w = s._win("scan" + ip, 30); w.append(t)
                if len(w) >= s.scan_n and s._once("scan" + ip): alert("Scan", [f"{len(w)} error responses (401/403/404) from {ip} in 30s: directory/vuln scanning"], .85, len(w))
        elif k == "suricata" and ip and s._once("ids" + ip + ev["sig"]): alert("IDS Alert", [f"Suricata: {ev['sig']}"], .9, sev={1: 90, 2: 70}.get(ev["sev"], 50))
        return out
