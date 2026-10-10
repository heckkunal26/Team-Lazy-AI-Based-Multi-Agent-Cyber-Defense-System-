"""Team Lazy - Multi-Agent Cyber Defense (production-style build)
Real NSL-KDD-trained models + real log sensors (sshd / nginx / Suricata) + SQLite audit trail + firewall adapters.
Agents: Monitor -> Detect -> Analyse -> Respond -> Report over an async message bus."""
import asyncio, hmac, ipaddress, json, os, platform, random, sqlite3, subprocess, time
from collections import Counter, defaultdict
from contextlib import asynccontextmanager
from pathlib import Path
import joblib, numpy as np, pandas as pd
from fastapi import Depends, FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel
import sensors, tinyfish_intel as tf
from train import COLS, FAMILY, load

ENFORCE = os.getenv("ENFORCE", "0") == "1"                      # real firewall changes only when ENFORCE=1
API_KEY = os.getenv("API_KEY", "")                              # if set, all POST endpoints require X-API-Key
ALLOW = {x for x in os.getenv("ALLOWLIST", "").split(",") if x}  # never block these IPs
BASE = Path(__file__).parent; OUT = BASE / "reports"; OUT.mkdir(exist_ok=True)
def _load():
    try: return joblib.load(BASE / "models" / "model.joblib")
    except Exception as e:                                      # sklearn version mismatch on another machine -> retrain automatically (~25 s)
        print("Model load failed (%s); retraining on NSL-KDD..." % e); subprocess.run([__import__("sys").executable, "train.py"], cwd=BASE, check=True, capture_output=True); return joblib.load(BASE / "models" / "model.joblib")
MODEL = _load(); METRICS = json.load(open(BASE / "models" / "metrics.json"))
PRE, RF, ISO, CLASSES = MODEL["clf"].named_steps["pre"], MODEL["clf"].named_steps["rf"], MODEL["iso"], MODEL["classes"]
RF.n_jobs = 1; ISO.n_jobs = 1; NAMES = MODEL["names"]; CATN = {"protocol_type", "service", "flag"}
MITRE = {"DoS": "T1498 Network Denial of Service (Impact)", "Probe": "T1046 Network Service Discovery (Discovery)", "R2L": "T1110/T1078 Credential Access / Valid Accounts",
         "U2R": "T1068 Exploitation for Privilege Escalation", "Unknown anomaly": "Unclassified behavioural anomaly (analyst review)", "Credential Access": "T1110 Brute Force (Credential Access)",
         "Web Attack": "T1190 Exploit Public-Facing Application (Initial Access)", "Scan": "T1595 Active Scanning (Reconnaissance)", "IDS Alert": "Per Suricata signature"}
BASE_SEV = {"DoS": 70, "Probe": 50, "R2L": 75, "U2R": 90, "Unknown anomaly": 55, "Credential Access": 70, "Web Attack": 70, "Scan": 45, "IDS Alert": 60}
PLAYBOOK = {"DoS": "Enable rate-limiting / SYN cookies; coordinate with ISP; check service health", "Probe": "Review exposed services; tighten firewall rules; watch for follow-up exploitation",
            "R2L": "Enforce MFA; reset exposed credentials; review remote logins", "U2R": "Isolate host, collect forensics, check for new privileged accounts",
            "Unknown anomaly": "Analyst triage: compare against baseline", "Credential Access": "Block source IP; enforce MFA; review auth logs", "Web Attack": "Block source IP; add WAF rule; patch application",
            "Scan": "Block source IP; review exposed paths", "IDS Alert": "Triage signature; block source IP if confirmed"}

# ---------- persistence (SQLite) ----------
DB = sqlite3.connect(os.getenv("DB_PATH", str(BASE / "defense.db")), check_same_thread=False)
DB.execute("CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY, body TEXT)"); DB.execute("CREATE TABLE IF NOT EXISTS audit(ts REAL, actor TEXT, action TEXT, detail TEXT)"); DB.commit()
def audit(actor, action, detail=""): DB.execute("INSERT INTO audit VALUES(?,?,?,?)", (time.time(), actor, action, detail)); DB.commit()
def save(i): DB.execute("INSERT OR REPLACE INTO incidents VALUES(?,?)", (i["id"], json.dumps(i))); DB.commit()
INC = {r[0]: json.loads(r[1]) for r in DB.execute("SELECT id, body FROM incidents")}
ST = dict(flows=0, alerts=0, seq=max(INC, default=0), replay=True, rate=30, tp=0, fp=0, fn=0, tn=0, lat=[], mttr=[], blocked=set())
CLIENTS, Q, DET, BUCKET = set(), {}, sensors.LogDetector(), defaultdict(list)

async def push(m):
    for c in list(CLIENTS):
        try: await c.send_text(json.dumps(m, default=list))
        except Exception: CLIENTS.discard(c)
def stats():
    n = ST["tp"] + ST["fp"] + ST["fn"] + ST["tn"]; P = ST["tp"] / max(ST["tp"] + ST["fp"], 1); R = ST["tp"] / max(ST["tp"] + ST["fn"], 1)
    return dict(flows=ST["flows"], alerts=ST["alerts"], live_n=n, precision=round(P, 3), recall=round(R, 3), acc=round((ST["tp"] + ST["tn"]) / max(n, 1), 3),
                ms=round(float(np.mean(ST["lat"][-50:])), 2) if ST["lat"] else None, mttr=round(float(np.mean(ST["mttr"])), 1) if ST["mttr"] else None,
                tf=dict(enabled=tf.enabled(), **tf.USAGE), blocked=sorted(ST["blocked"]), replay=ST["replay"], rate=ST["rate"], enforce=ENFORCE, auth=bool(API_KEY))
async def bus(frm, to, txt): await push(dict(k="bus", frm=frm, to=to, txt=txt))
async def upd(i): save(i); await push(dict(k="inc", inc=i, stats=stats()))
def now(): return time.strftime("%H:%M:%S")

# ---------- Detect: real ML on flows ----------
def score(df):
    X = np.asarray(PRE.transform(df[COLS]), dtype=float); P = RF.predict_proba(X); iso = -ISO.score_samples(X)
    pn = P[:, CLASSES.index("normal")]; att = np.where(P[:, CLASSES.index("normal")] < .5, 1, 0).astype(bool); P2 = P.copy(); P2[:, CLASSES.index("normal")] = -1
    fam = np.array(CLASSES)[P2.argmax(1)]; unk = (~att) & (iso > MODEL["iso_thr"]); fam = np.where(unk, "Unknown anomaly", fam)
    return X, att | unk, fam, np.where(unk, np.clip(iso, 0, 1), 1 - pn)
def explain(X, df):
    z = (X.mean(0) - MODEL["mu"]) / MODEL["sd"]; idx = [j for j in np.argsort(-np.abs(z)) if NAMES[j] not in CATN][:3]
    why = [f"{NAMES[j]} avg {X[:, j].mean():.2f} vs normal {MODEL['mu'][j]:.2f} (z={z[j]:.1f})" for j in idx]
    return why + [f"top services: {', '.join(f'{k}×{v}' for k, v in Counter(df['service']).most_common(3))}"]
async def detect_agent():
    while True:
        job = await Q["raw"].get()
        if job["kind"] == "log":
            for a in DET.feed(job["ev"]): await Q["alert"].put(a)
            continue
        df, truth = job["df"], job.get("truth"); t = time.perf_counter()
        X, flag, fam, conf = await asyncio.to_thread(score, df); ST["lat"].append((time.perf_counter() - t) * 1000 / len(df)); ST["lat"] = ST["lat"][-200:]
        if truth is not None:
            y = truth != "normal"; ST["tp"] += int((flag & y).sum()); ST["fp"] += int((flag & ~y).sum()); ST["fn"] += int((~flag & y).sum()); ST["tn"] += int((~flag & ~y).sum())
        ST["flows"] += len(df)
        await push(dict(k="flows", rows=[f"{r.protocol_type}/{r.service} {r.flag} src_bytes={r.src_bytes} count={r.count}" + (f"  [{t_}]" if t_ else "") for r, t_ in zip(df.head(6).itertuples(), (truth[:6] if truth is not None else [""] * 6))],
                         flags=[bool(x) for x in flag[:6]], stats=stats()))
        for f in set(fam[flag]):
            m = flag & (fam == f); BUCKET[f].append(dict(X=X[m], df=df[m], conf=float(conf[m].mean()), t=time.time()))
async def flush_agent():
    while True:
        await asyncio.sleep(3)
        for f, items in list(BUCKET.items()):
            n = sum(len(x["X"]) for x in items)
            if n < 3 and time.time() - items[0]["t"] < 9: continue
            del BUCKET[f]
            if n < 3: continue
            X = np.vstack([x["X"] for x in items]); df = pd.concat([x["df"] for x in items])
            await bus("Detect", "Analyse", f"{n} flows classified {f} (RandomForest + IsolationForest)")
            await Q["alert"].put(dict(family=f, source="flows", ips=[], count=n, conf=float(np.mean([x["conf"] for x in items])), why=explain(X, df), t0=items[0]["t"], sev=None))

# ---------- Analyse ----------
BLOCKLIST = set(open(os.getenv("BLOCKLIST_FILE")).read().split()) if os.getenv("BLOCKLIST_FILE") and Path(os.getenv("BLOCKLIST_FILE")).exists() else set()
async def analyse_agent():
    while True:
        a = await Q["alert"].get(); f = a["family"]; ST["alerts"] += 1
        old = next((i for i in INC.values() if i["family"] == f and i["source"] == a["source"] and time.time() - i.get("last", i["t0"]) < 90 and i["status"] != "fp" and ((not a["ips"] and not i["ips"]) or set(i["ips"]) & set(a["ips"]))), None)
        if old:
            old["count"] += a["count"]; old["last"] = time.time(); old["tl"].append([now(), f"Analyse: +{a['count']} events merged into this campaign"]); await upd(old); continue
        ti = 90 if any(ip in BLOCKLIST for ip in a["ips"]) else 0
        sev = a["sev"] or min(100, round(BASE_SEV.get(f, 50) * (.5 + .5 * a["conf"]) + min(20, 3 * np.log2(max(a["count"], 1))) + (.15 * ti)))
        prev = [x for x in INC.values() if a["ips"] and set(x["ips"]) & set(a["ips"]) and time.time() - x["t0"] < 600 and x["status"] != "fp"]
        corr = None
        if prev: sev = min(100, sev + 10 * len(prev)); corr = f"Kill chain: stage {len(prev) + 1} by {a['ips'][0]}, linked to " + ", ".join(f"INC-{x['id']} ({x['family']})" for x in prev)
        ST["seq"] += 1
        i = dict(id=ST["seq"], family=f, source=a["source"], ips=a["ips"], count=a["count"], sev=sev, conf=round(a["conf"], 2), ti=ti, mitre=MITRE.get(f, ""), why=a["why"], corr=corr,
                 playbook=PLAYBOOK.get(f, ""), status="new", t0=a["t0"], sec=None, cmds=[], tl=[[now(), f"Detect: {f} from {a['source']} ({a['count']} events)"], [now(), f"Analyse: MITRE {MITRE.get(f, '-')}, severity {sev}"]])
        if corr: i["tl"].append([now(), "Analyse: " + corr]); await bus("Analyse", "Respond", "MULTI-STAGE ATTACK: " + corr)
        INC[i["id"]] = i; audit("analyse", "incident_created", f"INC-{i['id']} {f} sev={sev}"); await bus("Analyse", "Respond", f"INC-{i['id']} {f} severity {sev}"); await Q["incident"].put(i); await Q["intel"].put(i)

# ---------- Intel (TinyFish Search + Fetch): runs concurrently, never delays containment ----------
async def intel_agent():
    while True:
        i = await Q["intel"].get();
        async def work(i=i):
            await bus("Intel", "Analyse", f"TinyFish researching INC-{i['id']} ({i['family']})")
            r = await tf.enrich(i); i["intel"] = r
            if r["status"] == "ok":
                i["ti"] = max(i["ti"], r["ti"]); i["tl"].append([now(), f"Intel: TinyFish Search+Fetch found {len(r['sources'])} sources" + (f"; IP appears on reputation pages (score {r['ti']})" if r["ti"] else "")]); audit("tinyfish", "enrich", f"INC-{i['id']} {len(r['sources'])} sources")
            elif r["status"] == "error": i["tl"].append([now(), f"Intel: TinyFish error {r['error']} (response unaffected)"])
            await upd(i)
        asyncio.create_task(work())

# ---------- Respond: real firewall adapters, dry-run by default ----------
def block_cmd(ip):
    ipaddress.ip_address(ip)                                    # validates input; no shell is ever used
    if platform.system() == "Windows": return ["netsh", "advfirewall", "firewall", "add", "rule", f"name=LazyBlock-{ip}", "dir=in", "action=block", f"remoteip={ip}"]
    return ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
def blockable(ip):
    return ipaddress.ip_address(ip).is_global and ip not in ALLOW
async def execute(i, who):
    i["cmds"] = []
    for ip in i["ips"][:20]:
        if not blockable(ip): i["cmds"].append(f"SKIP {ip} (internal/non-routable/allow-listed: isolate via EDR instead)"); continue
        c = block_cmd(ip)
        if ENFORCE:
            r = await asyncio.to_thread(subprocess.run, c, capture_output=True, text=True); i["cmds"].append(f"{' '.join(c)} → rc={r.returncode}")
        else: i["cmds"].append("[DRY-RUN] " + " ".join(c))
        ST["blocked"].add(ip)
    i["status"] = "contained"; i["sec"] = round(time.time() - i["t0"], 1); ST["mttr"].append(i["sec"])
    i["tl"].append([now(), f"Respond: {len(i['cmds'])} action(s) by {who}"]); audit(who, "contain", f"INC-{i['id']} {i['cmds']}"); await bus("Respond", "Report", f"INC-{i['id']} contained in {i['sec']}s"); await Q["done"].put(i)
async def respond_agent():
    while True:
        i = await Q["incident"].get()
        if not i["ips"]:                                         # network-flow data carries no IPs -> recommend, analyst acknowledges
            i["status"] = "review"; i["tl"].append([now(), "Respond: no source IP in flow data; playbook recommended, awaiting analyst"]); await upd(i)
        elif i["sev"] >= 85: i["status"] = "pending"; i["tl"].append([now(), "Respond: high severity, awaiting analyst approval"]); await bus("Respond", "Analyst", f"approval needed INC-{i['id']}"); await upd(i)
        else: await execute(i, "auto")
async def report_agent():
    while True:
        i = await Q["done"].get(); i["tl"].append([now(), "Report: incident report written (NIST 800-61 structure)"]); (OUT / f"INC-{i['id']}.md").write_text(report_md(i)); await upd(i)
def report_md(i):
    return (f"# INC-{i['id']}: {i['family']}\n\n- Source: {i['source']} · Events: {i['count']} · IPs: {', '.join(i['ips']) or 'n/a (flow data)'}\n- Severity {i['sev']}/100 · Confidence {i['conf']}\n- MITRE ATT&CK: {i['mitre']}\n- Status: {i['status']} · Time to contain: {i['sec']}s\n"
            f"- Playbook: {i['playbook']}\n\n## Evidence (why it fired)\n" + "\n".join(f"- {w}" for w in i["why"]) + "\n\n## Actions\n" + ("\n".join(f"- `{c}`" for c in i["cmds"]) or "- none") + "\n\n## Timeline\n" + "\n".join(f"- {t} {x}" for t, x in i["tl"]) + "\n")

# ---------- Sources ----------
async def replay_source():
    df = load("KDDTest+.txt").sample(frac=1, random_state=11).reset_index(drop=True); p = 0
    while True:
        await asyncio.sleep(1)
        if not ST["replay"]: continue
        b = df.iloc[p:p + ST["rate"]]; p = (p + ST["rate"]) % (len(df) - 200)
        await Q["raw"].put(dict(kind="flows", df=b, truth=b["family"].values))
async def tail_source(kind, path):
    pos = Path(path).stat().st_size if Path(path).exists() else 0
    while True:
        await asyncio.sleep(1)
        try:
            p = Path(path)
            if not p.exists(): continue
            if p.stat().st_size < pos: pos = 0
            with open(p, "rb") as f:
                f.seek(pos); data = f.read(); pos = f.tell()
            for ln in data.decode("utf-8", "ignore").splitlines():
                ev = sensors.parse(kind, ln)
                if ev: await Q["raw"].put(dict(kind="log", ev=ev))
        except OSError: pass

@asynccontextmanager
async def life(_):
    for t in ("raw", "alert", "incident", "done", "intel"): Q[t] = asyncio.Queue()
    ts = [asyncio.create_task(c()) for c in (detect_agent, flush_agent, analyse_agent, intel_agent, respond_agent, report_agent, replay_source)]
    for spec in filter(None, os.getenv("LOG_SOURCES", "").split(",")):                  # e.g. ssh:/var/log/auth.log,web:/var/log/nginx/access.log,suricata:/var/log/suricata/eve.json
        k, p = spec.split(":", 1); ts.append(asyncio.create_task(tail_source(k, p)))
    yield
    for t in ts: t.cancel()
app = FastAPI(title="Team Lazy Multi-Agent Cyber Defense", lifespan=life)
def auth(x_api_key: str = Header("")):
    if API_KEY and not hmac.compare_digest(x_api_key, API_KEY): raise HTTPException(401, "bad or missing X-API-Key")

@app.get("/")
def index(): return FileResponse(BASE / "static" / "index.html")
@app.websocket("/ws")
async def ws(w: WebSocket):
    await w.accept(); CLIENTS.add(w)
    await w.send_text(json.dumps(dict(k="snap", inc=list(INC.values()), stats=stats(), model=METRICS), default=list))
    try:
        while True: await w.receive_text()
    except WebSocketDisconnect: CLIENTS.discard(w)
def get(id):
    if id not in INC: raise HTTPException(404)
    return INC[id]
@app.post("/api/approve/{id}", dependencies=[Depends(auth)])
async def approve(id: int):
    i = get(id)
    if i["status"] == "pending": i["status"] = "executing"; asyncio.create_task(execute(i, "analyst"))
    elif i["status"] == "review": i["status"] = "acknowledged"; i["sec"] = round(time.time() - i["t0"], 1); i["tl"].append([now(), "Analyst acknowledged; playbook applied manually"]); audit("analyst", "ack", f"INC-{id}"); await Q["done"].put(i)
    else: raise HTTPException(409, "nothing to approve")
    return {"ok": True}
@app.post("/api/reject/{id}", dependencies=[Depends(auth)])
async def reject(id: int):
    i = get(id); i["status"] = "rejected"; i["tl"].append([now(), "Analyst rejected action"]); audit("analyst", "reject", f"INC-{id}"); await upd(i); return {"ok": True}
@app.post("/api/feedback/{id}", dependencies=[Depends(auth)])
async def feedback(id: int):
    i = get(id); i["status"] = "fp"; i["tl"].append([now(), "Analyst marked false positive (stored for the next retraining run)"])
    for ip in i["ips"]: ST["blocked"].discard(ip)
    audit("analyst", "false_positive", f"INC-{id} {i['family']}"); await upd(i); return {"ok": True}
@app.post("/api/investigate/{id}", dependencies=[Depends(auth)])
async def investigate(id: int):
    """Analyst-triggered deep investigation with the TinyFish Agent API (uses credits)."""
    i = get(id)
    if not tf.enabled(): raise HTTPException(503, "Set TINYFISH_API_KEY to enable the TinyFish Agent")
    i["tl"].append([now(), "Intel: TinyFish Agent started (real browser session)"]); await upd(i); await bus("Intel", "Analyst", f"Agent browsing for INC-{id}")
    i["deep"] = await tf.deep(i); d = i["deep"]
    sc = (d.get("result") or {}).get("abuse_confidence_score")
    if sc is not None: i["ti"] = max(i["ti"], int(sc))
    i["tl"].append([now(), f"Intel: TinyFish Agent {d['status']}" + (f", AbuseIPDB confidence {sc}/100" if sc is not None else "")]); audit("tinyfish", "agent_run", f"INC-{id} {d['status']}"); await upd(i); return d
class LogLine(BaseModel): kind: str; line: str
@app.post("/api/ingest/log", dependencies=[Depends(auth)])
async def ingest(l: LogLine):
    """Integration point: ship any log line here (rsyslog/Filebeat/Fluent Bit/curl). kind = ssh | web | suricata"""
    ev = sensors.parse(l.kind, l.line)
    if not ev: return {"parsed": False}
    await Q["raw"].put(dict(kind="log", ev=ev)); return {"parsed": True}
@app.post("/api/replay/{on}", dependencies=[Depends(auth)])
def replay(on: bool, rate: int = 30): ST["replay"] = on; ST["rate"] = max(1, min(rate, 500)); return stats()
@app.get("/api/report/{id}", response_class=PlainTextResponse)
def report(id: int): return report_md(get(id))
@app.get("/api/incidents")
def incidents(): return list(INC.values())
@app.get("/api/audit")
def audit_log(): return [dict(ts=r[0], actor=r[1], action=r[2], detail=r[3]) for r in DB.execute("SELECT * FROM audit ORDER BY ts DESC LIMIT 200")]
@app.get("/api/metrics")
def metrics(): return dict(live=stats(), model=METRICS)
