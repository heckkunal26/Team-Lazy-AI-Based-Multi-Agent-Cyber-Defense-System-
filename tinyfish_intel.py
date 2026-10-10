"""TinyFish integration: a Threat-Intel agent that researches every incident on the live web.
  Search API (free)  -> ranked sources about the attacker IP / attack family
  Fetch API  (free)  -> reads the top pages; an IP-mention gate + keyword evidence yields a bounded reputation score
  Agent API  (credits, analyst-triggered) -> browses AbuseIPDB / MITRE ATT&CK and returns structured JSON
Web content is UNTRUSTED: it only becomes display evidence and a clamped 0-95 score; it can never trigger an action."""
import asyncio, ipaddress, os, re, time
import httpx

SEARCH = os.getenv("TINYFISH_SEARCH_URL", "https://api.search.tinyfish.ai")
FETCH = os.getenv("TINYFISH_FETCH_URL", "https://api.fetch.tinyfish.ai")
AGENT = os.getenv("TINYFISH_AGENT_URL", "https://agent.tinyfish.ai/v1/automation/run")
EVIDENCE = ("malicious", "abuse", "botnet", "brute", "scanner", "scanning", "attack", "blacklist", "blocklist", "reported", "c2", "exploit")
_transport = None                                   # tests inject httpx.MockTransport here
_cache, _sem = {}, None
USAGE = dict(search=0, fetch=0, agent=0, errors=0)

def key(): return os.getenv("TINYFISH_API_KEY", "")
def enabled(): return bool(key())
def _client(t): return httpx.AsyncClient(timeout=t, transport=_transport, headers={"X-API-Key": key()})
def _err(e):                                         # never leak the key; keep messages short
    if isinstance(e, httpx.HTTPStatusError): return f"HTTP {e.response.status_code}" + (" (rate limited, retry later)" if e.response.status_code == 429 else " (add credits/wallet)" if e.response.status_code == 402 else " (check TINYFISH_API_KEY)" if e.response.status_code == 401 else "")
    return type(e).__name__

async def search(query, purpose, **extra):
    USAGE["search"] += 1
    async with _client(20) as c:
        r = await c.get(SEARCH, params={"query": query, "purpose": purpose, **extra}); r.raise_for_status()
    return r.json().get("results", [])
async def fetch(urls, purpose):
    USAGE["fetch"] += 1
    async with _client(150) as c:
        r = await c.post(FETCH, json={"urls": urls[:10], "format": "markdown", "purpose": purpose, "per_url_timeout_ms": 25000}); r.raise_for_status()
    return r.json()
async def agent(url, goal, schema):
    USAGE["agent"] += 1
    async with _client(300) as c:
        r = await c.post(AGENT, json={"url": url, "goal": goal, "output_schema": schema, "browser_profile": "stealth", "agent_config": {"max_duration_seconds": 180}}); r.raise_for_status()
    return r.json()

def public_ips(i):
    out = []
    for ip in i.get("ips", []):
        try:
            if ipaddress.ip_address(ip).is_global: out.append(ip)
        except ValueError: pass
    return out

async def enrich(i):
    """Search + Fetch research for one incident. Returns a dict stored in incident['intel']; never raises."""
    if not enabled(): return dict(status="disabled", note="Set TINYFISH_API_KEY to enable live threat-intel research")
    t0, ips = time.time(), public_ips(i)
    tid = (re.search(r"T\d{4}", i.get("mitre", "")) or [""])[0]
    if ips: q, purpose, extra = f'"{ips[0]}" malicious IP abuse reports', f"SOC analyst checking reputation of IP {ips[0]} seen attacking ({i['family']})", {}
    else: q, purpose, extra = f"{i['family']} network attack detection mitigation {tid}".strip(), f"SOC analyst needs authoritative mitigation guidance for a {i['family']} incident", {"include_domains": "attack.mitre.org,cisa.gov,nist.gov,cert-in.org.in,owasp.org"}
    if q in _cache and time.time() - _cache[q][0] < 600: return {**_cache[q][1], "cached": True}
    global _sem; _sem = _sem or asyncio.Semaphore(2)
    try:
        async with _sem:
            res = await search(q, purpose, **extra)
            src = [dict(title=r.get("title", "")[:140], url=r.get("url", ""), site=r.get("site_name", ""), snippet=(r.get("snippet") or "")[:240]) for r in res[:5] if str(r.get("url", "")).startswith("http")]
            hits, mentioned, fetched = 0, False, 0
            if src:
                page = await fetch([s["url"] for s in src[:2]], purpose); fetched = len(page.get("results", []))
                for p in page.get("results", []):
                    txt = (p.get("text") or "")[:60000].lower() if isinstance(p.get("text"), str) else ""
                    if ips and ips[0] in txt: mentioned = True; hits += min(5, sum(txt.count(k) for k in EVIDENCE))
        out = dict(status="ok", query=q, sources=src, fetched=fetched, ip_mentioned=mentioned, ti=min(95, 15 * hits) if ips else 0, ms=int((time.time() - t0) * 1000))
        _cache[q] = (time.time(), out); return out
    except Exception as e:
        USAGE["errors"] += 1; return dict(status="error", error=_err(e))

IP_SCHEMA = {"type": "object", "properties": {"found": {"type": "boolean"}, "abuse_confidence_score": {"type": "number"}, "total_reports": {"type": "number"}, "country": {"type": "string"}, "isp": {"type": "string"}, "last_reported": {"type": "string"}}, "required": ["found"]}
MIT_SCHEMA = {"type": "object", "properties": {"found": {"type": "boolean"}, "mitigations": {"type": "array", "items": {"type": "string"}}}, "required": ["found"]}
async def deep(i):
    """Agent API: a real browser session. IP incidents -> AbuseIPDB report page; flow incidents -> MITRE mitigations."""
    if not enabled(): return dict(status="disabled")
    ips, tid = public_ips(i), (re.search(r"T\d{4}", i.get("mitre", "")) or [""])[0]
    if ips: url, schema = f"https://www.abuseipdb.com/check/{ips[0]}", IP_SCHEMA; goal = "Read this IP reputation page. Return the abuse confidence score (0-100), total number of reports, country, ISP and the last reported date. If a CAPTCHA or block page appears, return found=false."
    elif tid: url, schema = f"https://attack.mitre.org/techniques/{tid}/", MIT_SCHEMA; goal = "On the Mitigations table of this MITRE ATT&CK technique page, list up to 6 mitigation names with their IDs (e.g. 'M1037 Filter Network Traffic'). If there is no Mitigations table, return found=false."
    else: return dict(status="skipped", note="no public IP or MITRE technique id to investigate")
    try:
        r = await agent(url, goal, schema); res = r.get("result") if isinstance(r.get("result"), dict) else {}
        if "abuse_confidence_score" in res: res["abuse_confidence_score"] = max(0, min(100, float(res["abuse_confidence_score"] or 0)))
        return dict(status="ok" if r.get("status") == "COMPLETED" else "failed", url=url, run_id=r.get("run_id"), steps=r.get("num_of_steps"), result=res, error=(r.get("error") or {}).get("message") if r.get("error") else None)
    except Exception as e:
        USAGE["errors"] += 1; return dict(status="error", url=url, error=_err(e))
