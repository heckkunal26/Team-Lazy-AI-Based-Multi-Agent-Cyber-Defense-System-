# Team Lazy · Multi-Agent Cyber Defense (Build with Bharat 4.0)

Detects, explains and contains attacks in real time with five cooperating agents
(Monitor → Detect → Analyse → Respond → Report), with a human approving risky actions.

## TinyFish integration (all 3 data/agent APIs)
A 6th agent, **Intel**, researches every incident on the live web using TinyFish, without ever delaying containment:
| TinyFish API | Used for | Cost |
|---|---|---|
| **Search** (`api.search.tinyfish.ai`) | finds reputation/abuse pages for the attacker IP, or CISA/MITRE/NIST/CERT-In guidance for flow incidents | free allowance |
| **Fetch** (`api.fetch.tinyfish.ai`) | reads the top pages; the IP must literally appear on the page, then keyword evidence gives a bounded 0-95 reputation score | free allowance |
| **Agent** (`agent.tinyfish.ai/v1/automation/run`) | analyst clicks **Deep investigate**: a real browser session reads AbuseIPDB (score, reports, country, ISP) or MITRE mitigations and returns structured JSON | credits |

Enable: `set TINYFISH_API_KEY=your_key` (PowerShell: `$env:TINYFISH_API_KEY="your_key"`) before starting uvicorn. Key from agent.tinyfish.ai/api-keys.
Safety: web content is untrusted. It is shown as evidence and clamped to a score; it can never trigger a block. Only public IPs are ever sent out. Without a key the system runs normally with Intel disabled.
Verified: request formats were built from the official docs and checked by 6 mock-server tests (headers, params, bodies). **Not yet run against the live TinyFish servers** (needs your key): test once before the demo.

## What is REAL in this project
| Part | Implementation |
|---|---|
| Dataset | **NSL-KDD** (KDDTrain+ 125,973 flows, KDDTest+ 22,544 flows), real labelled network traffic records |
| ML | RandomForest (normal/DoS/Probe/R2L/U2R) + IsolationForest trained on normal-only flows (unseen anomalies) |
| Held-out result (KDDTest+) | Attack detection **precision 96.7% · recall 66.6% · accuracy 79.7%**; 5-class accuracy 74.1% (`models/metrics.json`) |
| Live sensors | Tails real **sshd**, **nginx/apache** access logs and **Suricata eve.json**; or ship any line to `POST /api/ingest/log` (rsyslog/Filebeat/Fluent Bit) |
| Response | `iptables` (Linux) / `netsh advfirewall` (Windows) adapters; **DRY-RUN by default**, `ENFORCE=1` to act; private IPs and `ALLOWLIST` are never blocked; IPs validated, no shell |
| Governance | SQLite incident store + audit trail (`/api/audit`), API-key on all write endpoints, human approval for sev ≥ 85, NIST 800-61 style reports in `reports/` |
| Intelligence | MITRE ATT&CK mapping, explainable evidence (top deviating features), kill-chain correlation across stages per IP, optional IP blocklist (`BLOCKLIST_FILE`) |

## Run (Windows PowerShell / Linux / Mac)
    pip install -r requirements.txt
    python -m uvicorn main:app --port 8000        # open http://localhost:8000
The dashboard replays real labelled KDDTest+ traffic live and shows **live precision/recall** computed against ground truth.
Retrain from scratch (22 s): `python fetch_data.py` (only if `data/` is missing) then `python train.py`.
Tests: `python -m pytest tests -q` (15 tests).

## Connect real company logs (Linux server)
    set LOG_SOURCES=ssh:/var/log/auth.log,web:/var/log/nginx/access.log,suricata:/var/log/suricata/eve.json   (export on Linux)
    API_KEY=yourkey python -m uvicorn main:app --host 0.0.0.0 --port 8000
Or ship logs from anywhere:
    curl -X POST localhost:8000/api/ingest/log -H "X-API-Key: yourkey" -H "Content-Type: application/json" -d '{"kind":"ssh","line":"...Failed password for root from 45.155.205.9 ..."}'
Docker: `docker compose up --build` (see docker-compose.yml).

## Honest limitations (say these in the pitch)
- NSL-KDD is a 1999-era benchmark (cleaned KDD'99). Modern traffic differs; roadmap: retrain on **CICIDS2017/2018** flows from CICFlowMeter.
- Flow records have no IP addresses, so flow-based incidents are *campaign-level* recommendations the analyst acknowledges; automatic blocking applies to log/IDS sensors that carry IPs.
- Recall on R2L/U2R is low (known hard classes: few training samples, attacks unseen in the training set). The Isolation Forest recovers part of this.
- Message bus is in-process asyncio; scale-out path is Redis Streams/Kafka with the same four topics.
- Human feedback ("false positive") is audit-logged for the next retraining run; the model is not retrained online.


