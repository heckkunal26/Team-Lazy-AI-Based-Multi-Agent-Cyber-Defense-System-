import json, time
import pytest
from fastapi.testclient import TestClient
import main, sensors

PUB = "45.155.205.9"
SSH = "Oct 10 07:41:02 srv sshd[991]: Failed password for root from {ip} port 4422 ssh2"
WEB = '{ip} - - [10/Oct/2026:07:41:02 +0000] "GET /a?id=1%27%20or%201=1-- HTTP/1.1" 200 5 "-" "x"'

@pytest.fixture()
def c():
    main.INC.clear(); main.DET.w.clear(); main.DET.seen.clear(); main.ST["replay"] = False; main.ST["blocked"].clear(); main.API_KEY = ""
    with TestClient(main.app) as c:
        c.post("/api/replay/false"); yield c

def wait(c, pred, t=15):
    end = time.time() + t
    while time.time() < end:
        r = [i for i in c.get("/api/incidents").json() if pred(i)]
        if r: return r
        time.sleep(.3)
    return []

def test_model_quality_on_heldout_real_data():
    m = json.load(open("models/metrics.json"))["binary_ensemble_with_isolation_forest"]
    assert m["precision"] > .9 and m["recall"] > .6 and m["accuracy"] > .75

def test_parsers():
    assert sensors.parse("ssh", SSH.format(ip=PUB))["ip"] == PUB
    assert sensors.parse("web", WEB.format(ip=PUB))["method"] == "GET"
    assert sensors.parse("suricata", json.dumps({"event_type": "alert", "src_ip": PUB, "alert": {"signature": "ET SCAN", "severity": 1}}))["sev"] == 1
    assert sensors.parse("ssh", "garbage") is None

def test_replay_of_real_flows_detects_attacks(c):
    c.post("/api/replay/true?rate=80"); r = wait(c, lambda i: i["source"] == "flows", 20); c.post("/api/replay/false")
    assert r and any(i["family"] in ("DoS", "Probe") for i in r)
    s = c.get("/api/metrics").json()["live"]; assert s["live_n"] > 100 and s["precision"] > .85

def test_real_log_ssh_bruteforce_is_contained_dry_run(c):
    for _ in range(6): c.post("/api/ingest/log", json={"kind": "ssh", "line": SSH.format(ip=PUB)})
    i = wait(c, lambda i: i["family"] == "Credential Access" and i["status"] == "contained")[0]
    assert i["ips"] == [PUB] and i["cmds"][0].startswith("[DRY-RUN]") and PUB in i["cmds"][0]

def test_internal_ip_never_blocked(c):
    for _ in range(6): c.post("/api/ingest/log", json={"kind": "ssh", "line": SSH.format(ip="10.0.0.5")})
    i = wait(c, lambda i: i["ips"] == ["10.0.0.5"] and i["status"] == "contained")[0]; assert i["cmds"][0].startswith("SKIP")
    assert "10.0.0.5" not in main.ST["blocked"]

def test_kill_chain_from_logs(c):
    for _ in range(6): c.post("/api/ingest/log", json={"kind": "ssh", "line": SSH.format(ip=PUB)})
    wait(c, lambda i: i["family"] == "Credential Access"); c.post("/api/ingest/log", json={"kind": "web", "line": WEB.format(ip=PUB)})
    assert wait(c, lambda i: i["family"] == "Web Attack" and i["corr"])

def test_false_positive_and_audit(c):
    for _ in range(6): c.post("/api/ingest/log", json={"kind": "ssh", "line": SSH.format(ip=PUB)})
    i = wait(c, lambda i: i["family"] == "Credential Access")[0]; c.post(f"/api/feedback/{i['id']}")
    assert any(a["action"] == "false_positive" for a in c.get("/api/audit").json()) and PUB not in main.ST["blocked"]

def test_api_key_enforced(c):
    main.API_KEY = "s3cret"
    assert c.post("/api/replay/false").status_code == 401 and c.post("/api/replay/false", headers={"X-API-Key": "s3cret"}).status_code == 200

def test_firewall_command_is_validated():
    assert main.block_cmd(PUB)[-1] in ("DROP", f"remoteip={PUB}")
    with pytest.raises(ValueError): main.block_cmd("1.2.3.4; rm -rf /")
