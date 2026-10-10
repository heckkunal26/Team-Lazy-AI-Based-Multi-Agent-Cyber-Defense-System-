# 🛡️ Team Lazy — Multi-Agent Cyber Defense

### Build with Bharat 4.0

**An AI-powered cybersecurity system that detects, explains, and helps contain cyberattacks in real time using six cooperating agents, machine learning, live log monitoring, and web-based threat intelligence.**

## 🚀 Overview

Team Lazy is a multi-agent cyber defense platform designed to monitor network activity, identify suspicious behavior, analyze security incidents, recommend containment actions, and generate incident reports.

The system combines supervised machine learning, anomaly detection, real-time log ingestion, threat intelligence, and human-in-the-loop approval to provide an explainable and auditable security workflow.

A dedicated Intel Agent integrates TinyFish APIs to research incidents using live web sources without delaying the containment workflow.

## ✨ Key Features

* **Multi-Agent Architecture:** Six specialized agents collaborate across monitoring, detection, analysis, response, reporting, and threat intelligence.
* **Machine Learning Detection:** Random Forest classification for network attack categories and Isolation Forest for anomaly detection.
* **Real-Time Log Monitoring:** Supports SSH authentication logs, Nginx/Apache access logs, Suricata EVE JSON, and API-based log ingestion.
* **Explainable Detection:** Presents evidence, anomalous features, severity, and recommended security actions.
* **Threat Intelligence:** Uses TinyFish Search, Fetch, and Agent APIs for web-based investigation.
* **MITRE ATT&CK Mapping:** Connects detected activity with relevant attack techniques and mitigation guidance.
* **Human-in-the-Loop Security:** Requires human approval for high-severity actions.
* **Safe Response Mechanism:** Runs in DRY-RUN mode by default, with optional firewall enforcement.
* **Audit Trail:** Records incidents and actions for traceability and review.
* **Incident Reporting:** Generates structured security reports inspired by NIST incident-response practices.

## 🤖 Multi-Agent Workflow

The system follows a coordinated security pipeline:

1. **Monitor Agent** — Collects and processes incoming security logs and network-flow records.
2. **Detect Agent** — Identifies suspicious activity using trained ML models.
3. **Analyse Agent** — Evaluates evidence, severity, attack categories, and related events.
4. **Respond Agent** — Recommends or executes permitted containment actions, subject to safeguards.
5. **Report Agent** — Produces incident summaries, reports, and audit records.
6. **Intel Agent** — Uses TinyFish to investigate public threat intelligence sources and enrich incident context asynchronously.

**Workflow:** Monitor → Detect → Analyse → Respond → Report

The Intel Agent works alongside this pipeline so external web research does not need to finish before containment recommendations are produced.

## 🧠 Machine Learning

The project uses the NSL-KDD dataset, a benchmark dataset containing labelled network-traffic records.

**Models**

* Random Forest — Classifies traffic into Normal, DoS, Probe, R2L, and U2R categories.
* Isolation Forest — Detects unusual patterns using a model trained on normal-only flows.

**Reported evaluation results on KDDTest+:**

| Metric                             | Result |
| ---------------------------------- | -----: |
| Attack detection precision         |  96.7% |
| Attack detection recall            |  66.6% |
| Attack detection accuracy          |  79.7% |
| Five-class classification accuracy |  74.1% |

These are the project's reported held-out benchmark results, not guarantees of performance on modern production networks. Refer to `models/metrics.json` for the recorded metrics.

## 🔎 TinyFish Integration

The Intel Agent supports three TinyFish APIs:

| API    | Purpose                                                                     |
| ------ | --------------------------------------------------------------------------- |
| Search | Finds relevant IP reputation pages and security guidance                    |
| Fetch  | Retrieves web-page evidence for bounded reputation scoring                  |
| Agent  | Performs deeper browser-based investigations and returns structured results |

Investigations may retrieve public IP reputation information or relevant MITRE ATT&CK and security mitigation guidance.

Web content is treated as untrusted evidence. Intelligence results cannot independently trigger firewall blocks.

**Configuration**

Set your TinyFish API key before starting the application.

PowerShell:

```powershell
$env:TINYFISH_API_KEY="your_key"
```

Linux/macOS:

```bash
export TINYFISH_API_KEY="your_key"
```

Obtain your key from the TinyFish platform. Keep API keys private and never commit them to GitHub.

Without a configured key, the application can run with the Intel functionality disabled, subject to the project's configuration.

## 🖥️ Supported Log Sources

The platform can monitor:

* SSH authentication logs
* Nginx and Apache access logs
* Suricata `eve.json` events
* Custom log lines submitted through the ingestion API

Example API request:

```bash
curl -X POST http://localhost:8000/api/ingest/log \
  -H "X-API-Key: yourkey" \
  -H "Content-Type: application/json" \
  -d '{"kind":"ssh","line":"Failed password for root from 45.155.205.9"}'
```

Use authorized test data or logs from systems you administer.

## 🧰 Technology Stack

* **Language:** Python
* **Backend:** FastAPI, Uvicorn
* **Machine Learning:** Scikit-learn, Random Forest, Isolation Forest
* **Dataset:** NSL-KDD
* **Threat Intelligence:** TinyFish Search, Fetch, and Agent APIs
* **Security Framework:** MITRE ATT&CK
* **Incident Storage:** SQLite
* **Monitoring:** SSH, Nginx/Apache, Suricata
* **Firewall Adapters:** Linux `iptables` and Windows `netsh advfirewall`
* **Testing:** Pytest
* **Deployment:** Docker Compose

## ⚙️ Installation and Setup

### 1. Clone the repository

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd <YOUR_PROJECT_FOLDER>
```

Replace the placeholders with your actual GitHub repository URL and folder name.

### 2. Create a virtual environment (recommended)

Windows PowerShell:

```powershell
python -m venv env1
.\env1\Scripts\Activate.ps1
```

Linux/macOS:

```bash
python3 -m venv env1
source env1/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Start the application

```bash
python -m uvicorn main:app --port 8000
```

Open the application at:

http://localhost:8000

Ensure that the frontend is served or configured correctly by the application before expecting the dashboard to load.

### 5. Run tests

```bash
python -m pytest tests -q
```

### 6. Train the models (optional)

If the required dataset files are missing, run:

```bash
python fetch_data.py
python train.py
```

Review the dataset source and script configuration before running data-fetching scripts.

## 🔐 Security and Safety

Security is a core design consideration.

* Firewall enforcement is disabled by default; DRY-RUN mode displays proposed actions without applying them.
* Actual enforcement requires explicit configuration.
* Private IP addresses and allowlisted IPs are protected from blocking.
* High-severity actions require human approval.
* Write endpoints use API-key authentication.
* Incident actions are recorded in the audit trail.
* Only eligible public IP addresses are sent to external threat-intelligence services.
* External intelligence is advisory and cannot independently authorize containment.

**Important:** Deploy only on systems you own or are authorized to administer. Review firewall rules, access controls, and network exposure before enabling enforcement or exposing the service beyond localhost.

## 📊 Demo Workflow

1. Open the dashboard and review the network-flow replay and reported detection metrics.
2. Select an incident to inspect its evidence, severity, MITRE mapping, and recommended response.
3. Submit authorized sample SSH logs and observe the incident workflow.
4. Submit related web-access events to demonstrate cross-stage correlation.
5. Open the audit trail and review the generated incident report.
6. Trigger a deeper investigation to demonstrate the optional TinyFish integration.

Use DRY-RUN mode for demonstrations unless real containment is explicitly authorized.

## ⚠️ Limitations

* NSL-KDD is based on older network traffic and may not represent modern attack patterns.
* Reported benchmark metrics do not establish real-world production performance.
* Recall for rare R2L and U2R categories can be limited.
* NSL-KDD flow records do not provide source IP addresses; IP-based blocking depends on log or IDS events that contain validated addresses.
* The current in-process asynchronous message bus is intended for the current architecture; larger deployments may require Redis Streams or Kafka.
* False-positive feedback is audit-logged for future retraining and does not automatically retrain the model online.
* Live TinyFish integration requires credentials and should be verified against the actual services before a public demonstration.

## 🔮 Future Enhancements

* Evaluate models on CICIDS2017 and CICIDS2018 datasets.
* Add scalable message processing with Redis Streams or Kafka.
* Improve rare-attack detection and reduce false positives.
* Extend threat-intelligence enrichment and incident correlation.
* Add role-based access control and stronger production deployment safeguards.
* Evaluate detection quality on authorized, representative modern traffic.

## 👥 Team

**Team Lazy**
Project: Multi-Agent Cyber Defense
Event: Build with Bharat 4.0

## 📄 License

Add an appropriate open-source license before redistributing the project.

---

*Built to explore explainable AI, multi-agent collaboration, and safer automated cyber defense.*

<<<<<<< HEAD

=======
>>>>>>> def6de9 (Update UI and UX)
