# SIAAS GUI

Web dashboard for the **SIAAS — Security Audit System** agent. Displays scan results, vulnerability findings, AI-assisted remediation, and consolidated security posture in real time. Built with [Streamlit](https://streamlit.io).

---

## Requirements

| Requirement | Details |
|---|---|
| Python | 3.10 or newer |
| siaas-agent | Must be installed and running on the same machine, at `../siaas-agent/` relative to this repo |
| Network access | Only needed for the **Run now** buttons (calls the SIAAS server API) |

---

## Installation

### First-time setup (as root)

```bash
sudo bash siaas_gui_venv_setup.sh
```

This installs system packages (`python3`, `python3-venv`, `python3-tk`) and sets up the Python virtual environment with all dependencies.

### Start the GUI

```bash
bash siaas_gui_run.sh
```

Opens on **http://0.0.0.0:8501** by default.

> The script creates/updates the venv and installs dependencies on every run, so it is safe to use as a launcher without re-running the setup script.

---

## Directory structure expected

```
(parent dir)/
├── siaas-agent/          # SIAAS agent repo
│   └── var/
│       ├── portscanner.db
│       ├── webscanner.db
│       ├── metasploit.db
│       ├── remediation.db
│       ├── audit.db
│       ├── config.db     # agent config — read for server URL + credentials
│       └── uid           # agent unique ID — read for Run now triggers
└── aiaavsraw-gui/        # this repo (will be renamed siaas-gui)
    ├── siaas_gui.py
    ├── siaas_gui_aux.py
    ├── siaas_gui_run.sh
    ├── siaas_gui_venv_setup.sh
    └── requirements.txt
```

The GUI reads all `.db` files directly from `siaas-agent/var/` — no database or server connection is required to display data.

---

## Tabs

| Tab | Description |
|---|---|
| **Audit Report** | Consolidated security posture: org risk score/level, executive summary, AI-generated narrative, host and web target risk tables, remediation roadmap by phase |
| **Dashboard** | Top-level metrics per scanner and a consolidated host risk ranking across all data sources |
| **Port Scanner** | Nmap/portscanner results per host — open ports, services, vulnerability findings with severity filtering |
| **Web Scanner** | OWASP ZAP findings per web target — vulnerability list with severity, CWE, solution |
| **Metasploit** | Defensive CVE-to-module correlation — shows which Metasploit modules match detected services/CVEs, with module rank and platform |
| **Remediation** | Prioritised finding list with AI-assisted remediation steps, validation steps, risk summary, and status tracking (open / remediated / wontfix) |

---

## Run now buttons

The **Metasploit**, **Remediation**, and **Audit** tabs have a **▶ Run now** button that triggers the corresponding agent module on demand, without waiting for its scheduled interval.

**How it works:**

1. The GUI reads `siaas-agent/var/config.db` for `api_uri`, `api_user`, `api_pwd`
2. The GUI reads `siaas-agent/var/uid` for the agent's unique ID
3. A `POST` is sent to `<api_uri>/siaas-server/agents/configs/<uid>` with body:
   ```json
   { "trigger_<module>": "2026-06-01T12:05:33Z" }
   ```
4. The agent detects the new timestamp in its next config poll and runs the module immediately
5. Once the module writes new results, the GUI detects the updated `last_check` and clears the "Triggered" state automatically

**Button states:**

| State | Meaning |
|---|---|
| `Waiting for first run` | No data in the module DB yet |
| `⏳ Triggered at … UTC — waiting…` | POST sent, agent has not yet reported back |
| `Last run: … UTC` | Module completed and results are available |

Use the **✕ Clear** button to dismiss the "Triggered" state manually if the agent is not running or the trigger was not processed.

Use **Connection diagnostics** (expandable under each Run now button) to verify server URL, agent UID, and test connectivity.

---

## Data refresh

The dashboard auto-refreshes data every **30 seconds** (Streamlit cache TTL). Use the **Refresh data** button at the top to force an immediate reload.

---

## Dependencies

| Package | Version | Purpose |
|---|---|---|
| `streamlit` | ≥1.34, <2 | Web UI framework |
| `requests` | ≥2.28 | HTTP calls for Run now triggers |

---

## License

Part of the SIAAS project. See the main repository for licence details.
