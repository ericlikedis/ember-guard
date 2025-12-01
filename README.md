# ember-guard
a lightweight macos triage and forensic collection tool designed for quick safety checks, troubleshooting, and digital forensics readiness. it gathers key system information, autoruns, network activity, install logs, quarantine events, and login activity, then generates a simple verdict:

- 🟢 not compromised  
- ❗️ compromised (or at least suspicious)

this tool does **not** modify your system. all actions are read-only and safe to run on any mac.

---

## features

- collects forensic-relevant data:
  - system info  
  - launch agents & launch daemons  
  - network listeners & active connections  
  - recent install.log entries  
  - quarantine/download events  
  - recent authentication events  
- dynamic output folder creation (no hard-coded paths)
- runs simple heuristic checks to flag suspicious:
  - autorun items  
  - process names  
  - install records  
  - login/auth anomalies  
- produces a clear summary verdict
- cross-user friendly — anyone can drop the script into any folder and run it

---

## requirements

- macos (tested on modern versions with unified logging)
- python 3.8 or later  
- command-line tools typically built into macos:
  - `lsof`
  - `log`
  - `sqlite3`
  - `system_profiler`

---

## installation

clone or download the repository:

```bash
git clone https://github.com/ericlikedis/ember-guard.git
cd ember-guard
