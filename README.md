# ember-guard
a lightweight macos triage and forensic collection tool designed for quick safety checks, troubleshooting, and digital forensics readiness. it gathers key system information, autoruns, network activity, install logs, quarantine events, and login activity, then generates a simple verdict:

- 🟢 not compromised  
- ❗️ compromised (or at least suspicious)

this tool does **not** modify your system. all actions are read-only and safe to run on any mac.

---

flowchart TD

    A[start: user runs script  
    `python3 mactriage.py [output_base_dir]`] --> B[parse optional output directory argument]

    B --> C[determine base directory  
    (arg or script location)]
    C --> D[create timestamped output folder  
    `mac_quickcheck_YYYYMMDD_HHMMSS`]

    D --> E[collect_system_info()  
    - sw_vers  
    - system_profiler  
    -> system_info.txt]

    E --> F[collect_autoruns()  
    - user launchagents  
    - global launchagents  
    - launchdaemons  
    - recent changes  
    -> autoruns.txt  
    + run heuristics on filenames]

    F --> G[collect_network()  
    - lsof listening ports  
    -> network_listening_ports.txt  
    - lsof all connections  
    -> network_all_connections.txt  
    + run heuristics on process names]

    G --> H[collect_installs()  
    - grep "Installed" from /var/log/install.log  
    -> software_installs.txt  
    + run heuristics on install lines]

    H --> I[collect_quarantine()  
    - read quarantine sqlite db (if present)  
    -> quarantine_events.txt  
    + run heuristics on apps / urls]

    I --> J[collect_logins()  
    - mac unified log (last 1 day)  
    -> login_activity_1d.txt  
    + scan for failed login patterns / ssh activity]

    J --> K{any suspicious findings?}

    K -- yes --> L[record findings in memory  
    (FINDINGS list)]
    L --> M[print summary:  
    ❗️ compromised (or suspicious)  
    + list heuristic hits  
    + exit code 1]

    K -- no --> N[print summary:  
    🟢 not compromised  
    (no obvious indicators)  
    + exit code 0]

    M --> O[end]
    N --> O[end]

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
