# ember-guard

<p align="center">
  <img width="300" height="300" alt="image" src="https://github.com/user-attachments/assets/6634f3e0-35ce-4273-b14d-a2bf89520119" />
</p>

a lightweight macos triage and forensic collection tool designed for quick safety checks, troubleshooting, and digital forensics readiness. it gathers key system information, autoruns, network activity, install logs, quarantine events, and login activity, then generates a simple verdict:

- 🟢 not compromised  
- ❗️ compromised (or at least suspicious)

this tool does **not** modify your system. all actions are read-only and safe to run on any mac.

---

<img width="2494" height="662" alt="Brave Browser-2025-12-01-16-12" src="https://github.com/user-attachments/assets/77d5bcfc-43a4-4484-a2a2-b379637e31d9" />

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
```

## running

```python
python3 ember_guard.py
```

## running globally

simply move the script to `/usr/local/bin` directory
> make sure you are in the working directory where the script is first before running the command below! 
```
sudo mv ember-guard.py /usr/local/bin
```

> add an alias in your `.bashrc` or `.zshrc`
```
alias ember-guard="python3 /usr/local/bin/ember-guard.py
```
> save & source your `.bashrc` or `.zshrc`
```
source .zshrc
```
once all these stpes are complete you should be able to run `ember-guard` from any directory. 
> NOTE: this will save any log files in the directory the script runs from, in this case `/usr/local/bin/mac_quickcheck*`

![iTerm2-2025-12-09-10-18](https://github.com/user-attachments/assets/e52cb887-4e2a-4e72-9fa8-81a149a8e5d9)

