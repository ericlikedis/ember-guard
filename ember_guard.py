#!/usr/bin/env python3
"""
mac_forensics.py
Basic Mac triage script (read-only).
Collects system, autoruns, network, install, quarantine, and login info.

- Output directory is dynamic:
  * Default: a timestamped folder in the same directory as this script.
  * Optional: pass a base directory as the first argument:
      python3 mac_forensics.py /path/to/output_base

- Includes a simple heuristic "verdict":
    🟢 Not Compromised
    ❗️Compromised (or at least suspicious)

  NOTE: This is NOT a full antivirus. It just looks for obvious red flags
  using simple keyword-based rules.
"""

import os
import sys
import subprocess
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta

# ---------------- Heuristic state & helpers ---------------- #

FINDINGS: list[tuple[str, str]] = []

# Very simple suspicious keywords (all lowercased).
SUSPICIOUS_KEYWORDS = [
    "xmrig",
    "miner",
    "cryptominer",
    "rat",
    "keylog",
    "logger",
    "stealer",
    "steal",
    "trojan",
    "backdoor",
    "remoteaccess",
    # keep "malware" but guard it with SAFE_WORDS below
    "malware",
]

# Whitelist words that are typically security tools, not threats.
SAFE_WORDS = [
    "malwarebytes",
    "windows defender",
    "defender",
    "crowdstrike",
    "sentinelone",
    "sophos",
    "bitdefender",
    "avast",
    "avira",
    "eset",
    "kaspersky",
    "mcafee",
    "norton",
    "clamav",
]


def flag(category: str, detail: str):
    """Record a suspicious finding."""
    print(f"[!] Suspicious {category}: {detail}")
    FINDINGS.append((category, detail))


def looks_suspicious_name(name: str) -> bool:
    """Check if a filename/process name looks suspicious based on keywords,
    while skipping obvious security products (SAFE_WORDS).
    """
    n = name.lower()

    # If it contains a known safe word, don't treat it as suspicious.
    for safe in SAFE_WORDS:
        if safe in n:
            return False

    for kw in SUSPICIOUS_KEYWORDS:
        if kw in n:
            return True

    return False



# ---------------- Shell helper ---------------- #

def run_cmd(cmd, text=True, timeout=None) -> str:
    """Run a command and return stdout as string. Never raises on failure.

    timeout: in seconds; if exceeded, partial output is returned with a note.
    """
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=text,
            timeout=timeout,
            check=False,
        )
        return result.stdout
    except subprocess.TimeoutExpired as e:
        partial = e.stdout or ""
        return partial + f"\n[!] Command timed out after {timeout} seconds: {cmd}\n"
    except Exception as e:
        return f"[!] Failed to run {cmd}: {e}\n"


def write_file(path: Path, content: str):
    try:
        path.write_text(content, encoding="utf-8", errors="ignore")
    except Exception as e:
        print(f"[!] Failed to write {path}: {e}")


# ---------------- Collection functions ---------------- #

def collect_system_info(outdir: Path):
    print("[*] Collecting system info...")
    content = []
    content.append("=== sw_vers ===\n")
    content.append(run_cmd(["sw_vers"]))
    content.append("\n=== system_profiler SPSoftwareDataType ===\n")
    content.append(run_cmd(["system_profiler", "SPSoftwareDataType"]))
    write_file(outdir / "system_info.txt", "".join(content))


def collect_autoruns(outdir: Path):
    print("[*] Collecting launch agents/daemons...")
    content = []

    dirs = [
        Path.home() / "Library" / "LaunchAgents",
        Path("/Library/LaunchAgents"),
        Path("/Library/LaunchDaemons"),
    ]

    labels = [
        "=== User LaunchAgents (~/Library/LaunchAgents) ===",
        "=== Global LaunchAgents (/Library/LaunchAgents) ===",
        "=== Global LaunchDaemons (/Library/LaunchDaemons) ===",
    ]

    for label, d in zip(labels, dirs):
        content.append(label + "\n")
        if d.exists():
            try:
                for entry in sorted(d.iterdir()):
                    try:
                        stat = entry.stat()
                        mtime = datetime.fromtimestamp(stat.st_mtime)
                        content.append(f"{stat.st_mode:o} {mtime} {entry}\n")

                        # Heuristic: suspicious launch item name?
                        basename = entry.name
                        # Ignore very common benign names:
                        if basename.lower() not in {".ds_store"}:
                            if looks_suspicious_name(basename):
                                flag("autorun", f"suspicious launch item filename: {entry}")
                    except Exception as e:
                        content.append(f"[!] Error reading {entry}: {e}\n")
            except PermissionError:
                content.append("Permission denied\n")
        else:
            content.append("Directory does not exist\n")
        content.append("\n")

    # Recently modified (last 7 days) autoruns
    content.append("=== Recently modified (last 7 days) autoruns ===\n")
    cutoff = datetime.now() - timedelta(days=7)
    for d in dirs:
        if not d.exists():
            continue
        for root, _, files in os.walk(d):
            for f in files:
                p = Path(root) / f
                try:
                    mtime = datetime.fromtimestamp(p.stat().st_mtime)
                    if mtime >= cutoff:
                        content.append(f"{mtime} {p}\n")
                except Exception:
                    continue

    write_file(outdir / "autoruns.txt", "".join(content))


def collect_network(outdir: Path):
    print("[*] Collecting network connection snapshot (this may take a moment)...")

    # Listening ports
    listening = run_cmd(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"])
    write_file(outdir / "network_listening_ports.txt", listening)

    # Simple heuristics: any suspicious process names in listening sockets?
    for line in listening.splitlines():
        if not line or line.startswith("COMMAND"):
            continue
        parts = line.split()
        if len(parts) < 1:
            continue
        proc_name = parts[0]
        if looks_suspicious_name(proc_name):
            flag("network", f"suspicious process listening on a port: {proc_name} (line: {line})")

    # All connections
    all_conn = run_cmd(["lsof", "-nP", "-i"])
    write_file(outdir / "network_all_connections.txt", all_conn)

    # You *could* add more heuristics here, e.g., flag certain destination ports/IPs,
    # but that risks a lot of false positives. For now we keep it simple.


def collect_installs(outdir: Path):
    print("[*] Collecting recent software install log lines...")
    install_log = Path("/var/log/install.log")
    if not install_log.exists():
        write_file(outdir / "software_installs.txt", "/var/log/install.log not found\n")
        return

    try:
        grep_output = run_cmd(["grep", "Installed", str(install_log)])
        lines = grep_output.splitlines()
        last_200 = "\n".join(lines[-200:])
        write_file(outdir / "software_installs.txt", last_200 + "\n")

        # Heuristic: check app names for suspicious keywords
        for line in lines[-200:]:
            # Simple approach: look inside quotes or whole line
            if looks_suspicious_name(line):
                flag("install", f"suspicious software install line: {line}")
    except Exception as e:
        write_file(outdir / "software_installs.txt", f"[!] Failed to read install.log: {e}\n")


def find_quarantine_db() -> Path | None:
    base = Path.home() / "Library" / "Preferences" / "com.apple.LaunchServices"
    candidates = [
        base / "QuarantineEventsV2",
        base / "QuarantineEvents.V2",
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def collect_quarantine(outdir: Path):
    print("[*] Collecting quarantine (downloaded file) events...")
    quar_db = find_quarantine_db()
    if quar_db is None:
        write_file(outdir / "quarantine_events.txt", "No quarantine database found\n")
        return

    out_lines = ["Time (local), App, URL\n"]
    try:
        conn = sqlite3.connect(quar_db)
        cur = conn.cursor()
        query = """
            SELECT
                datetime(LSQuarantineTimeStamp + 978307200, 'unixepoch', 'localtime'),
                LSQuarantineAgentName,
                LSQuarantineDataURLString
            FROM LSQuarantineEvent
            ORDER BY LSQuarantineTimeStamp DESC
            LIMIT 100;
        """
        for row in cur.execute(query):
            time_str = row[0] or ""
            app = (row[1] or "").replace("\n", " ")
            url = (row[2] or "").replace("\n", " ")
            out_lines.append(f"{time_str}, {app}, {url}\n")

            # Heuristics: app or URL suspicious?
            if app and looks_suspicious_name(app):
                flag("download", f"suspicious downloader app in quarantine DB: {app}")
            if url and looks_suspicious_name(url):
                flag("download", f"suspicious URL in quarantine DB: {url}")
        conn.close()
    except Exception as e:
        out_lines.append(f"[!] Failed to read quarantine DB: {e}\n")

    write_file(outdir / "quarantine_events.txt", "".join(out_lines))


def collect_logins(outdir: Path):
    print("[*] Collecting recent login/auth events (last 1 day, limited)...")
    cmd = [
        "log",
        "show",
        "--style",
        "syslog",
        "--last",
        "1d",  # last 1 day only
        "--predicate",
        '(process == "loginwindow" OR process == "sshd" OR process == "sudo" OR process == "su")',
    ]
    # At most 60 seconds; if longer, we bail with partial output
    output = run_cmd(cmd, timeout=60)
    write_file(outdir / "login_activity_1d.txt", output)

    # Heuristics: failed logins, ssh, sudo abuse
    lower = output.lower()
    suspicious_login_markers = [
        "failed password",
        "invalid user",
        "authentication failure",
    ]
    for marker in suspicious_login_markers:
        if marker in lower:
            flag("auth", f"login/auth log contains marker: '{marker}'")

    # If we see sshd at all, that may be interesting on a laptop
    if "sshd[" in output:
        flag("auth", "sshd activity seen in last 1 day")


# ---------------- Output dir & main ---------------- #

def make_output_dir() -> Path:
    """
    Decide where to put output:

    - If the user passed an argument:
        python3 mac_forensics.py /some/base/dir
      -> output in /some/base/dir/mac_quickcheck_timestamp

    - Otherwise:
      base dir = directory where this script lives.
      So if the script is in ~/Desktop/Forensics, output goes there.
    """
    script_dir = Path(__file__).resolve().parent

    if len(sys.argv) > 1:
        base = Path(sys.argv[1]).expanduser()
    else:
        base = script_dir

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = base / f"mac_quickcheck_{timestamp}"

    try:
        outdir.mkdir(parents=True, exist_ok=False)
    except Exception as e:
        print(f"[!] Failed to create output directory {outdir}: {e}")
        sys.exit(1)

    return outdir


def main():
    outdir = make_output_dir()
    print(f"[*] Saving results to: {outdir}")

    collect_system_info(outdir)
    collect_autoruns(outdir)
    collect_network(outdir)
    collect_installs(outdir)
    collect_quarantine(outdir)
    collect_logins(outdir)

    print("\n================ SUMMARY ================")
    if FINDINGS:
        print("❗️Compromised (or at least suspicious) – findings below:")
        for category, detail in FINDINGS:
            print(f"- [{category}] {detail}")
        print("\n(Consider deeper investigation or professional DFIR help.)")
        exit_code = 1
    else:
        print("🟢 Not Compromised (no obvious indicators found by this script)")
        print("(This does NOT guarantee absolute safety, but nothing obvious stood out.)")
        exit_code = 0

    print("Logs saved in:", outdir)
    print("=========================================\n")
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
