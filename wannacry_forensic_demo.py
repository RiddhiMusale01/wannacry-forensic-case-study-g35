"""
WannaCry Forensic Detection Demo  (Group 35 - Cyber Security CA-II)

Safe, educational tool. It contains NO malware and makes NO network calls.
It analyses SYNTHETIC logs to demonstrate the detection controls from
Section 4.6 of the report:
  1. Evidence integrity (SHA-256 hashing)
  2. Patch-gap calculation (MS17-010 patch vs outbreak)
  3. Detection of worm-like behaviour in synthetic event logs:
       - burst of outbound TCP/445 connections (SMB scanning)
       - service installation from a user-writable path (T1543.003)
       - mass file renames to one common extension (T1486)
       - DNS lookup of a known kill-switch indicator
Run:  python wannacry_forensic_demo.py
"""
import hashlib
import random
import sys
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta

random.seed(35)  # reproducible output

# ---------- 1. Evidence integrity ----------
def sha256_of(path, chunk=65536):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while block := f.read(chunk):
            h.update(block)
    return h.hexdigest()

def evidence_hash_demo():
    print("\n[1] EVIDENCE INTEGRITY (SHA-256)")
    path = sys.argv[0]  # hash this script as a stand-in artefact
    print(f"  Artefact : {path}")
    print(f"  SHA-256  : {sha256_of(path)}")
    print("  Note: record the hash in the chain-of-custody log, re-hash later to prove no change.")

# ---------- 2. Patch gap ----------
def patch_gap_demo():
    patch = date(2017, 3, 14)    # MS17-010 released
    leak = date(2017, 4, 14)     # Shadow Brokers dump
    outbreak = date(2017, 5, 12) # outbreak begins
    print("\n[2] PATCH GAP")
    print(f"  Patch -> leak     : {(leak - patch).days} days")
    print(f"  Patch -> outbreak : {(outbreak - patch).days} days")
    print("  Conclusion: not a zero-day; a patch-deployment failure.")

# ---------- 3. Synthetic log generation ----------
KILL_SWITCH = "killswitch.example.invalid"  # placeholder, NOT the real domain

def make_logs():
    start = datetime(2026, 1, 1, 9, 0, 0)
    net, svc, files, dns = [], [], [], []
    # normal activity
    for i in range(300):
        t = start + timedelta(seconds=i * 20)
        host = f"PC-{random.randint(1, 8):02d}"
        net.append((t, host, f"10.0.0.{random.randint(2, 50)}", random.choice([80, 443, 53, 445])))
        if i % 25 == 0:
            files.append((t, host, "report.docx", "report.docx"))
    # infected host: SMB scanning burst
    t0 = start + timedelta(minutes=30)
    for i in range(250):
        net.append((t0 + timedelta(seconds=i * 0.2), "PC-09", f"10.0.{random.randint(0,3)}.{random.randint(1,254)}", 445))
    # service installed from writable path
    svc.append((t0, "PC-09", "mssecsvc2.0", r"C:\Users\Public\svc.exe -m security"))
    svc.append((start, "PC-02", "Spooler", r"C:\Windows\System32\spoolsv.exe"))
    # mass rename
    for i in range(120):
        files.append((t0 + timedelta(seconds=60 + i * 0.5), "PC-09", f"doc{i}.docx", f"doc{i}.docx.WNCRY"))
    # DNS lookup of kill-switch indicator
    dns.append((t0 - timedelta(seconds=2), "PC-09", KILL_SWITCH))
    return net, svc, files, dns

# ---------- 4. Detection rules ----------
def detect(net, svc, files, dns, smb_threshold=100, rename_threshold=50):
    alerts = []
    smb = Counter(h for _, h, _, port in net if port == 445)
    for host, n in smb.items():
        if n >= smb_threshold:
            alerts.append(("HIGH", host, f"SMB scanning: {n} outbound TCP/445 connections (T1210)"))
    for _, host, name, path in svc:
        if path.lower().startswith((r"c:\users", r"c:\temp", r"c:\programdata")):
            alerts.append(("HIGH", host, f"Service '{name}' installed from writable path (T1543.003)"))
    ren = defaultdict(Counter)
    for _, host, old, new in files:
        if new != old and "." in new:
            ren[host][new.rsplit(".", 1)[-1]] += 1
    for host, c in ren.items():
        ext, n = c.most_common(1)[0]
        if n >= rename_threshold:
            alerts.append(("CRITICAL", host, f"Mass rename: {n} files -> .{ext} (T1486)"))
    for _, host, domain in dns:
        if domain == KILL_SWITCH:
            alerts.append(("MEDIUM", host, f"DNS lookup of kill-switch indicator '{domain}'"))
    return alerts

def detection_demo():
    print("\n[3] DETECTION ON SYNTHETIC LOGS")
    net, svc, files, dns = make_logs()
    print(f"  Events: {len(net)} network, {len(svc)} service, {len(files)} file, {len(dns)} DNS")
    alerts = detect(net, svc, files, dns)
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    for sev, host, msg in sorted(alerts, key=lambda a: order[a[0]]):
        print(f"  [{sev:8}] {host}: {msg}")
    hosts = {h for _, h, _ in alerts}
    print(f"\n  Summary: {len(alerts)} alerts, hosts flagged: {sorted(hosts)}")
    print("  Expected: only PC-09 (the simulated infected host) is flagged.")

if __name__ == "__main__":
    print("=== WannaCry Forensic Detection Demo (synthetic data only) ===")
    evidence_hash_demo()
    patch_gap_demo()
    detection_demo()
