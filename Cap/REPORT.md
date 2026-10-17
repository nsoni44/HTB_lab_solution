# Penetration Testing Report — HTB "Cap" (Easy, Linux)

**Target:** Cap — IP `$TARGET`
**Engagement date:** 2026-09-30
**Assessed by:** HTB/CTF multi-agent swarm (Recon, Strategist, Exploit, PrivEsc, Scribe agents)
*Conventions: `$TARGET` = current box IP; `$ATTACKER_IP` = your tun0/VPN address. Substitute both; no environment-specific IPs or local paths are hardcoded.*
**Result:** Full compromise — unauthenticated access escalated to `root`. Both flags captured.

---

## 1. Executive Summary

Cap is an "easy"-rated Ubuntu 20.04 Linux box compromised by chaining a web **IDOR** with an unsafe
**Linux capability** on the Python interpreter. The host runs a Flask/Gunicorn "Security Dashboard"
that generates per-user packet captures and serves them at `/download/<id>`. The `<id>` is
user-controlled and unauthenticated (an **Insecure Direct Object Reference**), so an attacker can
download *any* capture — including capture `0`, an administrator's PCAP that contains **cleartext FTP
credentials** (`nathan:Buck3tH4TF0RM3!`). Those credentials are reused for SSH to obtain an interactive
foothold as `nathan` (uid 1001) and `user.txt`. Local enumeration shows `/usr/bin/python3.8` carries the
**`cap_setuid`** file capability; invoking `os.setuid(0)` from that binary yields a root shell and
`root.txt`. The root cause is twofold: a missing authorization check on a data-download endpoint, and
granting a UID-changing capability to a general-purpose interpreter.

---

## 2. Attack Chain Timeline

1. Full TCP sweep + service scan (`nmap -p- -sCV`) — 21 (vsftpd 3.0.3), 22 (OpenSSH 8.2p1 Ubuntu),
   80 (Gunicorn / Python "Security Dashboard"). *Result:* web app is the primary surface; FTP/SSH parked
   pending credentials.
2. Web enumeration — the dashboard exposes `/capture`, `/ip`, `/netstat`, and report pages at
   `/data/<id>`, each linking to a PCAP at `/download/<id>`. *Result:* capture IDs are exposed in URLs.
3. Confirmed IDOR — `/data/0` and `/data/1` both return 200, and `/capture` binds a report to the
   current session ID while `/data/<id>`/`/download/<id>` accept an arbitrary, unauthenticated `<id>`.
   *Result:* any user's capture is downloadable.
4. Downloaded capture `0` (`/download/0`) and extracted FTP authentication with `tshark` — cleartext
   `USER nathan` / `PASS Buck3tH4TF0RM3!`. *Result:* valid credentials recovered.
5. Reused the credentials over SSH (`ssh nathan@…`) — `id` → `uid=1001(nathan)`. *Result:* interactive
   foothold; **user.txt captured.**
6. Local privilege-escalation enumeration — `getcap -r /` reveals
   `/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip`. *Result:* interpreter can change UID to 0.
7. `python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'` → `uid=0(root)`. *Result:* root shell;
   **root.txt captured** — box fully owned.

---

## 3. Key Vulnerabilities Identified

### 3.1 IDOR on `/data/<id>` and `/download/<id>` — unauthenticated download of any capture
- **Description:** Packet-capture report pages (`/data/<id>`) and their PCAP downloads (`/download/<id>`)
  accept a user-supplied numeric `<id>` with no authorization check binding the capture to the requesting
  session/user. Any capture, including other users' and the administrator's, can be read without
  authentication.
- **Affected component:** Flask/Gunicorn "Security Dashboard", port 80.
- **Impact:** Disclosure of sensitive captured traffic; in this case an admin PCAP containing cleartext
  credentials, directly enabling account takeover.
- **Estimated CVSS:** 7.5 (High) [estimate], approx `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`.
- **Remediation:** Enforce authorization on both endpoints — bind captures to the authenticated
  session/user and reject IDs the caller does not own; use unguessable identifiers as defense-in-depth.

### 3.2 Cleartext credentials in captured traffic / plaintext FTP
- **Description:** The administrator's capture recorded an FTP session transmitting credentials in
  cleartext, which are trivially extracted from the PCAP. The same password is reused for SSH.
- **Affected component:** vsftpd 3.0.3 (port 21); credential hygiene.
- **Impact:** Credential disclosure and lateral/vertical reuse (FTP → SSH shell).
- **Estimated CVSS:** 6.5 (Medium) [estimate] — contributes to the chain via disclosed reusable creds.
- **Remediation:** Disable plaintext FTP in favour of FTPS/SFTP; do not reuse FTP passwords for SSH;
  rotate `nathan`'s password.

### 3.3 Dangerous Linux capability — `cap_setuid` on `/usr/bin/python3.8`
- **Description:** The Python 3.8 binary carries the `cap_setuid` file capability (`+eip`), allowing any
  user who can execute it to call `os.setuid(0)` and run code as root without a password (GTFOBins).
- **Affected component:** `/usr/bin/python3.8` on the host.
- **Impact:** Any local user escalates to root.
- **Estimated CVSS:** 7.8 (High) [estimate] — local, low complexity, full CIA impact (root).
- **Remediation:** Remove the capability (`setcap -r /usr/bin/python3.8`); never grant UID-changing
  capabilities to general-purpose interpreters. (Note: only `cap_setuid` is present, not `cap_setgid`, so
  `os.setgid(0)` errors — `setuid(0)` alone suffices.)

---

## 4. Command Log & Proof of Concepts

All commands were run against the lab target only, from the engagement workstation on `tun0` (HTB VPN).

### 4.1 Recon
```bash
nmap -p- --min-rate 2000 -oN nmap/allports.txt $TARGET
nmap -sCV -p21,22,80 -oN nmap/services.txt $TARGET
```
Result: 21/vsftpd 3.0.3, 22/OpenSSH 8.2p1 (Ubuntu 20.04), 80/Gunicorn Python "Security Dashboard".

### 4.2 IDOR + credential extraction
```bash
curl -s http://$TARGET/data/0 -o web/data0.html      # 200 (not our session's capture)
curl -s http://$TARGET/download/0 -o loot/0.pcap
tshark -r loot/0.pcap -Y ftp -T fields -e ftp.request.command -e ftp.request.arg
# USER nathan
# PASS Buck3tH4TF0RM3!
```
Evidence: web/data0.html, loot/0.pcap, loot/creds.txt.

### 4.3 Foothold — credential reuse over SSH
```bash
ssh nathan@$TARGET        # password: Buck3tH4TF0RM3!
id                               # uid=1001(nathan) gid=1001(nathan)
```
Flag capture: `~/user.txt` = `[REDACTED-HTB-FLAG]`.

### 4.4 Privilege escalation — cap_setuid on python3.8
```bash
/usr/sbin/getcap -r / 2>/dev/null
# /usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
/usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'
id                               # uid=0(root)
```
Flag capture: `/root/root.txt` = `[REDACTED-HTB-FLAG]`.

---

## 5. Both Flags

| Flag | Value | Location | Notes |
|---|---|---|---|
| user.txt | `[REDACTED-HTB-FLAG]` | `/home/nathan/user.txt` | Captured as `nathan` via SSH with the PCAP-sourced credentials. |
| root.txt | `[REDACTED-HTB-FLAG]` | `/root/root.txt` | Captured via `cap_setuid` on `/usr/bin/python3.8`. |

---

## 6. Credentials & Artifacts

| Principal | Secret | Source | Scope |
|---|---|---|---|
| `nathan` | `Buck3tH4TF0RM3!` | Cleartext FTP in PCAP `/download/0` | Works on FTP (21) and SSH (22); uid 1001. |

Artifacts recovered: `loot/0.pcap` (admin capture with credentials), `loot/creds.txt`.

---

## 7. Cleanup / Artifacts Left on Target

No persistent artifacts were written to the target (no uploaded tools, no dropped files, no added
accounts). The root shell was obtained in-memory via the existing `python3.8` capability. No cleanup
required beyond closing sessions.

---

## 8. Open Items / [needs verification]

- None. Box fully owned; both flags captured and recorded.
- Operational note (environment): a duplicate VPN tunnel earlier produced a false "target down" read —
  confirm exactly one `tun` device if connectivity looks flaky.

---

*Companion documents: `walkthrough.md` — step-by-step reproduction; `STORY.md` — plain-language
narrative; `GLOBAL_CONTEXT.md` — the engagement blackboard and evidence trail.*
