# Touch — Manual Walkthrough (user.txt confirmed; root.txt open)

Target: `10.129.81.80` (box respawned 2026-10-05; prior session used `10.129.79.205` — same
box image/creds/bugs, substitute the new IP everywhere below). Full prior evidence/screenshots
from last session live in `easy/Touch/loot/`, `web/`, `nmap/`, `fuzz/` — reference them if a step
doesn't reproduce exactly and you want to compare.

---

## 0. Confirm connectivity

```bash
sudo openvpn machines_eu-3.ovpn      # if not already up
ip a | grep tun0                     # confirm tunnel
pgrep -a -f openvpn                  # make sure there's only ONE tunnel — a second one causes false "down" reads
ping -c1 10.129.81.80                # will likely show nothing (HTB blocks ICMP) — not a signal either way
```

## 1. Recon — port scan

```bash
nmap -p- -T4 10.129.81.80                          # full sweep: expect only 4 open ports
nmap -sC -sV -p135,3389,5985,8443 10.129.81.80 -oN targeted.txt
```

Expected result (from last session): only **135** (msrpc), **3389** (RDP), **5985** (WinRM,
plain HTTP listener — normal), **8443** (plain HTTP, NOT TLS — custom app) open. Everything else
filtered. Host is Windows.

## 2. Web enum on port 8443 — "Nexion DeviceHub"

```bash
curl -s http://10.129.81.80:8443/login -o login.html      # confirm plain HTTP works, grab login page
curl -s http://10.129.81.80:8443/api/status | jq
```

`/api/status` is **unauthenticated** and leaks the device serial:

```json
{"device":"Nexion DeviceHub DH-100","serial":"NX-DH-2024-B7042","firmware":"1.4.2","status":"online","uptime":...}
```

The login page's "Forgot your password?" link title literally says the default password is the
device serial. So:

```bash
curl -s -i -X POST http://10.129.81.80:8443/login \
  -d "password=NX-DH-2024-B7042" \
  -c cookies.txt
# expect: 302 Found, Location: /dashboard, Set-Cookie: nxsession=...
```

**If the serial differs on the respawned box** (unlikely but possible if HTB randomizes it per
spawn), re-fetch `/api/status` first — don't assume `NX-DH-2024-B7042` blindly.

## 3. Authenticated dashboard — grab Windows credential

```bash
curl -s -b cookies.txt http://10.129.81.80:8443/dashboard -o dashboard.html
grep -i -A2 'toggleCred\|password\|cred' dashboard.html
```

The dashboard page hardcodes device credentials in its HTML (behind a JS "show" toggle, but the
value is already present in the page source). Last session this was:

```
Username: KioskUser
Password: K!0sk2026#
```

Re-grep to confirm this value is unchanged on the new spawn before trusting it.

*(Everything else on this web app — `/login/badge`, `/api/scanner/test-image` upload,
`/api/scanner/settings` mass-assignment, the `localhost:5173` link — was exhaustively tested last
session and is a dead end. Full detail in `GLOBAL_CONTEXT.md` "Failed Attempts" if you want to
verify instead of trusting it. Don't re-spend time re-probing those unless something about the
respawn looks different.)*

## 4. RDP in as KioskUser

```bash
Xvfb :99 -screen 0 1280x800x24 &
DISPLAY=:99 xfreerdp /v:10.129.81.80 /u:KioskUser /p:'K!0sk2026#' /cert:ignore /w:1280 /h:800 +clipboard /sec:rdp
```

(`/sec:rdp` required — this host's listener rejects NLA/TLS.) You should land straight into a
full-screen kiosk app: **"HTB Airways — Self Check-In"** (no Windows login prompt — auto-logon).

Don't bother with client-side `/shell:` or `/app:` overrides — confirmed dead-end server-side
last session (the RDS host enforces the initial program regardless of client flags).

## 5. Kiosk breakout → real cmd.exe

This is the actual trick for this box — **OS-level accessibility shortcuts aren't blocked**,
unlike every app/browser shortcut:

1. From the kiosk home screen, send **`Win+U`** (opens Ease of Access Settings). This surfaces a
   genuine native Windows dialog titled **"Narrator updates"** — a real OS dialog with its own
   title bar and live hyperlinks, sitting outside the kiosk lockdown.
2. Click the **"Narrator guide"** hyperlink inside that dialog, then press `Return` to activate
   it. This launches a **full, unsandboxed Microsoft Edge window** (normal chrome — address bar,
   tabs, minimize/close). The page itself won't load (no real internet in the lab network) —
   irrelevant, you just need the window.
3. In Edge's address bar (`Ctrl+L`), go to `file:///C:/Users/KioskUser/Desktop/user.txt` to read
   the flag directly, **or** go straight for a shell:
4. Press **`Ctrl+S`** in Edge (Save As) → a real native Windows file-save dialog opens. In it:
   - Change **"Save as type"** from "TXT File" to **"All files"** (critical — otherwise `.exe`
     won't resolve/show).
   - Click the breadcrumb/address area of the dialog (`Ctrl+L` works here too) and type:
     `C:\Windows\System32\cmd.exe`, then press `Return`.
   - This **launches `cmd.exe` as a real window** — classic common-dialog kiosk-escape (the
     Save/Open dialog is real Explorer-shell code; navigating it to an .exe and "opening" it
     executes it, bypassing the kiosk's assigned-shell policy).

Verify:
```
whoami            → kiosk-042\kioskuser
hostname          → KIOSK-042
type C:\Users\KioskUser\Desktop\user.txt
```

Last session's value was `[REDACTED-HTB-FLAG]` — confirm the new spawn gives the
same (or a new) value and update `loot/user.txt` accordingly.

**user.txt done.**

---

## 6. Where privesc was left off (root.txt — NOT solved yet)

This is the honest state from last session — the bug is understood, the trigger is not. Don't
expect a working root chain below; this is what's confirmed vs. still open.

**Confirmed:**
- `whoami /groups` shows `kioskuser` is in a **custom local group**:
  `KIOSK-042\Printer Administrators` (not built-in Administrators).
- `icacls "C:\Program Files\Nexion Systems\Printer\publish\plugins\"` shows that group has
  **Modify (M)** rights on this *plugins* subfolder specifically (the main app folder above it
  does not grant this) — strongly implies a plugin-DLL-drop privesc.
- `NexionPrinter.exe` runs as **SYSTEM**, launched by a **Scheduled Task in the Task Scheduler
  root folder (`\`)** (confirmed via parent-process chain `svchost.exe → "Schedule" service`),
  **not** a registered Windows service. Non-admin accounts can't enumerate that task (`schtasks`,
  `Get-ScheduledTask`, and even listing `C:\Windows\System32\Tasks` directly are all
  access-denied).
- Real Print Spooler service is confirmed **stopped**, no PointAndPrint policy key — this is
  **not** PrintNightmare, rule that out immediately, don't re-test it.

**The actual missing piece: how to make `NexionPrinter.exe` restart/reload its plugins.**
Plugins only load at process startup (no live FileSystemWatcher reload confirmed by testing both
overwrite and new-file-create — neither triggered anything). Everything tried to force a
restart failed: `taskkill` (access denied, expected), the web dashboard's "restart printer"
button (cosmetic — PID never changes), killing/power-cycling via the fake `/api/printer/power`
and `/api/printer/restart` endpoints (no real effect), `shutdown /r` (access denied).

**Leading untested hypothesis:** `NexionPrinter.exe` may be meant to process one real print job
and exit (the watchdog .bat that restarts it in a loop only makes sense if it's supposed to exit
periodically) — it's just sitting idle because no real job has ever been fed to it. The only
plausible way to feed it a real job is the `localhost:5173` "HTB Airways Self Check-In" kiosk
app's full flow (booking lookup → Documents → Boarding Pass print), which requires a **real
booking reference** we never found (not in `/logs`, not in printer queue, no backend route for it
on 8443 — it must live behind `localhost:5173`'s own process, not reachable without code exec,
which is a chicken-and-egg problem we hadn't resolved).

**To resume root from your own shell, in priority order:**
1. From the `cmd.exe` shell (section 5), try completing the actual boarding-pass flow in the
   kiosk app's own GUI (Self Check-In → Find Booking → ...) — if you can get a *real* seeded demo
   booking/PNR from somewhere (HTB forums/box discussion often leak the intended "obvious" demo
   value once released — check there before brute-forcing), finishing that flow for real may be
   what makes `NexionPrinter.exe` actually print something, which could be the restart/reload
   trigger.
2. Re-examine `C:\Program Files\Nexion Systems\Printer\publish\` for anything not yet read in
   full (last session only grepped for strings/plugin interfaces — a full read of the main exe's
   plugin-loading code via `ILSpy`/`dotPeek`/`strings` for the *exact* trigger condition, e.g. a
   named pipe, a file it watches, a specific filename pattern, was not completed).
3. Re-check for a named pipe or local socket `NexionPrinter.exe` listens on (`Get-NetTCPConnection`,
   or enumerate named pipes via `[System.IO.Directory]::GetFiles("\\\\.\\pipe\\")` in
   PowerShell) — not yet tried last session, and a much more direct way to "ask" the SYSTEM
   process to reload than guessing a file-trigger.
4. Don't re-waste time on: PrintNightmare/spooler (ruled out), task-name guessing (6 plausible
   names already tried and missed), WinRM credential reuse (26 combos tried, all failed), the
   `/login/badge` endpoint (confirmed dead code — `Bitmap()` on a non-seekable stream, always
   throws regardless of input).

Full verbose detail/evidence trail for all of the above is in `GLOBAL_CONTEXT.md` under
"PrivEsc progress" and "Failed Attempts" if you want the exact commands/outputs rather than the
summary.

Good luck — ping me with whatever you find (especially if you spot the named pipe or a real PNR)
and I'll help push it the rest of the way.
