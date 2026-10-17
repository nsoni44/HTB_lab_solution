# GLOBAL CONTEXT MEMORY — Touch

> Single source of truth for the swarm. Every agent reads this on start and
> writes VERIFIED findings on finish. Mark uncertain items `[unconfirmed]`.

## Engagement
- **Box:** Touch
- **Target IP:** 10.129.81.80 (**RESPAWNED 2026-10-05** — was `10.129.79.205` on 2026-10-04; box image/creds/bugs are static per-box, only the IP changed. All commands below use the new IP. Not yet re-verified live against this new IP.)
- **Difficulty:** easy / windows
- **Started:** 2026-10-04
- **Current Access Level (as of last session, pre-respawn):** **FOOTHOLD OBTAINED.** Full interactive `cmd.exe` shell as `KIOSK-042\kioskuser` over RDP, via an OS-level accessibility-shortcut kiosk breakout (see below). `user.txt` CAPTURED (value from last session, should be identical post-respawn since it's a static box).
- **Current Phase:** User requested a manual walkthrough (`WALKTHROUGH.md` in this folder) to reproduce up through user.txt and resume privesc themselves. Key lead for privesc: `KioskUser` is a member of a **custom local group `KIOSK-042\Printer Administrators`** — modify rights on the Nexion printer app's plugin folder. Primitive (malicious plugin DLL) is understood; the trigger to make the SYSTEM process reload it was NOT found last session — see PrivEsc section below.

## Open Ports & Services
| Port | Proto | Service | Version | Evidence |
|------|-------|---------|---------|----------|
| 135  | tcp | msrpc | Microsoft Windows RPC | nmap/targeted.txt |
| 3389 | tcp | ms-wbt-server | Microsoft Terminal Service (RDP) | nmap/targeted.txt |
| 5985 | tcp | http (WinRM) | Microsoft-HTTPAPI/2.0 — standard WinRM listener (404 on GET is normal unauth behavior) | nmap/targeted.txt, web/5985_root_http.html |
| 8443 | tcp | http (plain HTTP, NOT TLS) | Microsoft-HTTPAPI/2.0 hosting "Nexion DeviceHub" custom app | nmap/targeted.txt, web/8443_* |

Full port sweep: nmap/allports.txt (only these 4 ports open of 65535; all others filtered/no-response). Host OS: Windows (per nmap OS CPE).

Note: nmap's `http-trane-info` NSE script flagged `/evox/about` on 8443 — this is a generic heuristic false-positive match (the app just 302-redirects unknown paths to /login); it is NOT a real Niagara/Tridium Framework instance. Confirmed by manual inspection.

## Web / App Surface
- **App:** "Nexion DeviceHub" (DH-100) — custom-built device-management kiosk app, branded "Nexion DocReader Management Service", airport self-service kiosk theme ("Gate B7 — Terminal 4 — Kiosk #042"). Service v4.2.1, Server header `Microsoft-HTTPAPI/2.0` (looks like a .NET/Windows HttpListener-based app, NOT IIS).
- **Protocol:** Port 8443 speaks plain **HTTP**, not HTTPS (verified — TLS handshake fails, plain `curl http://` works). Port 5985 also plain HTTP (standard WinRM).
- **Unauthenticated baseline signature:** any unknown route → `302 Found`, `Location: /login`, 0-byte chunked body. Used this to filter ffuf noise.
- **Public unauthenticated routes:**
  - `GET /login` — 200, login form (POST password; see below). Evidence: web/8443_login.html
  - `GET /css/style.css`, `GET /favicon.svg` — 200 static assets
  - `GET /api` , `GET /api/` — 403 JSON `{"error":"Authentication required"}` — confirms a real `/api` namespace distinct from the catch-all redirect
  - `GET /api/status` — **200, UNAUTHENTICATED**, JSON: `{"device":"Nexion DeviceHub DH-100","serial":"NX-DH-2024-B7042","firmware":"1.4.2","status":"online","uptime":532}` — leaks the device serial number. Evidence: web/8443_api_status.json
  - `POST /api/scan` — 200 (no auth required), JSON `{"success":true,"documentDetected":true,"image":"/api/scan/last-capture",...}` — simulates a document scan
  - `GET/POST /login/badge` — "Staff Badge" scan feature; POST (any body) → `{"success":false,"error":"Invalid badge format"}`. Exact expected badge format not yet determined (tried raw string, JSON {badge:}, {id:}, {badgeId:}, form badge= — all same generic error). Marked `[unconfirmed]` whether this is a viable second auth path.
  - ffuf against root and `/api/` (raft-medium-words.txt, 63k words, filtered 302 baseline) found NO other hidden routes besides the above. Evidence: fuzz/ffuf_8443_root.json, fuzz/ffuf_8443_api.json
- **Login page hint (verified source — view-source of /login):** `title` attribute on "Forgot your password?" link reads: *"The default password is the device serial number included in your DeviceHub packaging."*
- **AUTH BYPASS VERIFIED:** `POST /login` with `password=NX-DH-2024-B7042` (the serial leaked by unauthenticated `/api/status`) → `302 Found`, `Location: /dashboard`, `Set-Cookie: nxsession=<token>`. Followed up with `GET /dashboard` using that cookie → `200 OK`, real dashboard HTML (title "Nexion DeviceHub — Dashboard"). **Full login confirmed working end-to-end.** Evidence: web/8443_dashboard.html, loot/cookies.txt
- **Authenticated pages mapped** (all 200 with session cookie): `/dashboard`, `/scanner`, `/printer`, `/logs`, `/settings`. Evidence: web/8443_dashboard.html, web/8443_scanner.html, web/8443_printer.html, web/8443_logs.html, web/8443_settings.html
- **Authenticated API routes referenced in dashboard JS** (not yet invoked beyond what's listed): `POST /api/scanner/power`, `POST /api/printer/power`, `PUT /api/scanner/settings`, `PUT /api/printer/settings`, `POST /api/scanner/test-image` (file upload, client-side accepts only image/jpeg,image/png via `<input type=file>` — server-side validation UNKNOWN, classic candidate for upload-based attack), `DELETE /api/scanner/test-image`, `GET /api/scanner/test-image` (confirmed works: returns `{"hasImage":true,"size":12545}`).
- **Sidebar link** "Return to Kiosk" points to `http://localhost:5173` — suggests a second internal-only frontend (likely a dev server / SPA) bound to localhost on the box, not reachable externally. `[unconfirmed]` whether reachable via SSRF through this app.
- **/settings page confirms:** Auth Mode = "Password (device serial)", Listen Port 8443, Serial NX-DH-2024-B7042, Firmware 1.4.2.
- **`POST /api/scanner/test-image` — fully characterized, NOT exploitable:**
  - Size-only validation: `{"error":"Image must be between 100 bytes and 10MB"}` — **no Content-Type check, no magic-byte/content check at all.** Verified by successfully uploading raw HTML/JS (`<html><script>alert(1)</script>...`) with header `Content-Type: image/jpeg` → `200 {"success":true,...}`. Also verified same with `Content-Type: text/plain` — content type is completely ignored server-side.
  - No filename is ever sent by the real client (`fetch(url,{method:'POST',body:input.files[0]})` — raw binary body, not multipart). Manually tried multipart/form-data with path-traversal filenames (`../../../../windows/temp/shell.aspx`) — server correctly parses multipart and extracts just the file-part bytes (confirms it CAN parse multipart) but filename is never used/stored anywhere discoverable — no path traversal possible, no write-outside-upload-dir found.
  - Retrieval is only via `GET /api/scanner/test-image/preview`, which **always forces `Content-Type: image/jpeg` in the response regardless of what was uploaded** — no stored-XSS via content-type reflection, no code execution path (not served from disk/static handler, served from an in-memory/managed blob by the app itself).
  - Fuzzed common upload/static dirs (`/uploads/ /upload/ /files/ /images/ /scans/ /data/ /app_data/ /static/ /tmp/ /temp/ /documents/ /docs/ /media/`) — all hit the generic 302 catch-all, none exist.
  - `PUT` on `/api/scanner/test-image` → 404 (PUT only valid on `/api/scanner/settings`). JSON mass-assignment tested on `/api/scanner/settings` (extra fields like `command`, `path`, `host`) and `/api/printer/restart`, `/api/printer/test-print` (extra fields `command`, `script`, `path`, `file`) — all silently ignored, no injection effect observed, no verbose errors (the app uses clean `System.Text.Json` parsing and returns tidy `JsonException.Message` text, no stack traces, no file paths — e.g. malformed JSON → `{"error":"'n' is an invalid start of a property name...”}`, wrong JSON type → `{"error":"The requested operation requires an element of type 'Object', but the target element has type 'Array'."}`). **No command/path injection surface found in settings/printer/scanner APIs.**
  - `/logs` page: read-only activity feed (timestamps + byte counts of our own test uploads), no filenames logged, no injection reflection — dead end, confirmed low value.
- **`/login/badge` — exhaustively retested this round, conclusively a dead/broken feature, NOT exploitable (yet):**
  - With `Content-Length: 0` (true empty body, matching what the real client JS sends: `fetch('/login/badge',{method:'POST'})` with no body) → consistent new error message `{"success":false,"error":"Badge scan failed: Parameter is not valid."}` — this is the literal text of a .NET GDI+ `ArgumentException` (classic `new Bitmap(stream)` failure), confirming the backend unconditionally attempts to decode the POST body as an image via GDI+/System.Drawing.
  - Tried: raw fake-magic-bytes JPEG, a real decodable JPEG (PIL-generated), the real captured `last-capture.bin` image (valid, confirmed-decodable 300x300 JPEG), multipart with field names `badge`/`image`, `application/octet-stream`, added `Referer`/`Origin: http://localhost:5173` headers to mimic the real frontend's origin — **every single variant returns the identical "Parameter is not valid." error**, including with a genuinely valid, real, already-rendering JPEG. This proves the endpoint is broken/non-functional for ANY input (most likely a server-side bug such as not resetting the MemoryStream position before passing to `Bitmap()`, or simulated-hardware-absent design) — **not a format-guessing problem, this is a dead feature.**
  - **New finding — decoded the hidden QR content:** the dashboard's static `/api/scan/last-capture` demo image (fetched via `GET`, unauthenticated) is actually a QR code. Decoded with `zbarimg`: **`STAFF-T4-B7-042`**. Tried this value against `/login/badge` as raw text, JSON `{"badge":...}`, and form `badge=...` — still the same GDI+ "Parameter is not valid" error (confirms backend never even gets to parsing a badge string — it dies trying to treat the body as an image first, regardless of content). Saved to loot/qr_decode_result.txt and loot/last-capture_QR_decoded_STAFF-T4-B7-042.jpg.
  - `/api/scan` / `/api/scan/last-capture` always returns the exact same static demo image (byte-identical across 5 repeated `POST /api/scan` + `GET last-capture` calls) — it's a hardcoded demo asset, not a live/randomized capture.
- **MAJOR NEW DISCOVERY — second kiosk frontend confirmed reachable only via RDP GUI session (not externally, port 5173 confirmed filtered/timeout from attacker):** RDP as `KioskUser` lands directly (auto-logon, no Windows login prompt shown) into a full-screen Chromium-based kiosk app branded **"HTB Airways — Self Check-In"** (T4, Gate B7, Kiosk #042 — same theming as DeviceHub, confirms this is the `localhost:5173` app the DeviceHub sidebar's "Return to Kiosk" link referenced). Screenshots saved under `loot/rdp_screens/`.
  - Home screen: "SELF CHECK-IN — Touch screen to begin" + a **"STAFF LOGIN"** button (top-right).
  - STAFF LOGIN → "Staff Authentication — Place your staff badge face-down on the scanner" → **SCAN BADGE** button. Clicking it shows "Scanning badge..." then always fails: **"Could not read badge barcode."** Tried sending keystrokes via `xdotool type` (the QR value `STAFF-T4-B7-042`) immediately after clicking Scan Badge, before the ~3s animation completes — no effect, same failure. This UI path is consistent with (and likely drives) the broken `/login/badge` backend endpoint above.
  - Self Check-In flow (Touch to begin) → Language select (20 languages, cosmetic) → **"Find Your Booking"** form with 4 lookup tabs: **Booking Ref / Last Name**, **ID / Passport**, **FF / Frequent Flyer**, **ET / E-Ticket**. This gates further steps in the top nav (`DOCUMENTS`, `SEATS`, `BAGGAGE`, `BOARDING PASS` are all disabled/non-navigable until a valid lookup succeeds — confirmed by directly clicking those nav tabs, no state change).
  - **Input fields are deliberately touch-only hardened:** the on-screen fields **ignore physical keyboard input entirely** (`xdotool type`/`xdotool key` into a focused field produces no text) **and ignore clipboard paste** (set X clipboard to `' OR '1'='1` via `xclip`, focused field, sent `ctrl+v` — no change to field value). The *only* way to enter text is clicking the app's own on-screen keyboard, which exposes just `A-Z`, `0-9`, space, and `-` (hyphen) — **no quote, semicolon, or parenthesis characters available**, which blocks classic string-break SQLi/NoSQLi payloads from being enterable via the UI at all.
  - Tried `BOOKING REF=ABC123` / `LAST NAME=SMITH` (plausible-looking demo values, not a guess spree) → `"Booking not found. Please check your details and try again."` — clean, generic error, no verbose/stack-trace leak.
  - **No backend API endpoint for this lookup exists on port 8443** — tried `/api/booking/lookup`, `/api/bookings/lookup`, `/api/checkin/lookup`, `/api/checkin/find`, `/api/flights/lookup`, `/api/reservation/lookup`, `/api/pnr/lookup`, `/api/booking`, `/api/bookings`, `/api/checkin` — **all hit the generic unauthenticated 302→/login catch-all**, i.e. none of these routes exist on the 8443 app. The Airways app's backend (if any) must live on a port/process only reachable from `localhost` on the box itself (consistent with port 5173 itself being externally filtered) — we have no code-execution primitive yet to query `localhost` from inside the box to find it.
  - **All standard AND several additional kiosk-escape shortcuts retested/newly tried inside this specific app and failed:** `F12` (devtools), `Ctrl+Shift+Esc` (Task Manager), `Alt+Tab`, `Ctrl+L` (Chrome address-bar focus), plus a 6-second long-press on the logo (checking for a hidden dev-menu gesture) — no effect in every case. Combined with the previously-tried `F11, Alt+F4, Ctrl+N/T/W/P/S/U, Win, Win+R/E, Ctrl+Esc, Ctrl+Alt+End, right-click`, this is now a very thoroughly exhausted list — strongly suggests a global low-level keyboard/input hook is blocking all non-touch interaction with the OS chrome, by design.

## Credentials & Secrets
| User | Secret | Source | Works on? |
|------|--------|--------|-----------|
| (device login) | `NX-DH-2024-B7042` (device serial, used as password) | Unauthenticated `GET /api/status` | VERIFIED — logs into Nexion DeviceHub web app (`/login` → `/dashboard`, session cookie `nxsession`) |
| `KioskUser` | `K!0sk2026#` | Disclosed in plaintext on authenticated `/dashboard` page (shown for both "Passport Scanner — Nexion DocReader SR-4200" and "Boarding Pass Printer — Nexion TP-820" device credential fields, click "show" reveals via `toggleCred()` JS — value is already in the page source, not fetched live) | **RDP (3389): WORKS** — confirmed real Windows auth success (xfreerdp connects, lands in a kiosk desktop/app, not a login prompt — screenshots in loot/rdp_screens/). Session is locked to a kiosk-mode browser shell with no explorer.exe access found (see Vulnerabilities section for exhaustive escape-attempt list). **WinRM (5985): FAILS** — re-verified via `nxc winrm`, explicit `[-]` auth rejection, hostname resolves as `KIOSK-042`. Also sprayed both known passwords (`K!0sk2026#`, `NX-DH-2024-B7042`) against common usernames (`Administrator/administrator/admin/Admin/kiosk/Kiosk/nexion/Nexion/devicehub/DeviceHub/svc/service/KioskAdmin`) on WinRM — **all 26 combinations failed**, no valid WinRM account found. |
| QR decode: `STAFF-T4-B7-042` | — | Decoded from the unauthenticated `/api/scan/last-capture` static demo JPEG via `zbarimg` | Tried as a badge value against `/login/badge` in multiple encodings — **does not work** (endpoint fails identically for all inputs, see below) |

## Vulnerabilities / Attack Paths
| Component | Version | CVE/Technique | Status |
|-----------|---------|----------------|--------|
| Nexion DeviceHub login | app-specific | Info disclosure (unauth `/api/status` leaks serial) → auth bypass (serial is default device password) | **CONFIRMED WORKING** — see Credentials table |
| `KioskUser` / `K!0sk2026#` on RDP (3389) | — | Credential reuse for Windows OS login | **CONFIRMED WORKS** but lands in locked kiosk browser shell, not explorer — breakout NOT YET FOUND despite exhaustive shortcut testing (see Web/App Surface section for full list: F11,Alt+F4,Ctrl+N/T/W/P/S/U,Win,Win+R/E,Ctrl+Esc,Ctrl+Alt+End,right-click,F12,Ctrl+Shift+Esc,Alt+Tab,Ctrl+L,long-press-logo, physical-keyboard-into-form-fields, clipboard-paste-into-form-fields — ALL FAILED) |
| `KioskUser` / `K!0sk2026#` on WinRM (5985) | — | Credential reuse | **CONFIRMED FAILS** (401/auth rejected), also sprayed against 12 common usernames — all fail |
| `POST /api/scanner/test-image` | — | Unrestricted file upload (no content-type/magic-byte validation at all) | **CONFIRMED present but NOT exploitable** — no filename control (no path traversal), retrieval always forced to `image/jpeg` content-type (no stored XSS/RCE path found) |
| `/login/badge` staff badge scanner (both the DeviceHub backend route AND the "HTB Airways" kiosk's Staff Login → Scan Badge UI) | — | Hoped to be an auth-bypass/injection point | **CONFIRMED DEAD/BROKEN** — backend always throws a GDI+ "Parameter is not valid" image-decode error regardless of input (empty body, real valid JPEG, fake JPEG, multipart, various content-types/headers all tested) — do not keep probing this, it is not currently exploitable without a different primitive |
| `http://localhost:5173` "HTB Airways Self Check-In" kiosk app | — | Separate, previously-unknown frontend only reachable via the RDP GUI session itself (port 5173 confirmed externally filtered) | **NEW OPEN LEAD, BLOCKED** — has a "Find Your Booking" form (Booking Ref/Last Name, Passport, Frequent Flyer, E-Ticket tabs) that gates a further Documents/Seats/Baggage/Boarding-Pass flow. No backend API for this found on port 8443 (9 plausible paths tried, all miss). Input fields block physical-keyboard AND clipboard-paste entry — only an on-screen virtual keyboard (A-Z,0-9,space,hyphen only, no quote/semicolon chars) can enter data, which blocks classic string-break SQLi from the UI. Need either: (a) a way to execute code/commands on the box to find what port/process backs this app's API, or (b) a legitimately-valid demo booking reference/passport number we don't currently have, to reach the `DOCUMENTS` step (which may have its own file-upload — a plausible RCE/breakout vector if the native OS file-picker dialog is used, since that's a classic kiosk-escape technique — **UNTESTED, blocked on reaching that step**). |

## Status (this round, @Exploit_Agent)
All currently-known leads are exhausted with NO new foothold obtained this round:
1. RDP client-side alternate-shell/RemoteApp bypass (`/shell:`, `/app:`) — confirmed blocked server-side (see Failed Attempts).
2. DeviceHub dashboard JS hardcoded internal API URL — none found beyond the already-known `localhost:5173` link.
3. `/logs` + newly-found `/api/printer/queue` for a real seeded booking record — none found, only scanner/printer housekeeping entries.
4. Generic booking-lookup guesses via the kiosk GUI (`ABC123/SMITH`, `TEST123/TEST`, `DEMO123/DEMO`, `HTB2026/HTB`) — all "Booking not found."

**No OS-level shell obtained. No user.txt captured.** Still stuck with: a valid but kiosk-locked RDP session as `KioskUser`, and an authenticated DeviceHub web session — neither yields code execution or file read yet. The most promising remaining idea (untested, needs new input): reach a real/valid booking reference so the Self Check-in flow progresses past lookup to the `DOCUMENTS` step, which may expose a native OS file-picker dialog (classic kiosk breakout) if it uses a real file upload — but we have no valid PNR and no way to enumerate one without brute-forcing beyond the time-boxed budget, or finding the real backend (likely on a box-internal-only port/process backing `localhost:5173`, which we cannot reach without existing code execution — a chicken-and-egg problem).

## Access Obtained
- Web app session only: authenticated `nxsession` cookie for Nexion DeviceHub dashboard (not an OS shell, not user.txt). Cookie value used during recon: `cb5be8d90ef5492ea411265042425683` (will likely expire; reproduce via `POST /login` with `password=NX-DH-2024-B7042`).
- **RDP (3389) as `KioskUser`/`K!0sk2026#`: Windows authentication CONFIRMED SUCCESSFUL** (via `xfreerdp`). Historically landed in a locked kiosk app with no breakout found — **NOW SUPERSEDED, see KIOSK BREAKOUT below, full cmd.exe shell obtained.**
- Repro (base RDP connect): `Xvfb :99 -screen 0 1280x800x24 &` then `DISPLAY=:99 xfreerdp /v:10.129.79.205 /u:KioskUser /p:'K!0sk2026#' /cert:ignore /w:1280 /h:800 +clipboard /sec:rdp` then `DISPLAY=:99 import -window root screenshot.png` to observe, `DISPLAY=:99 xdotool mousemove X Y click 1` to interact.

### KIOSK BREAKOUT — CONFIRMED WORKING, full shell obtained
**Technique: Windows OS-level accessibility shortcuts are NOT blocked by this AssignedAccess/kiosk lockdown, unlike every app/browser-level shortcut and RDP client-side shell override.**

Exact working chain (reproduced once, screenshots in `loot/rdp_screens/01` through `26`):
1. Connect fresh RDP session as `KioskUser`/`K!0sk2026#` (lands on "SELF CHECK-IN" kiosk home screen).
2. Send `Ctrl+Win+Enter` (toggles Narrator) — no immediately visible effect on its own.
3. Send `Win+U` (Ease of Access Settings shortcut) — **this surfaced a genuine native Windows dialog titled "Narrator updates"** (a Narrator first-run/changelog popup, NOT part of the kiosk app, with its own title bar, close button, and real hyperlinks: "Bluetooth and devices settings", "Configure Braille Displays settings", "Narrator guide"). This is the actual breakout point — the dialog is rendered by the OS accessibility stack and sits outside the kiosk's app-level lockdown/keyboard-hook.
4. Clicked the **"Narrator guide"** hyperlink (click once to focus it, then `Return` to activate) → this launched a **full, real Microsoft Edge browser window** with normal window chrome (minimize/maximize/close, tabs, address bar) — not sandboxed/kiosked at all. (Page itself failed to load — `go.microsoft.com` DNS — expected, no real internet from this lab network; irrelevant, the window itself is the win.)
5. In Edge's address bar (`Ctrl+L`), navigated to `file:///C:/Users/` → Edge natively renders a directory listing for local paths. Browsed to `file:///C:/Users/KioskUser/Desktop/user.txt` and read the flag directly in-browser.
6. For a **real interactive shell** (not just file read): in Edge, pressed `Ctrl+S` ("Save As") to open a genuine native Windows common Save-File-Picker dialog. In that dialog: set "Save as type" dropdown from "TXT File" to **"All files"** (critical — the default type filter hides `.exe` from view/search). Typed `C:\Windows\System32\cmd.exe` directly into the dialog's address/breadcrumb bar (`Ctrl+L` equivalent — click the breadcrumb area) and pressed `Return`. **This launched `cmd.exe` directly as a real OS window** (classic file-picker-dialog kiosk-escape trick: a Save/Open common dialog is real Explorer-shell-hosted code, and navigating it to an executable + "opening" it executes it, bypassing whatever shell-replacement/AssignedAccess policy governs the kiosk's own initial program).
7. Verified in the resulting cmd.exe: `whoami` → `kiosk-042\kioskuser`; `hostname` → `KIOSK-042`; `type C:\Users\KioskUser\Desktop\user.txt` → `[REDACTED-HTB-FLAG]` (matches the file:// read, cross-confirmed).

**Key screenshots:** `loot/rdp_screens/02_winu_easeofaccess.png` (native Narrator dialog appears), `06_narrator_guide_click.png`/`07_narrator_guide_after_enter.png` (real Edge window opens), `08_file_users.png`/`09_kioskuser_desktop.png`/`11_usertxt_clean.png` (file:// filesystem browsing + flag), `20_allfiles_selected.png` (All files filter fix), `23_after_full_path_enter.png`/`24_cmd_whoami_flag.png`/`26_systeminfo.png` (live cmd.exe shell, whoami, flag, systeminfo).

**Environment of the shell:** Windows 11 Pro, Build 26100 (OS Version `10.0.26100 N/A Build 26100`), host `KIOSK-042`, user `kioskuser`. `whoami /groups` shows `KIOSK-042\Printer Administrators` — a **custom local group**, not built-in Administrators — as an enabled group for this user. No admin privileges observed yet in `whoami /priv` (only `SeChangeNotifyPrivilege` enabled; `SeUndockPrivilege`, `SeIncreaseWorkingSetPrivilege`, `SeTimeZonePrivilege` present but disabled — all standard non-admin user privileges).

## Flags
- **user.txt:** [x] `[REDACTED-HTB-FLAG]` — captured from `C:\Users\KioskUser\Desktop\user.txt` both via Edge `file://` view and via `type` in a real cmd.exe shell (identical value, cross-verified). Saved to `loot/user.txt`.
- **root.txt:** [ ] not captured — see "PrivEsc progress" below, genuinely blocked on finding the restart trigger, not on the exploit primitive itself.

## PrivEsc progress (resumed session) — primitive is READY, trigger mechanism NOT FOUND
**The actual privesc bug is confirmed and the payload is already deployed. What's missing is purely how to make it execute.**
- `KIOSK-042\Printer Administrators` (KioskUser's group) has **Modify (M)** rights on `C:\Program Files\Nexion Systems\Printer\publish\plugins\` (confirmed via `icacls`). The main exe/folder above it does NOT grant this — only the plugins subfolder, confirming this is the intended vector.
- A working .NET payload DLL (`Plugin.cs`, source at `C:\Users\KioskUser\Downloads\evilplugin\`) is already compiled and sitting at `...\plugins\NexionHelper.dll` (overwritten) and `...\plugins\EvilHelper.dll` (copy, to test create-vs-modify file events). On load, it writes `whoami /all` to `C:\ProgramData\Nexion\pwned_as_system.txt`, adds KioskUser to local Administrators, and reads+exfiltrates `C:\Users\Administrator\Desktop\root.txt` to `C:\ProgramData\Nexion\root_leak.txt`.
- `NexionPrinter.exe` (PID 2180 throughout this entire engagement — never restarted) runs in **Session 0 ("Services")**, confirmed via process-parent chain: `NexionPrinter.exe(2180) <- svchost.exe(1808) <- "Schedule" service (Task Scheduler, running as LocalSystem)`. So it IS launched by a Scheduled Task as SYSTEM, not a registered Windows Service (`Get-CimInstance Win32_Service` with `PathName -like '*Nexion*'` returns nothing).
- The task lives in the Task Scheduler **root folder (`\`)**, which `schtasks /query` and `Get-ScheduledTask` both refuse to enumerate for this non-admin account ("no scheduled tasks presently available at your access level"). Guessed 6 plausible task names directly (`NexionPrinter`, `NexionPrinterWatchdog`, `Nexion Printer Service`, `PrinterWatchdog`, `DeviceHub`, `NexionWatchdog`) — all "cannot find the path specified." Don't keep guessing task names blindly.
- Found `C:\ProgramData\NexionPrinter.bat` — a batch watchdog: `:loop` → run `NexionPrinter.exe` **synchronously** (blocks until it exits) → `timeout /t 3` → `goto loop`. This proves the exe is expected to exit periodically under normal operation (otherwise the watchdog is pointless) — but it has run continuously, uninterrupted, for the entire multi-hour engagement, meaning it does NOT crash/exit under the inputs we've thrown at it so far.
- **Exhaustively tried to force a restart/reload — ALL FAILED, do not repeat:**
  - `taskkill /PID 2180 /F` → `Access is denied` (not SYSTEM/admin, as expected)
  - `Stop-Process`/direct process termination — same access-denied expectation, not separately re-tested (would fail identically)
  - Web app's device-control buttons are **cosmetic/fake**, confirmed again this round: `POST /api/printer/restart` → `{"success":true,...}` message but PID unchanged; `POST /api/scanner/power` and `/api/printer/power` (both on/off) → always `{"success":true,"powered":true}` regardless of input, no real effect
  - `POST /api/scan` (to test "does a scan event invoke the plugin live, no restart needed") → no proof files appeared
  - Copying the payload DLL under a NEW filename (`EvilHelper.dll`, to test "does a FileSystemWatcher fire on file-CREATE even if it doesn't on overwrite-MODIFY") → no proof files appeared. **Conclusion: plugins are loaded ONLY at process startup, no live-reload of any kind.**
  - `shutdown /r /t 5` → `Access is denied` (no SeShutdownPrivilege for this user/group)
  - Checked the REAL Windows Print Spooler service as an alternate angle (in case "Printer Administrators" was about that, not the Nexion app): **Spooler service is STOPPED**, no `PointAndPrint` policy registry key exists, `sc sdshow Spooler` shows only default SDDL (no custom grant for our group). **This rules out PrintNightmare/Point-and-Print entirely — confirmed not the vector, don't revisit.**
  - Tried `Start-Process explorer.exe` hoping for a real desktop/taskbar/system-tray icon with a "restart service" context-menu option — produced a black screen on the RDP session (process still alive per `pgrep`, but display went blank and didn't recover). Left unresolved; reconnecting the RDP session fresh is the way to recover if this is hit again (don't keep retrying explorer.exe in the same broken session).
- **Additional generic privesc checks this round — ALL NEGATIVE, confirmed, don't repeat:**
  - `cmdkey /list` → "Currently stored credentials: * NONE *"
  - `Get-ChildItem C:\Users` → only `Administrator`, `KioskUser`, `Public` — no hidden extra accounts
  - `AlwaysInstallElevated` (both HKLM and HKCU policy keys) → not set at all (registry key doesn't exist)
  - Full `Get-CimInstance Win32_Service` dump (all ~250+ services) filtered for `Nexion|Gate|Kiosk|Document|Boarding|DocReader|Scan|DH-100|Printer` in Name/DisplayName/PathName → only stock Windows hits (`PrintNotify`, `PrintScanBrokerService`, `BTAGService` etc.) — **conclusively zero custom service of any kind tied to the Nexion app.** It really is Task-Scheduler-only, as established.
  - `C:\Windows\System32\Tasks` → `Access to the path ... is denied` even just to **list** the directory (not just to read a specific file) — the raw-XML-on-disk trick doesn't work here, this folder's NTFS ACL itself blocks non-admin listing, not just the Task Scheduler API layer.
  - `Microsoft-Windows-TaskScheduler/Operational` event log → zero events found for Task Start/Stop (IDs 200/201) in the most recent 2000 entries — this operational log appears to not be populated/enabled on this box, so it can't be used to discover the task name or trigger type either.
  - Got a full real desktop this round (`Start-Process explorer.exe` succeeded fully this time, including completing a first-logon OOBE flow) — checked system tray for a Nexion-specific icon with a context-menu restart option: **none found**, taskbar/tray is minimal/standard.
- **Leading hypothesis for the real trigger (untested, needs either a real booking or a different idea):** `NexionPrinter.exe` may not be a persistent server at all, but something that's supposed to process one print/scan job and exit each time — it just happens to be sitting idle with nothing to process for the entire engagement so far. If so, actually completing a real boarding-pass print through the "HTB Airways Self Check-In" kiosk (localhost:5173, reachable only via the RDP GUI session) might be what makes it exit/restart naturally with our plugin loaded. **That flow is gated behind the same "Find Your Booking" form requiring a real name + booking confirmation code that was never available (the original Layover-engagement hint)** — meaning Layover's intel may be the missing piece for ROOT specifically, even though user.txt was obtained via an unrelated kiosk-escape bug that bypassed needing it. This reconciles the original clue with everything found so far. **Needs user input/confirmation before spending more agent rounds guessing other trigger mechanisms.**

## MINED FROM SCREENSHOTS 2026-10-05 — facts the written summary above never captured
<!-- Reconstructed by reading privesc_40 through privesc_170 rdp_screens/*.png directly (not fabricated,
     each fact below was visually read from a real terminal screenshot). The prior summary undersold
     how far the previous session actually got. -->

- **Local-only backend API found and fully mapped** (this is the `localhost:5173`/DeviceHub-sidebar-link
  backend the old summary said was unreachable): `127.0.0.1:3001` (Node.js, confirmed via `netstat -ano`
  → PID bound to `node.exe`, PPID 3600). Routes recovered by downloading `/assets/index-BqHnJ3Je.js` and
  regexing it: `POST /api/session/start {kioskId,language}` → returns `sessionId` + `X-Session-Token`
  (header name confirmed literal in bundle), `GET /api/session/:id`, `DELETE /api/session/:id`,
  `POST /api/checkin/lookup {type,value,lastName}` (type enum: `pnr`|`passport`|`frequent_flyer`|`eticket`,
  `value` is alphanumeric-only validated server-side), `POST /api/checkin/perform`, `GET /api/seats/map`,
  `POST /api/seats/assign`, `POST /api/boarding-pass/issue`, `POST /api/documents/scan`,
  `POST /api/staff/badge-scan {badge}`.
- **Badge-scan via the real API**: `POST /api/staff/badge-scan {"badge":"STAFF-T4-B7-042"}` →
  `{"success":false,"step":"qr","error":"Could not read badge barcode"}` — confirms this endpoint expects
  an actual scanned QR/barcode image, not a bare string; the known QR value alone isn't sufficient input.
- **SQLi was tried against `/api/checkin/lookup` and is NOT confirmed exploitable**: `value` field is
  server-validated alphanumeric-only (blocks quote injection there). `lastName` field accepts arbitrary
  strings (no filter) — tried `lastName="x' OR '1'='1"` → clean `{"code":"NOT_FOUND"}`, not a DB error and
  not a bypass, consistent with a parameterized query. **Treat this as a dead end, not an open lead** —
  don't keep re-trying SQLi here without a genuinely new payload class (e.g. second-order, blind timing).
- **MySQL 8.0 confirmed installed, listening 127.0.0.1:3306, service `MySQL80` runs as `LocalSystem`**
  (`sc qc MySQL80` → `SERVICE_START_NAME: LocalSystem`) — i.e. **if valid MySQL credentials with FILE
  privilege are ever found, that is a direct SYSTEM code-execution path via UDF (`INTO OUTFILE` a
  malicious DLL + `CREATE FUNCTION ... SONAME`).** This was recognized but not completed last session.
  `root` login was tried with no password, the device serial (`NX-DH-2024-B7042`), and KioskUser's
  password (`K!0sk2026#`) — **all three failed** (`Access denied for user 'root'@'localhost'`). The
  **real credential the Node.js backend itself uses to talk to MySQL was never located** — worth finding
  (likely in the Node app's own source/config/env, which was never found either — `C:\inetpub` was
  checked and is empty; Node app's actual install directory is still unknown).
- **`NexionPrinter.dll` (the small 6144-byte file alongside `NexionPrinter.exe` in the publish folder,
  NOT the exe itself) contains a real class/namespace string: `NexionPrinter.TriggerDir`**, found via
  raw string extraction, sitting near `LoadPlugins`, `GetFiles`, `Exists`, `Environment`, `AppContext`,
  `Assembly.get_BaseDirectory` in the string heap — strongly suggestive of a real directory-polling/watch
  mechanism for triggering a reload. **This was never actually resolved to a literal watched path** — the
  follow-up search for trigger/restart/flag-style strings was run against `NexionPrinter.exe`'s strings
  (found nothing) rather than `NexionPrinter.dll`'s strings (where `TriggerDir` actually lives) — this is
  a real gap, not a dead end.
- **`C:\ProgramData\Nexion` — KioskUser has FULL CONTROL here** (`icacls` → `KIOSK-042\KioskUser:(I)(F)`),
  not just Modify-on-a-subfolder like the plugins directory. This is a much bigger write primitive than
  the old summary's "Modify rights on plugins folder" framing suggested, and the name match (`Nexion`)
  makes it a very plausible home for whatever `TriggerDir` points at. Folder currently contains only
  `devices.json` and `test-scan.jpg` (both already app-managed runtime data, confirming the SYSTEM process
  actively reads/writes here). **Untested: create candidate trigger files/folders here (e.g. a `trigger`
  subfolder, a `.flag`/`.trigger` file, or touching `devices.json`) and watch whether `NexionPrinter.exe`'s
  PID changes/restarts.**
- The `NexionPrinter.bat` watchdog runs the exe **synchronously in a blocking loop** (`"...NexionPrinter.exe"`
  with no backgrounding, then `timeout /t 3`, then `goto loop`) — confirms the exe is DESIGNED to exit
  periodically under normal operation; it just hasn't under any input thrown at it yet. Startup banner
  string (UTF-16, decoded from raw bytes): `"[NexionPrinter] Nexion TP-820 Print service ready... waiting"`.
- Confirmed (again, final attempt): `taskkill`/`Stop-Process` on PID 2180 → access denied;
  `shutdown /r` → access denied (no `SeShutdownPrivilege`); a full `Get-ScheduledTask` dump (saved to
  `alltasks.txt`) grepped for `restart|Printer|NexionPrinter|publish` → only unrelated stock Windows
  tasks matched (`PrinterCleanupTask`, `SvcRestartTaskLogon`) — the controlling task is confirmed still
  hidden from this account (root Task Scheduler folder, as before).

**Updated priority order for resuming root** (supersedes the old "leading hypothesis" paragraph below):
1. **Dump full strings (ASCII *and* UTF-16/Unicode) of `NexionPrinter.dll` specifically** (not the .exe)
   and search for the literal path `TriggerDir` resolves to, or any file-extension pattern it checks for.
2. **Probe `C:\ProgramData\Nexion` directly** given KioskUser's full control there — try creating a
   `trigger` subfolder and/or plausible flag files, and independently try touching/rewriting
   `devices.json` (already app-managed) — watch `Get-Process NexionPrinter` PID across each attempt.
3. Only if 1–2 go nowhere: hunt for the Node.js backend's own source/install directory (not yet found)
   to recover its real MySQL credentials, since LocalSystem-run MySQL + real creds = direct SYSTEM via
   UDF, independent of the plugin-DLL path entirely.
4. SQLi on `/api/checkin/lookup` — deprioritize, evidence suggests parameterized/not exploitable.

## Kiosk re-breakout attempt 2026-10-05 (post-respawn) — BLOCKED, new nuances learned
- The "Narrator updates" dialog is **not** strictly one-time-forever per user profile as
  previously assumed — toggling Narrator off/on (`Ctrl+Win+Enter` twice) DID re-trigger it
  once after it had already been shown and dismissed earlier in the same engagement. However
  this is **not freely repeatable** — after that one extra retrigger, repeated toggles (tried
  4x with 2-3s gaps) and fresh RDP reconnects no longer bring it back. The exact rule governing
  when it will/won't retrigger is still unknown — don't assume either "never again" or "always
  retriggerable via toggle," test cheaply before relying on it.
- **New blocker, fully characterized**: clicking the "Narrator guide" hyperlink inside that
  dialog correctly activates it (confirmed — it reliably produces a follow-up "how do you want
  to open this link" flyout), but that follow-up flyout **renders almost entirely off-screen**,
  clipped to only its bottom ~18px sliver in the top-left corner of the virtual desktop,
  regardless of the RDP session resolution (confirmed identical clipping at both 1280x800 and
  1920x1080 — not a resolution-mismatch issue, don't re-test different resolutions for this).
  Most plausible cause: it's a taskbar/notification-area-anchored flyout that normally opens
  upward from a tray icon; this kiosk has no taskbar, so it anchors near y=0 and the bulk of
  it renders off the top of the screen. Clicking the visible "Just once" sliver at its apparent
  coordinates did not register (tried multiple precise coordinates). Keyboard Tab/Enter also
  did not reach it (focus appears to stay with the dialog/app behind it, not the flyout).
  **Not yet tried**: dragging the flyout into view, right-click on it for a context menu,
  checking if a *different* link in the same dialog (not "Narrator guide" specifically) avoids
  this flyout entirely — e.g. "Bluetooth and devices settings." is an `ms-settings:` deep link
  and should route straight to the Settings app with no browser-chooser flyout at all, but my
  click on it landed on the surrounding paragraph (Narrator's read-focus block) rather than the
  embedded hyperlink run itself and nothing opened — needs a more precise re-attempt (click
  exactly on the underlined blue text, confirm single-link focus highlight — not the whole
  paragraph — before pressing Enter).
- Session behavior: disconnecting the RDP client (killing `xfreerdp`) without an in-session
  logoff **resumes the same Windows logon** on reconnect (confirmed via persisted Narrator-
  active state and dialog-dismissed state surviving multiple reconnects) — contradicts the
  original engagement's note that "each connect is a fresh logon." Don't rely on reconnecting
  alone to get a clean slate; a ~2.5 minute disconnected wait was NOT enough to force a
  server-side session reset either (untested beyond that duration).
- **Recommendation for next session**: don't re-attempt the Narrator-dialog route cold without
  a specific new idea (precise click on a non-"Narrator guide" link, or dragging/right-clicking
  the clipped flyout) — it's expensive and the last several attempts all failed the same way.

## Failed Attempts (do not repeat)
- **RDP client-requested alternate shell/RemoteApp — CONCLUSIVELY BLOCKED SERVER-SIDE, do not retry.** Tested with FreeRDP 3.31.1:
  - `/shell:"cmd.exe"` + `/shell-dir:"C:\\"` → lands on identical kiosk "SELF CHECK-IN" screen (byte-for-byte same as no /shell at all).
  - `/shell:"C:\\Windows\\System32\\cmd.exe"` + `/shell-dir:"C:\\Windows\\System32"` (both `/sec:rdp` after confirming `/sec:nla` is rejected by server with `SSL_NOT_ALLOWED_BY_SERVER` — this box's RDP listener only accepts `/sec:rdp`, i.e. classic RDP security layer, not NLA/TLS) → still identical kiosk screen.
  - `/shell:"explorer.exe"` → still identical kiosk screen — proves the client-supplied AlternateShell value is being completely ignored/discarded by the server, not just "cmd.exe" being specially filtered.
  - `/app:"program:cmd.exe"` (RemoteApp/RAIL mode) → connection succeeds (new session, confirmed via `Logon Info V2 [KIOSK-042\KioskUser [N]]`, incrementing session IDs each connect — so it's NOT a single persistent locked session, each RDP connect is a fresh logon) but screen is **solid black**, FreeRDP log spams `xf_Pointer: Invalid appWindow` / `handle=0` continuously — RAIL window is never created, consistent with RemoteApp publishing not being configured on this RDS host (server has no allow-listed RemoteApp programs, so the RAIL request silently produces no window).
  - **Conclusion:** this RDS host enforces the initial program server-side (most consistent with the "Start a program on connection" / RDS-Tcp `InitialProgram` Group-Policy-style setting that overrides ANY client-requested shell, independent of the per-user `Winlogon\Shell` registry value) — the client-side alternate-shell/RemoteApp technique is a dead end on this box. Do not retry `/shell:`, `/app:`, or any other client-side "initial program" override flag; if revisiting kiosk escape, it needs a technique that doesn't rely on the client dictating the initial program (e.g. reaching a native file-picker/dialog from inside the kiosk app itself, or RCE via the web app).
  - Evidence: loot/xfreerdp_shellcmd_attempt1.log, loot/xfreerdp_shellcmd_attempt2.log (NLA rejection), loot/xfreerdp_shellcmd_attempt3.log, loot/xfreerdp_app_attempt1.log, loot/xfreerdp_app_attempt3.log, loot/xfreerdp_shellexplorer.log, screenshots loot/rdp_screens/07_altshell_cmd_attempt1.png through 12_altshell_explorer.png (all pixel-identical kiosk home screen except the black RAIL attempt).
- `/login/badge` (DeviceHub backend) — CONCLUSIVELY confirmed broken/dead for ALL input types this round (empty body, raw text, JSON `{badge:}/{id:}/{badgeId:}`, form `badge=`, real valid JPEG, fake-magic-byte JPEG, multipart with `badge`/`image` field names, various Content-Types, `Referer`/`Origin` headers matching the real frontend) — every variant returns either `{"error":"Invalid badge format"}` (empty/malformed non-image bodies) or `{"error":"Badge scan failed: Parameter is not valid."}` (GDI+ image-decode exception, happens even for genuinely valid real JPEGs) — **do not keep trying new body formats on this endpoint, it is not currently exploitable.**
- "HTB Airways" kiosk's own "Scan Badge" UI button — same dead-end, always ends in "Could not read badge barcode" regardless of keystrokes sent during the scanning animation.
- WinRM (5985) — `KioskUser`/`K!0sk2026#` rejected (re-verified). Also sprayed `Administrator, administrator, admin, Admin, kiosk, Kiosk, nexion, Nexion, devicehub, DeviceHub, svc, service, KioskAdmin` × both known passwords — all 26 rejected. Do not re-try WinRM with these same creds/usernames.
- RDP kiosk-escape keyboard/mouse shortcuts — full list tried and failed across two sessions: `F11, Alt+F4, Ctrl+N, Ctrl+T, Ctrl+W, Ctrl+P, Ctrl+S, Ctrl+U, Win, Win+R, Win+E, Ctrl+Esc, Ctrl+Alt+End, right-click, F12, Ctrl+Shift+Esc, Alt+Tab, Ctrl+L, 6-second long-press on logo`. Do not re-try these; if attempting further kiosk escape, try a genuinely different technique (e.g. reaching a native OS file-picker dialog via the check-in flow's Documents/passport-upload step, if a valid booking can ever be found).
- `/api/scanner/test-image` upload — confirmed NO content-type/magic-byte validation (accepts anything 100B–10MB) but NO path traversal (no filename ever sent/used) and NO way to retrieve/execute arbitrary content (preview endpoint always forces `Content-Type: image/jpeg`). Do not re-investigate this endpoint for RCE without a genuinely new angle (e.g. if a different endpoint is found that reads this stored blob with a different, attacker-influenced content-type).
- JSON mass-assignment on `/api/scanner/settings` (PUT), `/api/printer/restart` (POST), `/api/printer/test-print` (POST) with extra fields (`command`, `path`, `host`, `script`, `file`) — silently ignored, no effect, no verbose errors leaked (app returns clean `JsonException.Message` text only). Do not re-try extra-field injection on these without a new field name hypothesis grounded in actual evidence.
- Guessed 9 plausible REST paths for the "HTB Airways" booking-lookup backend on port 8443 (`/api/booking/lookup`, `/api/bookings/lookup`, `/api/checkin/lookup`, `/api/checkin/find`, `/api/flights/lookup`, `/api/reservation/lookup`, `/api/pnr/lookup`, `/api/booking`, `/api/bookings`, `/api/checkin`) — all hit the generic 302 catch-all (route doesn't exist on 8443). The real backend for this app is elsewhere (likely localhost-only on the box, reachable only from port 5173's own process) — don't re-guess more 8443 paths for this without new evidence it lives there.
- Fallback lead 1 (hardcoded internal API URL in DeviceHub JS) — re-checked all authenticated page inline `<script>` blocks (`dashboard.html`, `scanner.html`, `printer.html`, `logs.html`, `settings.html`) via grep for `5173`/`localhost`/`fetch(` — only same-origin `/api/*` calls and the already-known `http://localhost:5173` "Return to Kiosk" link exist. No second hidden backend URL found. Dead end.
- Fallback lead 2 (real booking record in /logs or printer job queue) — re-fetched `/logs` fresh (live) and discovered one previously-untested endpoint `GET /api/printer/queue` (200 OK, not in prior route list) → `{"queue":["[23:27:16] Test page — OK","[00:14:42] Test page — OK"]}` — only our own test-print entries, no booking/passenger data. `/logs` itself confirmed still just scanner/printer housekeeping (document byte-counts, admin logins, calibration) — no PNR/name ever logged. Dead end. (New route `/api/printer/queue` noted for completeness but not useful.)
- Fallback lead 3 (generic booking-lookup guesses via RDP GUI) — reconnected fresh (new xfreerdp session; noted input-click reliability issue below) and submitted the "Find Your Booking" (Booking Ref / Last Name tab) form via the on-screen keyboard for: `ABC123`/`SMITH` (re-confirmed), `TEST123`/`TEST`, `DEMO123`/`DEMO`, `HTB2026`/`HTB` — **all four return the identical "Booking not found. Please check your details and try again." error**, with the entered text visibly correct in both fields each time (screenshots loot/rdp_screens/40, 44, 46, 49). Stopped at 4 combos per the low-priority/time-boxed guidance rather than continuing to guess blindly — this path needs either a real seeded demo PNR (not found anywhere in logs/JS) or actual backend access to be productive, not more guessing.
- **Operational note on the RDP kiosk GUI session (xdotool/FreeRDP automation): click-through input intermittently stops registering on the outer "Touch screen to begin" attract screen after periods of inactivity/idle-timeout, while still working fine on inner-page buttons/fields.** Observed: after the in-app 2-minute session-timeout counter hit 0 and returned to the "SELF CHECK-IN" home attract screen, repeated `xdotool mousemove+click` (including on the always-present "STAFF LOGIN" button) had **zero effect** for several attempts, even though the FreeRDP process/log showed no disconnect and the screen was still live-updating. Killing and reconnecting xfreerdp fresh immediately restored full click responsiveness (confirmed by landing on Staff Authentication, then Self Check-in → language → booking form, all clicks working). Root cause not conclusively identified (candidates: RDPEI/ainput touch-channel state desync after idle, or an app-side idle/re-init quirk) — **workaround: if clicks stop registering in an RDP kiosk GUI session, kill and reconnect xfreerdp rather than retrying clicks indefinitely.**
- Ports 80/443 — not open at all on this host (confirmed via full port sweep); do not assume standard web ports.
- Port 5173 — confirmed externally filtered/unreachable (curl timeout from attacker), only reachable from inside the box itself (seen via the RDP kiosk session). Don't re-attempt direct curl to it from outside.

## Known Tech Weaknesses (reason from this, don't shotgun-guess)
<!-- Stack-specific knowledge: what this tech is KNOWN to break on. Every agent should
     read this and add to it BEFORE trying payload/shortcut variations blindly. -->
- **Backend stack:** `Microsoft-HTTPAPI/2.0` (raw `HttpListener`, not IIS/ASP.NET MVC/Kestrel) + `System.Text.Json` (clean error messages, no stack traces — don't expect verbose error leaks from this app).
- **`/login/badge` GDI+ "Parameter is not valid" on EVERY input (even valid JPEGs) — EXPLAINED, not a mystery:** classic `System.Drawing.Bitmap(stream)` requires a **seekable** stream; `HttpListenerRequest.InputStream` is **not seekable**. If the handler does `new Bitmap(Request.InputStream)` directly (no buffer-to-MemoryStream first), it throws this exact exception for ANY input, always. This is a genuine, unfixable-from-outside code bug — stop treating it as a payload-format puzzle. Only way it'd ever matter again: if some OTHER route buffers the body first and hands a seekable stream to the same decode path.
- **RDS kiosk lockdown — `AssignedAccess`/custom-Shell pattern:** Confirmed the RDS host enforces the initial program server-side (not registry `Winlogon\Shell` alone) — client `/shell:`/`/app:` RDP flags are a dead end here, proven not just assumed (see Failed Attempts). Known weakness classes for THIS category of lockdown that have NOT all been tried yet:
  - **Windows accessibility shortcuts — CONFIRMED WORKING BREAKOUT, do not re-derive, just reuse:** `Win+U` (Ease of Access Settings shortcut) surfaces a genuine native "Narrator updates" dialog with live hyperlinks outside the kiosk lockdown. Clicking its "Narrator guide" link opens a full unsandboxed Microsoft Edge window. From there, `file://` URLs browse the filesystem (got user.txt instantly) and `Ctrl+S` → Save-As dialog → set type filter to "All files" → navigate to `C:\Windows\System32\cmd.exe` → Enter → launches a real interactive cmd.exe as KioskUser. Full chain documented in "Access Obtained" section above. `Ctrl+Win+Enter` (Narrator toggle) alone showed no visible effect — it was `Win+U` specifically that surfaced the exploitable dialog.
  - Native file-picker dialogs reached via an in-app "Browse/Upload" feature (not an OS shortcut) are the single most common real kiosk-breakout vector in general — **turned out to be exactly how execution was ultimately achieved, just reached via the accessibility-dialog route (Edge's Save-As dialog) rather than the booking-flow upload step.** The booking-flow route is now moot/no longer needed.
  - RDS `/shell:`/`/app:` client overrides — CONFIRMED dead end on this box specifically (not a general Windows weakness, just doesn't apply here).
- **Chromium/Edge `--kiosk` flag behavior:** if `F11` does nothing, that's consistent with true `--kiosk` launch (not just maximized fullscreen) — don't keep re-testing browser-chrome shortcuts (Ctrl+T/N/W, address bar, devtools); they're reliably disabled by this flag. Accessibility shortcuts above are OS-level, not browser-level, so they're a genuinely different attack surface than what's been exhausted.
- **Check-before-repeat rule:** before trying a new technique, check (a) is this targeting a code path we've already proven structurally broken/blocked (don't retry), or (b) is this a genuinely distinct mechanism (different OS layer, different library, different trust boundary) from what's been tried? Only (b) is worth a new agent round.

## Agent Handoff Log
<!-- chronological agent-message blocks appended by the Orchestrator -->
