# GLOBAL CONTEXT MEMORY — Cap

> Single source of truth for the swarm. Every agent reads this on start and
> writes VERIFIED findings on finish. Mark uncertain items `[unconfirmed]`.

## Engagement
- **Box:** Cap
- **Target IP:** 10.129.106.230
- **Difficulty:** easy (Linux)
- **Started:** 2026-09-30
- **Current Access Level:** root
- **Current Phase:** COMPLETE (rooted)

## Open Ports & Services
<!-- port | proto | service | version | evidence file -->
- 21 | tcp | ftp | vsftpd 3.0.3 | nmap/services.txt
- 22 | tcp | ssh | OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu 20.04) | nmap/services.txt
- 80 | tcp | http | Gunicorn — "Security Dashboard" (Python app) | nmap/services.txt

## Web / App Surface
- /data/<id> & /download/<id> | Flask/Gunicorn "Security Dashboard" | **IDOR** — any user's PCAP downloadable | web/data0.html
- /download/0 | admin capture | contained cleartext FTP creds | loot/0.pcap

## Credentials & Secrets
- nathan | Buck3tH4TF0RM3! | pcap /download/0 (cleartext FTP) | works on FTP + SSH

## Vulnerabilities / Attack Paths
- Web /download/<id> | IDOR | download arbitrary capture -> creds | WORKING
- /usr/bin/python3.8 | cap_setuid+eip | setuid(0) -> root | WORKING

## Access Obtained
- foothold | nathan | SSH with pcap creds | shell | uid=1001
- root | root | python3.8 cap_setuid setuid(0) | command exec as uid=0

## Flags
- **user.txt:** [x] [REDACTED-HTB-FLAG] (nathan)
- **root.txt:** [x] [REDACTED-HTB-FLAG]

## Failed Attempts (do not repeat)

## Agent Handoff Log
