# The Story of Silentium — A Forgotten Password Reset, a Leaky Container, and a Root-Owned Git Server

*A plain-language account of how this box fell. For the exact commands see
`walkthrough.md`; this is the story of what happened and why it was hackable.*

---

## 1. A finance site with a staging server

Silentium looked like the website of a lending firm. Its "Leadership" page named
the staff — including one **"Ben, Head of Financial Systems."** That name turned
out to matter. Behind the scenes, a hidden sub-domain, **`staging.silentium.htb`**,
ran **Flowise** — a tool for building AI/automation workflows — the kind of thing
a team spins up for testing and forgets to lock down.

## 2. Hijacking an account through "forgot my password"

This version of Flowise had a known flaw (CVE-2025-58434) in its **password-reset
feature**. Normally "I forgot my password" emails *you* a secret reset link, so
only the real owner can use it. Here, the broken version **handed the reset token
straight back in its own response** — to whoever asked, no email, no proof of
identity.

So we asked to reset **Ben's** password (we had his name from the website),
caught the token the server foolishly returned, and used it to set a new password
of our own. We logged into Flowise as Ben — who happened to be an administrator.

## 3. From app admin to a shell (inside a box within the box)

Flowise had a second known flaw (CVE-2025-59528). One of its building blocks let
a user supply a chunk of configuration that the app then **executed as live
code** — meaning an admin could make the server run arbitrary commands. We did,
and got code execution.

But we landed inside a **Docker container** — a sealed, miniature machine-within-
the-machine that apps are often run inside to isolate them. Useful, but a
container is only a *wall*, not a vault, and this one had secrets written on the
inside of the wall: its **environment variables** held a batch of passwords. One
of them — labelled as an email (SMTP) password — turned out, through plain old
**password reuse**, to be **Ben's SSH password on the real host**.

We stepped out of the container and logged into the actual machine as Ben. The
first flag, `user.txt`, was ours.

## 4. From user to root: a code server running as the administrator

Ben had no special powers — he couldn't even use `sudo`. So we looked at what
else was running on the machine, and found a quiet internal service: a **Gogs**
server (another "store your source code here" app), reachable through yet another
hidden sub-domain.

Two facts made it fatal. First, it was an old version with a known flaw. Second —
and this is the real sin — it was **running as the administrator (root)** itself.

The flaw (CVE-2025-8110) was a **symlink trick**. A symlink is a "shortcut" file
that simply points at another file. Gogs let a user save file contents through
its interface, and checked that the *path* looked innocent — but it **followed
shortcuts without re-checking where they actually led.** So we uploaded a
shortcut that pointed at the administrator's list of trusted login keys, then
told Gogs to "save" some content to that shortcut. Because Gogs ran as root, it
followed the shortcut and **overwrote root's key file with our own key.**

We logged in as **root**. The box was fully owned.

> **A recurring theme:** the hidden Gogs sub-domain was un-guessable from the
> outside — we only found it by reading the server's own configuration *after*
> getting the first foothold. You often can't find the last door until you're
> already inside.

---

## 5. So why was it hackable?

1. **A password reset that skipped proving who you are.** Handing the reset
   token back to the requester turns "forgot password" into "take any account."
2. **Secrets stored inside a container's environment.** A container isolates a
   process; it does not hide the passwords you bake into it — and those passwords
   were reused on the host.
3. **Password reuse.** An email password doubled as a human's SSH login.
4. **A powerful service running as root.** A code server that only *needed*
   ordinary privileges was run as the administrator, so its one file-write bug
   became a direct path to total control.

## 6. What would have stopped us

- Never return password-reset tokens in a response — deliver them out-of-band,
  to the account owner only, and keep the software patched.
- Don't bake reusable, host-valid passwords into container environments.
- Stop reusing passwords across services and accounts.
- **Run services as the least-privileged account that works** — a code server
  should never run as root. If Gogs had run as an ordinary user, its file-write
  bug could not have touched root's keys.

---

*Silentium is an intentionally vulnerable training machine. Everything here was
done against an authorized lab target.*
