# The Story of Nexus — A Password in the Git History and a Helpful Root Robot

*A plain-language account of how this box fell. For the exact commands see
`walkthrough.md`; this is the story of what happened and why it was hackable.*

---

## 1. Three sites behind one address

Nexus looked like the website of an energy company — "Nexus Energy Authority."
But a single web server was quietly hosting **three** different sites, each
answering to a different name:

- **`nexus.htb`** — the public marketing page (dead quiet, nothing to grab).
- **`git.nexus.htb`** — a **Gitea** server (a place developers store source
  code), browsable by anyone, no login required.
- **`billing.nexus.htb`** — a **Krayin CRM**, a customer-management app whose
  login page we couldn't get past… yet.

## 2. The password someone thought they deleted

Developers using the code server had published a project that included a
configuration file — and in the file's **history**, in an early version, was a
live **database password**. Someone later realised the mistake and blanked it
out in a newer version. But here's the thing about version control: **it
remembers everything.** Deleting a secret in the latest version doesn't remove
it from the history — the old version is still right there for anyone to read.

We read it. Paired with a staff email address found on the main site, that
leaked password logged us straight into the **Krayin CRM** as an administrator.

## 3. Turning an upload button into a foothold

That version of Krayin had a known, severe flaw (CVE-2026-38526): an
**authenticated file-upload** bug. The app let a logged-in user upload what was
supposed to be an *image*, but it never actually checked that the file was an
image. So instead of a picture, we uploaded a tiny **program** — a "web shell,"
a file that runs whatever command you ask it to — and simply labelled it as an
image. The server accepted it, stored it at a public web address, and from then
on, visiting that address let us **run commands on the machine** as the web
server's account, `www-data`.

## 4. A second, fresher password → a real login

Our foothold could read the CRM's **current** configuration file — and it held a
*different*, newer database password (the one leaked in git had since been
rotated at the database, but the config still held the live one). And, once
again, **password reuse**: that live password was also the SSH password for a
staff user, **jones**. We logged in properly as jones. The first flag,
`user.txt`, was ours.

## 5. From user to root: the robot that rebuilt repositories

Now the clever part. Running quietly in the background, **as the administrator
(root)**, was a little homemade automation — a script that woke up **every 60
seconds**, looked for any code repository flagged as a "template," and copied the
files out of it onto disk.

The flaw: when it wrote those files out, it **blindly trusted the file names**
inside the repository. Normally the tools developers use would refuse a file
named something like `../../../somewhere-else` — a name that tries to **climb out**
of its folder and write elsewhere on the system. But you can hand-craft a
repository at a low level that *bypasses* those safety checks, producing exactly
such a booby-trapped file name.

So we made our own repository, flagged it as a template, and planted a file whose
name climbed all the way up and out to the **administrator's list of trusted
login keys**. Within a minute, the root-powered robot dutifully "rebuilt" our
repository and wrote our file exactly where its name told it to — installing
**our** SSH key into root's account. We logged in as **root**. The box was fully
owned.

> **Why the ordinary checks missed it:** this wasn't a scheduled job of the old,
> obvious kind — it was a newer-style background timer, easy to overlook if you
> only check the classic places. The lesson: *enumerate how a box schedules work,
> not just the one place you expect it.*

---

## 6. So why was it hackable?

1. **A secret committed to version history.** Blanking a password out later
   doesn't erase it — the history is a permanent record, and this one was public.
2. **An upload that checked the label, not the contents.** "Call it an image"
   was enough; the server never verified it actually was one — so an image slot
   became a code-execution slot.
3. **Password reuse (twice).** Leaked and live database passwords doubled as
   human logins.
4. **A root-powered helper that trusted untrusted names.** A background task
   running as administrator wrote files wherever the input told it to, with no
   sanity-checking of the paths.

## 7. What would have stopped us

- Treat any secret ever committed to git as **burned** — rotate it, and scrub
  history; don't just blank the latest version.
- Validate uploads by their **actual content**, store them where they can't be
  executed, and keep the app patched.
- Stop reusing passwords across databases and human accounts.
- Any automation running as root must **sanitise every path** it writes and
  never trust names that come from user-controlled data.

---

*Nexus is an intentionally vulnerable training machine. Everything here was done
against an authorized lab target.*
