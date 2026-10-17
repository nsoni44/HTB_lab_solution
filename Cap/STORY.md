# The Story of Cap — How a Security Dashboard Leaked Its Own Keys

*A plain-language account of how this box fell. For the exact commands see
`walkthrough.md`; this is the story of what happened and why it was hackable.*

---

## 1. A dashboard that watches the network

Cap presented itself as a tidy little **"Security Dashboard"** — a web app
(built in Python) whose job was to capture and display network traffic, the kind
of tool a security team runs to keep an eye on what's flowing across the wire.
Alongside it sat the usual pair of service doors: **FTP** (file transfer) and
**SSH** (remote login). Both of those needed a username and password we didn't
have. So, as always, the website was the way in.

The dashboard let you look at **packet captures** — recordings of network
traffic — and each one had a number. You'd view capture number such-and-such,
and the app would show you a report and let you download the raw recording.

## 2. The flaw hiding in the URL

Here's where it went wrong. The address of each capture was simply its number:
*download report #5*, *download report #3*, and so on. And the app never checked
whether the capture you asked for was actually **yours**.

This is a flaw with a name — **IDOR, Insecure Direct Object Reference** — and
it's as simple as it sounds: *if the only thing standing between you and someone
else's data is a number in the address bar, you just change the number.* We
asked for capture **#0** — the very first one, which belonged to an
administrator — and the app handed it right over.

## 3. Reading secrets straight off the wire

That capture turned out to be a recording of an **FTP login**. And FTP, by
design, sends usernames and passwords in **plain text** — unencrypted, right
there in the traffic. So the recording we weren't supposed to see contained a
real username and password in the clear: **nathan / Buck3tH4TF0RM3!**

People reuse passwords. We tried nathan's FTP password on **SSH**, and it
worked. We now had a real login on the machine — a genuine foothold, standing
inside as the user `nathan`. The first flag, `user.txt`, was ours.

## 4. From user to root: a tool with too much power

Being `nathan` is not being the administrator (**root**). To make that last
jump, we looked at what on the system had been given special powers.

On Linux, individual programs can be granted narrow "superpowers" called
**capabilities** — a way to give a program *just* the one privilege it needs
instead of full administrator rights. It's meant to be *safer* than the
all-or-nothing alternative. But here, the **Python interpreter itself** had been
granted the capability to **change which user it runs as**.

That's a catastrophic thing to hand to a general-purpose programming language.
Python can run any code you like — so a Python that's allowed to "become any
user" can simply be told: *become the administrator, then run a shell.* One
short line, and we were **root**. The final flag, `root.txt`, was ours.

---

## 5. So why was it hackable?

Four ordinary mistakes, chained:

1. **No ownership check on the data (IDOR).** The dashboard trusted the number
   in the URL and never asked "is this yours?" — so every user's capture was one
   guess away.
2. **Secrets in the clear.** FTP sent credentials unencrypted, and the app
   happily recorded and re-served them. A captured secret is still a secret.
3. **Password reuse.** The same password opened FTP *and* SSH. One leak became
   full interactive access.
4. **A superpower on the wrong program.** Granting the "become any user"
   capability to Python is effectively granting root to anyone who can run
   Python — which is everyone with a shell.

The through-line: **every layer trusted the one before it.** The dashboard
trusted the URL, the capture trusted the network, SSH trusted the reused
password, and the system trusted Python with a power it should never hold.

## 6. What would have stopped us

- Check that a capture **belongs to the requesting user** before serving it.
- Never transport or store credentials in plain text.
- Don't reuse passwords across services.
- Never grant `cap_setuid` (or similar) to a general-purpose interpreter like
  Python, Perl, or Ruby — scope capabilities to purpose-built binaries only.

Any single one of these breaks the chain.

---

*Cap is an intentionally vulnerable training machine. Everything here was done
against an authorized lab target.*
