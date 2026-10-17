# The Story of Cohort — How a Tidy Little Analytics Site Got Taken Apart

*A plain-language account of the engagement. No command-line required to follow it.
If you want the exact commands, read `WALKTHROUGH.md`; if you want the formal
findings, read `REPORT.md`. This is the story.*

---

## 1. The front door looked boring on purpose

Cohort introduced itself as **"Cohort Analytics — retention intelligence for
subscription teams."** A clean marketing site, a logo, some nice copy. From the
outside there were only three ways in:

- **SSH (port 22)** — locked, modern, no keys, no passwords. A brick wall.
- **The website (ports 80 and 443)** — everything interesting had to be here.

So we did what you do with any building: we walked the perimeter. And the
website, at first, seemed almost *aggressively* uninteresting. It was a
**single-page app** — the kind of site where the server hands your browser one
small shell and a big blob of scrambled JavaScript, and the browser draws the
rest. There were no login forms to poke, no obvious pages, no links to follow.
Typing random page names into the address bar? The site cheerfully returned the
same homepage for *every* guess — a classic "catch-all" that makes the usual
"let's guess hidden pages" approach useless. It was, politely, a dead end.

**The lesson of the first hour:** a site that gives you nothing to grab onto is
often hiding its real machinery one layer down. We stopped poking the website
*the human uses* and started asking about the **API the website talks to**.

---

## 2. The first real door: a helpful little "URL checker"

Behind the pretty front-end was a small programming interface — an **API** — the
kind of thing the website quietly calls in the background to fetch data. Most of
it was closed or said "not allowed." But one corner of it answered differently,
and different is *interesting*.

We found an endpoint whose whole job was: **"give me a web address, and I'll go
check it for you."** Think of it as a concierge: you hand it a link, it walks off,
visits the link on your behalf, and comes back to tell you what it saw.

That sounds harmless — even helpful. It is also one of the most dangerous things
a server can offer, and it has a name: **SSRF — Server-Side Request Forgery.**
The problem is simple once you see it: *the concierge is standing inside the
building.* When you ask it to visit a web address, it can reach places **you**
can't — rooms deep inside the private network that have no door to the outside
world. You're no longer knocking on the front door; you're handing notes to
someone who can walk the hallways for you.

We confirmed it the honest way: we asked the concierge to visit *our own*
computer, and sure enough, our computer's doorbell rang. The server really did
go fetch whatever we pointed it at. The concierge was real.

---

## 3. Walking the hallways nobody meant to show us

The server's owners had thought about this a little. They told the concierge:
*"never visit the building's own internal address."* A reasonable instinct. But
they enforced it by checking the **spelling** of the address rather than where it
actually led — and there are dozens of ways to spell "the building itself" that
don't look like it. We used one of those alternate spellings, and the concierge
happily walked right back inside.

Now we could explore the internal hallways. And one internal room was the key to
everything: a **status page** that nginx (the web server software) keeps for its
own administrators. It's supposed to be visible *only* from inside — which is
exactly where our concierge was standing. That page was essentially a **building
directory**, and on it was a line that changed the whole engagement:

> there is a hidden internal site, reachable at a long random name like
> `nb-1be3782a8afd3ad5.cohort.htb`, and it leads to a tool called **marimo**.

This mattered enormously. That random name was something **no amount of guessing
would ever have found** — it's gibberish by design. Earlier we'd tried the
standard trick of guessing hidden sub-sites from a wordlist, and it had failed,
and that failure had felt like a wall. It wasn't a wall. It was simply the wrong
tool: you don't *guess* a secret address, you get the building to **tell you**
what it is. Which it just had.

---

## 4. The room with no lock: marimo

**marimo** is a legitimate, popular tool — an interactive "notebook" where people
run and share live code, a bit like a digital lab bench. It's meant to live
safely tucked away inside a company's own network, used by trusted staff. On
Cohort, it was tucked away… but the version running (0.20.4) had a known, serious
flaw.

In plain terms: marimo had a feature that let a browser open a **live terminal** —
a direct command line into the machine — and in this version that terminal
**didn't check who you were first.** Normally a terminal like that would be the
most guarded thing in the building. Here, because of the flaw, it was a room with
the lock left off. Anyone who could reach the door could walk in and start typing
commands on the server.

And we could now reach that door, because the concierge had just handed us the
building directory with the room's exact address on it.

We walked in. The machine answered as a user named **`marimo`**. We weren't an
administrator — just an ordinary user — but we were *inside*, with a real foothold
and the ability to run commands. The first flag, `user.txt`, was ours. The site
was no longer just "a website we were looking at." It was a computer we were
*standing on*.

> **Why this worked only now, and not earlier:** the flaw had been there the whole
> time. What we'd been missing wasn't a trick — it was the *address*. The same
> door that was "unreachable" in hour one was wide open the moment the status page
> told us where it was. Same building, right door.

---

## 5. From guest to owner: the race against the installer

Being the `marimo` user is like having a desk in the building but no master key.
You can read your own files, run your own programs — but the truly valuable rooms
(and the final flag) belong to **root**, the all-powerful administrator account.
Getting from "ordinary user" to "root" is its own puzzle.

We worked through the usual checklist of shortcuts — misconfigured permissions,
forgotten passwords, scheduled jobs running with extra power, secrets left lying
in files. One by one, they came up empty. Whoever built this box had been tidy.
The absence of an easy win is itself a clue: it meant the intended path was
something more specific.

The answer was in the software inventory. The machine had a system component
called **PackageKit** — the behind-the-scenes helper that installs and updates
software — and its version had a freshly-known, subtle flaw. Here's the shape of
it, without the machinery:

PackageKit runs with full administrator power, because installing software needs
that power. Before it actually installs anything, it's supposed to ask a
gatekeeper, *"is this person allowed?"* But it also offers a **"just pretend"
mode** — a dry run that *skips* the permission check because, after all, pretending
to install something is harmless.

The flaw was a **timing trick** (the technical name is a "race condition"). We
asked PackageKit to do two things almost at once: *"do a harmless pretend
install"* — which sailed past the gatekeeper untouched — and then, a hair later,
*"actually, make that a real install."* Because of a bug in how it juggled those
two requests, it **carried the gatekeeper's 'sure, go ahead' from the pretend run
over to the real one.** It installed our software package for real, with full
administrator power, having never actually checked whether we were allowed.

And an installed software package gets to run a little setup script as it installs
— as the administrator. Ours did exactly one quiet thing: it left behind a small
program that would hand us administrator power on demand. We ran it, and the
machine confirmed what we already suspected: we were now **root**. The final flag,
`root.txt`, was ours. The box was fully owned.

---

## 6. So *why* was it hackable? The honest post-mortem

None of the individual pieces were exotic. What made Cohort fall was a **chain** —
each link reasonable on its own, dangerous in sequence:

1. **A helpful feature with too much reach.** The "check this URL for me" concierge
   was a normal product feature. It became a weapon because it ran *inside* the
   trusted network and could be pointed anywhere.
2. **A guard that checked spelling, not substance.** The block on "visit yourself"
   looked at how the address was *written* instead of where it actually *led* —
   so it was trivial to word around.
3. **A secret kept by obscurity, then given away.** The hidden marimo site was
   "protected" only by having an unguessable name — and the internal status page
   handed that name out to anyone who could reach it (which, thanks to step 1 and
   2, we could).
4. **A powerful tool left unlocked inside the walls.** marimo's unauthenticated
   terminal was trusted to be safe *because* it was internal. Once the internal
   network wasn't actually private to us, "internal" stopped meaning "safe."
5. **A system helper that trusted a pretend answer for a real action.** The final
   step turned full administrator power over to an unprivileged user because of a
   single moment where it confused "pretend" with "for real."

The through-line is the oldest lesson in security: **"internal" is not the same as
"safe," and a wall is only as good as the thing it actually checks.** Every layer
here assumed the layer around it would hold. The attacker's whole job was to prove
that assumption wrong, one door at a time.

---

## 7. What would have stopped us

Any *one* of these would have broken the chain:

- Make the URL checker validate the **real destination** (block internal and
  loopback addresses by where they resolve to, not by how they're spelled).
- Don't let an internet-facing feature reach internal admin pages at all.
- Put a real lock on marimo — authentication — even though it's "only internal,"
  and keep it patched.
- Keep system components like PackageKit up to date, and require a genuine
  permission check for every privileged action, pretend-mode or not.

Defense in depth isn't a slogan. If even the *last* door had held, we'd have had a
foothold and a user flag — but not the keys to the kingdom.

---

*Cohort was an intentionally vulnerable training machine. Everything above was
done against an authorized lab target, to learn exactly these lessons in a place
where it's safe to.*
