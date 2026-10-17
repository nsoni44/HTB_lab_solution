# The Story of Management — An Identity Server, a Chain of Secrets, and a Sloppy Backup Rule

*A plain-language account of how this box fell. For the exact commands see
`walkthrough.md`; this is the story of what happened and why it was hackable.*

---

## 1. The front door and the side door

Management showed a small company website over HTTPS. The page's assets were
scrambled and only unscrambled inside your browser — a mild attempt at hiding
things — but once unscrambled, they pointed at a **second** site on a
sub-domain: **`sso.management.htb`**, running **OpenAM**.

OpenAM is a serious piece of software: a **single sign-on / identity broker** —
the thing a big organisation puts in front of all its apps so staff log in once
and get access everywhere. It holds the keys to the kingdom by design, which
makes it a very high-value target when it has a flaw.

## 2. Breaking into the identity server itself

This OpenAM had a known, severe flaw (CVE-2026-33439): a **pre-authentication
remote code execution** bug. In plain terms, one of its web pages could be
tricked into **running commands the attacker chose, without logging in at all.**

The technical cause is a classic one called **insecure deserialization** —
the server accepted a bundle of saved data from the visitor and "rebuilt" it
into live objects without checking it was safe, and a carefully poisoned bundle
turns that rebuild step into *"run my code."* We sent one, and the server ran
our command. We were now executing code on the machine as the `openam` service
account — not an administrator, but inside.

## 3. Following the thread of secrets

From that modest foothold, the box became a chain of secrets, each unlocking the
next — the way real breaches usually unfold:

- The `openam` account could read a configuration file belonging to **GLPI**
  (an IT-asset-management app also installed on the box). That file held a
  **database password**.
- Inside the database was another credential — a **directory-service (LDAP)
  login** — but it was stored **encrypted**. The catch: the app's own
  encryption key was *also* sitting on the machine, readable by us. So we used
  the application's own tools to decrypt its own secret, revealing a plaintext
  password.
- And people reuse passwords. That decrypted password belonged to a staff
  account, **owen**, and it worked as **owen's SSH login**.

We now had a proper interactive session as `owen`. The first flag, `user.txt`,
was ours.

## 4. From user to root: a backup command that trusted a wildcard

`owen` wasn't an administrator. But `owen` was allowed to run **one** command
with root powers without a password — a **backup tool** (`rdiff-backup`),
locked down (in theory) so it could only ever touch one specific backup folder.

The lockdown was written with a **trailing wildcard** — roughly, *"run the
backup tool, restricted to the backup folder, …and whatever else the user tacks
on the end."* That little "whatever else" was the whole game. We tacked on a
**second** restriction that pointed at a *different* folder — the administrator's
home directory — and because the second instruction won, the tool happily copied
**all of root's private files** out to where `owen` could read them.

That included `root.txt` **and** the administrator's private SSH key — which let
us log straight back in as **root** whenever we liked. The box was fully owned.

---

## 5. So why was it hackable?

1. **An unauthenticated flaw in the most sensitive component.** The identity
   server — the thing guarding everything — could be made to run attacker code
   with no login at all.
2. **Secrets stored next to the keys that protect them.** An encrypted password
   is only as safe as the encryption key, and here the key was right there on
   the same machine.
3. **Password reuse.** A service credential doubled as a human's SSH password,
   turning a limited foothold into a real login.
4. **A sudo rule with a wildcard.** Allowing a trusted command "plus anything
   the user adds" let the user add the one argument that undid the restriction.

The through-line: **a single trusted exception at each layer was enough.** One
unauthenticated bug, one reachable key, one reused password, one loose wildcard.

## 6. What would have stopped us

- Keep internet-facing identity software patched — it's the highest-value target
  you run.
- Don't store a secret and the key that decrypts it on the same reachable host.
- Never reuse passwords across service and human accounts.
- Write sudo rules **without** trailing wildcards; pin every argument, so a
  "restricted" command can't be handed an argument that lifts the restriction.

---

*Management is an intentionally vulnerable training machine. Everything here was
done against an authorized lab target.*
