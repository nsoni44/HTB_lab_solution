# The Story of Touch — Escaping an Airport Kiosk Through the Back of a Help Dialog

*A plain-language account of how far this box fell. For the exact steps see
`WALKTHROUGH.md`; this is the story of what happened and why it was hackable.*

> **Note up front:** this box was taken as far as **user-level access** — the
> first flag was captured. The final jump to full administrator (**root**) was
> **not** achieved; the honest account of where it got stuck is at the end.

---

## 1. A kiosk, not a server

Touch was a **Windows** machine pretending to be an **airport self-check-in
kiosk** — "Gate B7, Terminal 4, Kiosk #042." It wasn't serving a normal website.
Its one interesting door was a custom management app, **"Nexion DeviceHub,"** and
behind the physical kiosk was a locked-down touchscreen you were clearly never
meant to escape from.

## 2. The device that told us its own password

The DeviceHub app had a status page that *anyone* could read without logging in.
Among the harmless-looking details it volunteered was the device's **serial
number**.

Then we read the login page's fine print, which said: *"the default password is
the device serial number."* The app was, in effect, **telling us its own
password** — the "secret" login was just a serial number it had already handed
out for free. We logged in. And the dashboard inside did something worse: it
displayed, in plain text, the **Windows login password** for the kiosk's user
account (`KioskUser`).

## 3. Trapped inside the touchscreen

That Windows password let us connect to the machine's remote desktop as
`KioskUser` — but we landed straight into the **locked kiosk**: a full-screen
check-in app with no desktop, no menus, no way out. Every normal escape trick —
keyboard shortcuts, task manager, closing the window — was blocked. The kiosk was
genuinely well-locked at the *application* level.

## 4. Escaping through a door the lockdown forgot

The lockdown guarded the app and the browser. What it **didn't** guard was
Windows' own **accessibility features** — the built-in tools for users with
disabilities, which live at a deeper level of the operating system.

Triggering the **"Ease of Access"** shortcut popped up a genuine Windows
**Narrator** help dialog — a real OS window, sitting *outside* the kiosk's cage.
That dialog had an ordinary hyperlink ("Narrator guide"), and clicking it opened
a **full, normal web browser** — not the locked kiosk, a real browser with an
address bar.

From there it was easy. We pointed the browser at the computer's own files (you
can browse local folders in a browser) and read the first flag directly. Then,
for a proper command line, we used the browser's ordinary **"Save As" dialog** —
itself a small piece of the Windows desktop — navigated it to the system's
command-prompt program, and "opened" it. That launched a **real command shell**.
We now had genuine command-line control as `KioskUser`. The first flag,
`user.txt`, was ours.

> **The core idea:** a kiosk lockdown is only as strong as its *weakest* window.
> This one locked the app and the browser beautifully — but left a thread
> dangling through the accessibility help system, and that thread unravelled the
> whole cage.

## 5. Where it stopped: the jump to administrator

Getting from `KioskUser` to full **administrator** is where this engagement ran
out of road — and it's worth being honest about why.

`KioskUser` belonged to a custom group that had **write access to a plugin folder**
belonging to a printer program — and that printer program ran with full system
privileges. The plan was sound: drop a malicious plugin into that folder, and
when the privileged program loaded it, our code would run as administrator. We
even got the malicious plugin into place.

The missing piece was the **trigger**. The privileged program only loads its
plugins **once, when it starts** — and we could never find a way to make it
restart (we weren't allowed to kill it, reboot the machine, or reach the hidden
scheduled task that controlled it). The weapon was loaded and aimed; we simply
never found the button to fire it. So **`root.txt` was never captured** — the box
was left at a solid user foothold with a clearly-identified but un-triggered
path to the top.

---

## 6. So why was it hackable (as far as it went)?

1. **Information disclosure.** An unauthenticated status page leaked the serial
   number…
2. **…which was also the password.** Using a publicly-readable serial as the
   login secret means "secret" and "public" were the same value.
3. **Credentials shown in plain text.** The dashboard displayed the Windows
   account password outright.
4. **A kiosk lockdown with an unguarded layer.** App- and browser-level escapes
   were blocked, but OS-level accessibility features were not — and that was
   enough to reach a real shell.

## 7. What would have stopped us

- Don't leak device identifiers from unauthenticated endpoints, and **never use
  a serial number as a password** — force a change on first setup.
- Never display account passwords in an app's own interface.
- Lock down kiosks at the **OS policy level**, including accessibility tools and
  file dialogs — not just by hiding the browser chrome.
- (For the privesc that was *almost* there) don't grant write access to a
  folder whose contents a privileged process will load and execute.

---

*Touch is an intentionally vulnerable training machine. Everything here was done
against an authorized lab target.*
