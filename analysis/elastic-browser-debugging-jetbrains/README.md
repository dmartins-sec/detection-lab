# Browser Debugging from an Unusual Parent — JetBrains IDEs Beyond WebStorm

**Rule:** `credential_access_browser_debugging_from_unusual_parent`
**Source:** Elastic `protections-artifacts` (Windows behaviour rules)
**Verdict:** Benign true positive — the rule fired on legitimate IDE activity that its exclusion list only partially covers.

---

## Why this rule exists

Launching a Chromium browser with `--remote-debugging-port` opens the DevTools
Protocol on a local port. Anything that can reach that port can drive the
browser: read cookies, dump saved logins, and hijack authenticated sessions
without ever touching the credential files on disk. It is a well-documented
credential-access technique, which is why a browser started this way — and
especially one started by an *unusual parent process* rather than by the user —
is worth alerting on.

The important half of the logic is the parent. A browser launching itself with
a debug port is one thing; `cmd.exe` or `powershell.exe` launching it is the
shape that infostealers actually use.

## What fired

An Edge process started under a shell, with a debugging port and a custom
profile directory:

```
process.executable          C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
process.parent.executable   C:\Windows\System32\cmd.exe
process.parent.command_line cmd.exe /c start "" msedge --remote-debugging-port=<port>
                            --user-data-dir=...\JetBrains\IntelliJIdea2025.1\chrome-profiles\chrome-user-data-<port>
                            --no-first-run --disable-fre --no-default-browser-check about:blank
process.working_directory   ...\IntelliJ\bin\
```

On the surface this hits every suspicious note the rule looks for: a browser,
a remote-debugging port, and a **shell** as the parent instead of the browser
itself. In isolation it is indistinguishable from the malicious pattern.

## Root cause

This is how **JetBrains IDEs run their JavaScript debugger**. To attach to the
DevTools Protocol, the IDE cannot reuse the user's normal browser profile —
Chrome/Edge will only open a debug port against a *fresh* user-data directory
(and, since Chrome 136, never against the default profile at all). So the IDE
spawns the browser through `cmd.exe /c start`, pointing `--user-data-dir` at a
disposable profile it owns under `...\JetBrains\<IDE><version>\chrome-profiles\`.

That behaviour is documented identically for **WebStorm and PhpStorm**, and the
observed event shows **IntelliJ IDEA** doing exactly the same thing. It is not
WebStorm-specific — it is how the whole IDE family debugs front-end code.

## The gap in the rule

The rule already anticipates this false positive. Its exclusion, however, is
scoped to a single product:

```
... and not process.parent.command_line : "*\\WebStorm*\\chrome-user-data-*"
```

Two things stop that exclusion from matching here:

1. **Product scope.** The path segment is `WebStorm`. The event comes from
   `IntelliJIdea2025.1`, so the wildcard never matches — even though the
   launching mechanism is identical. The exclusion was written against the
   product where this was first observed, not against the *behaviour*.

2. **Directory name.** The observed profile folder is `chrome-profiles\chrome-user-data-<port>`,
   an extra path segment deeper than the `*\chrome-user-data-*` the exclusion
   expects. Depending on IDE version, the layout is nested one level further
   than the pattern assumes.

Net effect: a legitimate, documented developer workflow keeps generating
credential-access alerts on any host running a JetBrains IDE that isn't
WebStorm.

## A more durable exclusion

The instinct is to add `IntelliJIdea` next to `WebStorm`. That works until the
next analyst files the same ticket for PyCharm, GoLand, Rider, or CLion — the
exclusion becomes a growing list of product names chasing a behaviour that is
shared across all of them.

The behaviour that is actually stable across the family is the **JetBrains-owned
profile directory**. Every one of these IDEs launches its debug browser with a
`--user-data-dir` under a `JetBrains` path containing a `chrome-user-data`
profile it created. Anchoring on that is both broader (covers the whole family)
and tighter (still requires the JetBrains-managed profile, not just any
`cmd.exe`-launched browser):

```
and not (
    process.parent.executable : "?:\\Windows\\System32\\cmd.exe" and
    process.parent.command_line : "*\\JetBrains\\*chrome-user-data*"
)
```

## What you lose if you exclude the wrong field

This is the part that matters, because the easy fixes quietly break the rule.

- **Excluding `cmd.exe` as a parent outright** would silence these alerts — and
  also silence the exact malicious pattern the rule was built for, a browser
  debug-launched from a shell. That is the technique, not the noise.

- **Excluding on the debug port or the browser path** removes the signal
  entirely: the malicious and benign cases share both.

- **Widening the profile match to any `chrome-user-data`** drops the JetBrains
  anchor. Malware can point `--user-data-dir` anywhere, including a folder it
  names `chrome-user-data`; the value is attacker-controlled. The exclusion has
  to keep the `JetBrains` path segment, which is the part the developer's IDE
  owns and an attacker has no reason to reproduce.

The safe exclusion narrows on the combination that is unique to the benign
workflow — shell parent **and** a JetBrains-managed profile path — and leaves
the shell-launched-browser signal intact for everything else.

## Takeaways

- Vendor exclusions are often written against the **first product** a false
  positive was seen in, not the **behaviour** behind it. When the same
  mechanism exists across a product family, a single-product exclusion ages
  into recurring noise.
- Anchor exclusions on the part of the artifact the legitimate software
  *owns* and an attacker would have to *reproduce* — here, the JetBrains
  profile directory — not on the parts the two cases share.

---

*Written from the public Elastic rule and vendor (JetBrains) documentation.
No customer or environment data is included; the port and profile paths are
generic examples reproducible on any host running a JetBrains IDE debugger.*
