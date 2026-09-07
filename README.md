# airlock

<sub>Codé avec amour ♥ par Genereux & Claude</sub>


A tiny two-way drop box between your **connected laptop** and the **isolated lab machine**.

One file. Standard library only. No `pip install`, no Docker, no build step.
Drop `airlock.py` on a machine, run it, and both boxes get a shared clipboard for code
snippets and files - through a browser page or from the terminal.

![The airlock console: a shared drop of code snippets on the left, and the internet
bridge panel open on the right](illustration/app.png)

<sub>The whole app is one page. Items appear live on every machine; the panel on the
right is the [internet bridge](#the-internet-bridge), open here with 29 minutes left on
its timer.</sub>

```
personal laptop  ──── LAN ────►  ┌───────────┐  ◄──── LAN ────  lab machine
(browser + CLI)                  │  airlock  │                  (browser + CLI)
                                 │  server   │
                                 └───────────┘
                                 runs on ONE of them
```

**What you need:** `python3` (3.8 or newer) on whichever machine runs the server, and
on any machine that uses the `airlock` command. A machine that only uses the web page
needs nothing but a browser.

---

## Start and discover

One command, everything switched on, nothing to install:

```bash
cd tools/airlock
python3 airlock.py serve --token lab42 --enable-proxy --proxy-allow any
```

It prints a URL like `http://192.168.1.42:8787/?t=lab42`. Open it in a browser - on this
machine, and on the isolated one. That page is the whole app: paste snippets, drag files,
and hit the **docs** button next to your name for the full manual, which is the only
documentation the isolated machine can reach.

What each part of that command does:

| | |
|---|---|
| `--token lab42` | a fixed code instead of a random one, so you can retype it. Drop it and airlock mints something like `87w-m6t` |
| `--enable-proxy` | arms the [internet bridge](#the-internet-bridge). **Leave this off unless you mean it** - it is what lets the isolated machine reach the internet |
| `--proxy-allow any` | lets the whole web through rather than just package mirrors. Without it you get pypi, npm, github, apt and little else |

With the bridge armed, a gold toggle appears at the bottom right. Press it to open the
gap, then paste this on the isolated machine to point its shell at your connection:

```bash
eval "$(curl -s 'http://192.168.1.42:8787/bridge.sh?t=lab42')"
```

The bridge closes itself after 30 minutes. To run airlock without lending any internet at
all, which is the normal case, just:

```bash
python3 airlock.py serve
```

> If `python3` on your machine is an old or broken build - more common than it sounds when
> several Pythons are installed - run [`./install.sh`](#install) once and use `airlock`
> instead. It pins a working interpreter.

**Contents**

0. [Start and discover](#start-and-discover)
1. [Do both machines need the same network?](#do-both-machines-need-the-same-network)
2. [Install](#install)
3. [Pick where the server runs](#pick-where-the-server-runs)
4. [Use it](#use-it)
5. [Who is who](#who-is-who)
6. [The internet bridge](#the-internet-bridge)
7. [Cheat sheet](#cheat-sheet) · [All flags](#all-flags)
8. [Codes](#codes)
9. [How it works](#how-it-works) · [HTTP API](#http-api)
10. [Security notes](#security-notes)
11. [Contributing](#contributing)

---

## Do both machines need the same network?

**They need a network path between them - but that does not mean giving up your internet.**

There is no way around the first part. airlock has no cloud relay and cannot have one:
the lab machine has no internet, so nothing on the internet can ever reach it. If the
two machines cannot see each other over IP, no tool can move bytes between them.

The good news is that "a path to the lab" is not the same as "leaving your own network".
Your laptop has more than one interface, and can hold both at once:

```
   internet ──wifi(en0)──►  laptop  ──ethernet(en9)──►  lab machine
                            ▲                            (isolated)
                        airlock serve
```

Wi-Fi keeps the internet. The ethernet port (a USB adapter is fine) goes to the lab
network. You keep browsing, pulling from git and running your editor on Wi-Fi while
airlock talks to the lab over the cable. Nothing bridges the two - the laptop simply has
a foot in each.

Even cleaner: **a plain ethernet cable straight between the two machines**, skipping the
lab network entirely. Both ends self-assign a `169.254.x.x` address and can see each
other. Wi-Fi is untouched.

One thing to check. If the lab network hands your laptop a default route and sits above
Wi-Fi in the service order, your laptop will try to reach the internet through a network
that has none, and you will lose connectivity. Put Wi-Fi first:

- macOS: **System Settings → Network → ⋯ → Set Service Order**, drag Wi-Fi to the top.
- Then confirm: `route -n get default | grep interface` should name your Wi-Fi device,
  and `ping <lab-ip>` should still answer. Directly-connected subnets do not need the
  default gateway, so the lab stays reachable.

If `ssh lab` already works when you are plugged in, a path exists and airlock will work
over exactly that same path.

**What will not work:** sitting on Wi-Fi alone, with the lab machine on a network you are
not attached to.

---

## Install

```bash
cd tools/airlock
./install.sh                      # puts `airlock` in ~/.local/bin
./install.sh /usr/local/bin       # or pick your own directory
```

Tested on macOS and Ubuntu 22.04. The script checks you have python3 3.8+ before doing
anything, tells you how to install it if not, and prints the line to add to your shell rc
when the target is not on `PATH`.

What it installs is a two-line launcher, not a symlink. That is deliberate: it pins the
interpreter it just verified, so a broken or ancient `python3` sitting earlier on your
`PATH` cannot hijack the shebang - a real situation on machines with several Pythons
installed. If that interpreter ever disappears, the launcher falls back to whatever
`PATH` offers.

Or skip the installer entirely and call `python3 airlock.py …` everywhere. Same thing.

---

## Pick where the server runs

It does not matter much, as long as the *other* machine can open a TCP port on it.
Three setups - pick the one that matches your network.

### A. Plain LAN (the normal case)

Run the server on your **laptop**:

```bash
airlock serve
```

It prints something like:

```
  airlock 1.0.0   store: /Users/you/.airlock
  ----------------------------------------------------------
  http://192.168.1.42:8787/?t=87w-m6t
  http://127.0.0.1:8787/?t=87w-m6t

  code:  87w-m6t
         (type it as you like - case and dashes are ignored)

  on the other machine, either open the URL above, or:
    airlock link 'http://192.168.1.42:8787/?t=87w-m6t'
  wrong codes are throttled to 10 tries/min per machine.
  ----------------------------------------------------------
```

On the lab machine, type that URL into a browser - it is short enough to retype by hand,
which matters because you cannot copy-paste between the two boxes. For the CLI, either
paste the full link or give the host and the code separately:

```bash
airlock link 'http://192.168.1.42:8787/?t=87w-m6t'
airlock link 192.168.1.42:8787 87w-m6t              # same thing, easier to type
```

Done. Both sides now share the lock. See [Codes](#codes) for why such a short code is
safe here.

### B. The lab machine cannot reach your laptop, but you can SSH into it

Common: the lab network firewalls inbound, but your `ssh lab` works. Keep the server on
your laptop and push its port into the lab box over SSH:

```bash
airlock serve                       # terminal 1, on the laptop
airlock tunnel user@lab             # terminal 2, on the laptop
```

`tunnel` prints the exact URL to use on the lab side - it will be
`http://127.0.0.1:8787/?t=…`, because the port now lives on the lab machine's own
localhost. Open it in the lab browser, or `airlock link` it there. Leave the tunnel
running; Ctrl-C closes it.

This also encrypts the traffic, which plain HTTP does not. Needs the stock sshd settings
(`AllowTcpForwarding`).

### C. Run the server on the lab machine instead

If you would rather the data lived on the lab side:

```bash
airlock deploy user@lab             # scp's airlock.py over and starts it
```

It copies this exact script to `~/airlock.py` on the remote, starts it under `nohup`, and
tails the log so you can copy the printed `http://…?t=…` URL. Add `--no-start` if you
want to launch it yourself.

---

## Use it

### From the browser

Open the URL. You get a one-page console:

- **Paste a snippet** into the box, `Cmd/Ctrl+Enter` to send.
- **Drag a file** anywhere on the page, or paste a file from the clipboard.
- Every item shows up **live on the other machines** (long-poll, no refresh needed).
- **Copy** puts a text item straight on your clipboard. **Download** grabs files.
- **Code is highlighted and numbered.** The language is detected from the filename, and
  from the content when the name gives nothing away - so a `git diff` piped in as
  `stdin.txt` still renders as a diff, with additions and deletions tinted. Covers js/ts,
  python, sql, json, yaml, shell, css, html/vue, prisma, Dockerfile, dotenv and diffs.
  No highlighting library is loaded: the tokenizer is ~150 lines of vanilla JS inside the
  page, because the lab machine cannot reach a CDN.
- **Everyone gets a pseudonym** like `cobalt-lynx`, with a colour derived from it, so in a
  three-way session you can see at a glance who dropped what. Click your name in the
  header to change it. See [Who is who](#who-is-who).
- **A `docs` button** next to your name opens the whole manual inside the page, with a
  copy button on every command. That page is the only documentation the isolated machine
  can reach, so it is kept complete on purpose.
- **Light / dark** toggle in the top-right. It follows your OS theme until you touch it,
  then remembers your choice per browser, and applies before the first paint so there is
  no white flash on a dark setup.

### From the terminal

Everything the page does has a command.

```bash
# send
airlock push src/api/http.js                     # a file
airlock push a.py b.py c.py                      # several
git diff | airlock push --name fix.patch         # anything on stdin
docker logs auth | airlock push --name auth.log

# receive
airlock pull                                     # latest text item -> stdout
airlock pull > fix.patch                         # so this just works
airlock pull --out .                             # latest, saved as a file
airlock pull --all --out ./inbox                 # everything
airlock pull 5bc931 --out .                      # by (partial) id
airlock pull --rm                                # and clear it from the server

# housekeeping
airlock ls
airlock rm 5bc931
airlock rm all
```

Text items print to stdout by default so they compose with the rest of your shell.
Files are written to disk; an existing file is never overwritten unless you pass
`--force` (otherwise the item id is appended to the name).

### Auto-sync a folder

The one to leave running while you work:

```bash
airlock watch ~/inbox            # blocks; new items land in ~/inbox
airlock watch ~/inbox --catchup  # also take what is already in the lock
airlock watch ~/inbox --rm       # and clear each item from the server after
```

`watch` on the lab side plus `push` from the laptop means files simply appear, within a
second. It remembers what it has already taken in `<dir>/.airlock-seen`, so restarting it
does not re-download everything.

---

## Who is who

Three or more machines can share one lock at the same time - that is the normal case, not
a special mode. The server is threaded, every client sees every item, and one push wakes
all the watchers at once.

To keep it readable, each participant carries a pseudonym:

```bash
airlock alias                    # phantom-zebu
airlock alias new                # roll a fresh one
airlock alias "Genereux"         # or pick your own
airlock push notes.md --as lab   # one-off, without changing your name
```

The name is minted once, kept in `~/.config/airlock/config.json` (or `localStorage` in
the browser), and travels with each drop as `X-Airlock-From`. The UI derives a stable
colour from it, so the same person always shows the same chip.

Nothing about this is a login - it is a label, not a credential. The access code is what
controls who gets in, and everyone who is in sees everything.

---

## The internet bridge

airlock can lend the isolated machine your internet connection. Read the warning before
you use it.

> **This deliberately opens a hole in the air gap**, which is the one property the
> isolated machine is supposed to have. Plenty of labs forbid it outright. Check that it
> is allowed where you work.

It is off unless you explicitly arm it, it stays shut until somebody opens it, and it
closes itself after 30 minutes.

**1. Arm it** when starting the server:

```bash
airlock serve --enable-proxy
```

**2. Open it.** A toggle appears at the bottom right of the page, or use the terminal -
both drive the same thing:

```bash
airlock bridge on         # open it
airlock bridge status     # is it open, what has gone through, what was blocked
airlock bridge off        # shut it now
airlock bridge on --minutes 5   # or give it a shorter leash
```

Two commands to run **on the isolated machine**:

```bash
airlock bridge check      # diagnose: tests each layer, names the broken one
airlock bridge firefox    # a throwaway proxied browser, system settings untouched
```

**3. Point the isolated machine at it.** Nothing to install there - its own pip, npm, apt,
git and Chrome then use the internet as they normally would. You do not browse from
inside airlock; airlock is only the pipe.

The short way is one line, and it needs nothing but `curl`:

```bash
eval "$(curl -s 'http://192.168.1.42:8787/bridge.sh?t=lab42')"
```

That asks the server for the current settings and applies them to your shell, so you
never retype an address. It reports what it did:

```
airlock: internet on via 192.168.1.42:8888 (any host, 30 min left)
         test: curl -I https://pypi.org
         off:  unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY
```

If the bridge is shut it says so and changes nothing. The exact line, with your address
and code already filled in, is the first row in the toggle's panel and in
`airlock bridge status` - copy it from either. Note it configures **that shell only**.

Or set it by hand:

```bash
export https_proxy=http://192.168.1.42:8888
export http_proxy=$https_proxy
unset http_proxy https_proxy    # hand the internet back
```

### Browsers

Browsers ignore `http_proxy`, so they need their own flag. Chrome takes one directly -
the separate `--user-data-dir` matters, or an already-running instance swallows the flag:

```bash
google-chrome --proxy-server="http://192.168.1.42:8888" --user-data-dir=/tmp/chrome-airlock
```

Firefox has no such flag; its proxy lives in a profile. This builds a throwaway one and
launches it, again with nothing installed:

```bash
mkdir -p ~/airlock-firefox && printf 'user_pref("network.proxy.type",1);
user_pref("network.proxy.http","192.168.1.42");
user_pref("network.proxy.http_port",8888);
user_pref("network.proxy.ssl","192.168.1.42");
user_pref("network.proxy.ssl_port",8888);
user_pref("network.proxy.share_proxy_settings",true);
' > ~/airlock-firefox/user.js && firefox -no-remote -profile ~/airlock-firefox
```

Use a **non-hidden** folder like `~/airlock-firefox`: snap-packaged Firefox, the default
on Ubuntu 22.04+, is confined and cannot read dot-directories or `/tmp`. Your normal
Firefox and your system network settings are untouched; delete the folder to undo it.

If airlock *is* installed there, `airlock bridge firefox` does all of that for you.

`airlock bridge status` prints that exact line with the right address filled in, and so
does the toggle in the page.

**`ping` will not work, ever.** It is ICMP and ignores proxies completely, so
`ping 8.8.8.8` fails whether the bridge is open or not - it tells you nothing. Test with
`curl -I https://pypi.org`, or with `airlock bridge check`.

### When it does not work

Run this on the isolated machine:

```bash
airlock bridge check
```

It walks the chain one link at a time - reach the server, is it armed, is it open, is the
proxy port accepting TCP, does a CONNECT tunnel open, does a real request come back - and
stops at the first failure with what to do about it. Typical answers: the bridge is still
closed, the port is bound to `127.0.0.1` only, something else already holds the port, or
the host you tried is simply not on the allowlist.

### A browser on the isolated machine

Chrome takes `--proxy-server` but is fussy about existing instances and profiles. Firefox
is easier, because its proxy setting lives in its own profile rather than the OS:

```bash
airlock bridge firefox                        # builds a profile, launches it
airlock bridge firefox --url https://pypi.org
airlock bridge firefox --browser /opt/firefox/firefox   # if it is somewhere unusual
```

It writes a throwaway profile in `~/.airlock-firefox` with the proxy pointed at the
bridge, DNS resolved on the proxy side (the isolated machine has none of its own), and
Firefox's background chatter - captive-portal checks, safebrowsing, telemetry, updates -
turned off so it does not fill your audit log with refusals. **Your normal Firefox and
your system network settings are untouched.** Delete the folder to undo it entirely.

### What gets through

By default **only package mirrors** - pypi, npm, github, crates, apt, conda, huggingface.
Everything else gets a `403`, and every attempt is logged. That is the setting to use when
you just need `pip install`, and the one you can defend if anyone asks why an isolated
machine had a route out.

Ordinary web browsing needs a wider door:

```bash
airlock serve --enable-proxy --proxy-allow any                    # anything at all
airlock serve --enable-proxy --proxy-allow arxiv.org,nature.com   # or name your own
airlock serve --enable-proxy --proxy-minutes 0                    # no auto-close
airlock serve --enable-proxy --proxy-on                           # open from startup
```

A domain on the list also covers its subdomains.

### How it works

A forward HTTP proxy in ~200 lines of standard library, listening on port 8888. Plain
HTTP requests arrive as absolute URIs and get relayed; `https` arrives as
`CONNECT host:443`, and airlock opens a socket and pumps bytes both ways.

No TLS is intercepted, no certificate is installed, nothing is decrypted - **airlock
cannot read the traffic it carries**. It can only see, and log, which host was asked for.

---

## Cheat sheet

| Command | What it does |
|---|---|
| `airlock serve` | run the server (port 8787, all interfaces) |
| `airlock link <url?t=…>` | remember the server on this machine |
| `airlock link <host:port> <code>` | same, without pasting a URL |
| `airlock push [files]` | send files, or stdin |
| `airlock pull [id]` | fetch latest (or one item) |
| `airlock ls` | list what is in the lock |
| `airlock rm <id\|all>` | delete one, or empty it |
| `airlock alias [name]` | show or change your pseudonym (`new` rolls a fresh one) |
| `airlock watch <dir>` | auto-download new items into a folder |
| `airlock bridge on\|off\|status` | the internet bridge ([above](#the-internet-bridge); needs `serve --enable-proxy`) |
| `airlock bridge check` | diagnose the bridge from the isolated machine |
| `airlock bridge firefox` | throwaway proxied browser on the isolated machine |
| `airlock deploy user@host` | scp this script to a remote and start it |
| `airlock tunnel user@host` | expose your local server on the remote's localhost |

### All flags

**`serve`** - `--port 8787`, `--bind 0.0.0.0`, `--dir ~/.airlock`, `--keep 200` (max items),
`--cap 4` (max GB), `--token`, `--new-token`, `--code-length 6`, `--long-token`, `--open`,
`--enable-proxy`, `--proxy-on`, `--proxy-port 8888`, `--proxy-minutes 30`, `--proxy-allow`.

**`push`** - `--name` (for stdin), `--as` (one-off pseudonym), `--text` (treat files as
previewable text), `--binary` (treat stdin as binary).

**`pull`** - `--out DIR`, `--all`, `--stdout`, `--rm`, `--force`.

**`watch`** - `--catchup`, `--rm`, `--force`.

**`bridge`** - `--minutes N`, and for `firefox`: `--profile`, `--browser`, `--url`.

**`deploy`** - `--path ~/airlock.py`, `--port`, `--bind`, `--no-start`.

**`tunnel`** - `--remote-port 8787`, `--port 8787`, `--dir`, `--token`.

Every client command also takes `--host` and `--token` to override the saved config, and
reads `AIRLOCK_HOST`, `AIRLOCK_TOKEN` and `AIRLOCK_ALIAS` from the environment.
`AIRLOCK_QUIET=1` silences the server's request log.

---

## Codes

The access code is deliberately short - six letters, shown as `87w-m6t` - because the
whole point of this tool is that the two machines have no shared clipboard. You read it
off one screen and type it on the other, so it is built to be typed:

- Drawn from a 31-character alphabet with no `0`/`O` and no `1`/`l`/`I`, so there is
  nothing to squint at.
- Compared case-insensitively, ignoring dashes and spaces. `87w-m6t`, `87WM6T` and
  `87W M6T` are all the same code.
- Generated once on first `serve` and kept in `~/.airlock/token`, so it survives restarts.

### Is a short code a security problem?

Not with a lockout in front of it, which is what airlock does.

Six letters from that alphabet is 31^6 = **887 million** combinations. Wrong codes are
rate-limited to **10 attempts per minute per IP** (and 60/min across all clients) on a
sliding window - so an attacker on your LAN needs, on average, **84 years of continuous
guessing** for a 1% chance of hitting it. The code is not the weak part of this setup.

What a short code does *not* survive is an attacker who can read your traffic, since this
is plain HTTP. That is a transport problem, not a length problem - see
[Security notes](#security-notes).

Practical note: the lockout applies to your own machine too. Fat-finger the code 10 times
and you wait a minute.

### Flags

```bash
airlock serve --token lab42        # pick your own code
airlock serve --new-token          # discard the saved code, mint a new one
airlock serve --code-length 9      # a longer generated code
airlock serve --long-token         # full random token, exact-match only
airlock serve --open               # no code at all, trusted LAN only
```

A code of 16 characters or fewer gets the forgiving comparison. Anything longer, or
containing symbols, is matched byte-for-byte - so `--long-token` and your own passphrases
keep their full strength.

---

## How it works

- Storage is a flat folder, `~/.airlock/items/`: one `<id>.json` (metadata) and one
  `<id>.bin` (payload) per item. Nothing else. Delete the folder to reset.
- Ids are `<epoch-ms>-<random>`, so a lexicographic sort is chronological.
- Bodies are streamed to disk in 256 KB chunks and sha256'd; CLI transfers are byte-exact
  for binaries.
- Live updates use a long-poll (`/api/wait?since=<version>`) against an in-process version
  counter - no WebSocket, no dependency.
- Auth is the code, accepted as `X-Airlock-Token` or as `?t=` in the URL, compared with
  `hmac.compare_digest`. Failures feed a sliding-window throttle that returns `429` with
  `Retry-After`.
- Retention: the oldest items are pruned past `--keep` items or `--cap` GB. It is a
  transit area, not storage.

### HTTP API

| Route | |
|---|---|
| `GET /` | the web console (unauthenticated; the code is never embedded in it) |
| `GET /api/ping` | unauthenticated health check |
| `GET /api/items` | `{items, version, you}` |
| `GET /api/wait?since=N` | long-poll, returns when `version` changes (25 s max) |
| `GET /api/items/<id>/raw` | payload (`?dl=1` for an attachment) |
| `POST /api/items` | raw body; headers `X-Airlock-Kind: text\|file`, `X-Airlock-Name`, `X-Airlock-From` |
| `DELETE /api/items/<id>` | delete one |
| `DELETE /api/items` | delete all |
| `GET /api/proxy` | internet bridge status |
| `GET /bridge.sh` | shell exports for the isolated machine, made to be `eval`'d |
| `POST /api/proxy` | `{"on": true\|false, "minutes": N}` - `409` if not armed |

Every route but `/` and `/api/ping` needs the code: `401` on a bad one, `429` once the
throttle trips.

So `curl` works fine as a client too:

```bash
curl -H "X-Airlock-Token: $TOK" -H 'X-Airlock-Kind: text' -H 'X-Airlock-Name: note.txt' \
     --data-binary @note.txt http://192.168.1.42:8787/api/items
```

---

## Security notes

Plain HTTP with a bearer code, meant for a local network you already trust. The code plus
the throttle stops a curious neighbour on the same wifi guessing their way in. Neither
stops someone *sniffing* the segment - they read the code off the wire on your first
request, and code length changes nothing about that. If the traffic matters, use setup
**B**: the SSH tunnel gives you encryption for free.

Bind to loopback with `--bind 127.0.0.1` when you only ever reach the server through the
tunnel; that way nothing is exposed on the LAN at all.

**On the air gap.** With the internet bridge disarmed - the default - airlock never
reaches the internet, and the isolated machine stays isolated: it only ever talks to the
other box on the local link. `--enable-proxy` is the one thing that changes this, and it
changes it deliberately. Do not arm it out of habit, and do not leave it armed on a server
you start automatically. `airlock bridge status` will always tell you where you stand.

---

## Contributing

**Contributions are very welcome**, especially cool features. This started as a weekend
tool for one problem and it turns out a lot of people have that problem.

### Three rules, and they are not negotiable

Everything else is open. These three exist because of where this runs:

1. **One file, standard library only.** No `pip install`, no `package.json`, no build
   step. The machine this is for cannot download a dependency, ever. If a feature needs a
   library, it needs to be written by hand or it does not go in.
2. **Nothing is fetched at runtime.** No CDN, no web font, no remote API. The syntax
   highlighter is ~150 lines of hand-written JavaScript for exactly this reason.
3. **macOS and Linux, python3 3.8+.** Test on both. `docker run --rm -v "$PWD:/src:ro"
   ubuntu:22.04` is enough for the Linux half.

### Ideas worth stealing

Roughly in order of how much they would improve daily use:

- **Zeroconf discovery** - mDNS so the other machine finds the server instead of you
  typing an IP. Doable with raw sockets, no dependency.
- **A QR code of the join URL**, drawn in the page. Removes the last bit of retyping.
  Needs a small hand-rolled QR encoder, which is the fun part.
- **TLS with a self-signed cert**, so the code is not readable on the wire without
  needing the SSH tunnel. `ssl` is in the standard library.
- **Resumable uploads** for the multi-gigabyte dataset that dies at 90%.
- **Two-way folder sync** - `watch` already pulls; a `--push` half would make it a real
  sync.
- **Image and PDF previews** in the item cards, from the bytes already on disk.
- **A diff view** between any two text items in the lock.
- **SOCKS mode for the bridge**, so tools that speak SOCKS but not HTTP proxy work too.

### Before you open a PR

There is no test suite yet - **adding one is itself a welcome contribution.** For now,
exercise the thing you touched:

```bash
python3 airlock.py serve --port 9999 --dir /tmp/t --token test &
python3 airlock.py link 127.0.0.1:9999 test
echo hi | python3 airlock.py push --name a.txt && python3 airlock.py pull
```

If you touched the web page, open it and check the browser console is clean, in both
light and dark. If you touched the bridge, `airlock bridge check` walks the whole chain.

Bug reports are just as useful as code. The ones that help most say which machine ran
what, and paste the output rather than describing it.

---

<sub>Codé avec amour ♥ par Genereux & Claude</sub>
