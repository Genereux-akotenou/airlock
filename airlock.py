#!/usr/bin/env python3
"""
airlock - a tiny two-way drop box for an air-gapped workstation.

Single file, standard library only, Python 3.8+.
Run the server on ONE machine, both machines talk to it over the LAN
(or through an SSH tunnel when the LAN path is blocked).

    airlock.py serve                      start the server
    airlock.py link <url-with-token>      remember server on a client
    airlock.py push [files...]            send files (or stdin) to the drop
    airlock.py pull [id]                  fetch latest (or a given item)
    airlock.py ls                         list what is in the drop
    airlock.py alias [name]               show or change your pseudonym
    airlock.py rm <id|all>                delete
    airlock.py watch <dir>                auto-pull new items into a folder
    airlock.py deploy user@host           copy this script to a remote + run it
    airlock.py tunnel user@host           expose a local server on the remote

See README.md for the full story.
"""

import argparse
import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
import selectors
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "1.0.0"
DEFAULT_PORT = 8787
DEFAULT_ROOT = os.path.expanduser("~/.airlock")
CONFIG_PATH = os.path.expanduser("~/.config/airlock/config.json")
MAX_BODY = 512 * 1024 * 1024          # 512 MB per item
POLL_TIMEOUT = 25                      # long-poll seconds
PREVIEW_CHARS = 4000

# Unambiguous alphabet: no 0/O, 1/l/I, so a code is safe to read off one
# screen and type on the other machine's keyboard.
CODE_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"   # 31 chars
CODE_LENGTH = 6                                      # 31^6 = 887M combinations
ADJECTIVES = ("amber arctic atomic brisk cobalt crimson dusky electric ember feral gilded hollow "
              "iron lucid lunar neon nocturnal obsidian phantom prime quantum rogue silent solar "
              "stellar swift tidal umbral velvet vivid wired zephyr").split()
NOUNS = ("otter falcon mantis comet cipher lynx viper quasar badger raven tapir orca heron panther "
         "gecko moth kestrel ibex marten pangolin caracal axolotl narwhal jackal osprey serval "
         "tamarin vulture wombat yak zebu dingo").split()
FAILS_PER_IP = 10                                    # per FAIL_WINDOW seconds
FAILS_GLOBAL = 60
FAIL_WINDOW = 60


def make_code(length=CODE_LENGTH):
    """A short token a human can type: 'k7m-q3x'."""
    raw = "".join(secrets.choice(CODE_ALPHABET) for _ in range(length))
    return "-".join(raw[i:i + 3] for i in range(0, len(raw), 3))


def normalize_code(value):
    """Forgive case, dashes and spaces when the token is a short code."""
    return re.sub(r"[^a-z0-9]", "", (value or "").lower())


def is_short_code(value):
    return bool(value) and len(value) <= 16 and bool(re.fullmatch(r"[A-Za-z0-9 _-]+", value))


class Presence:
    """Who is in the room. Every authed request refreshes that client's clock."""

    TTL = 45          # a browser long-polls at least every 25s, so this is generous

    def __init__(self):
        self.lock = threading.Lock()
        self.seen = {}

    def touch(self, who):
        who = (who or "").strip()[:40]
        if not who:
            return
        with self.lock:
            self.seen[who] = time.time()

    def live(self):
        cutoff = time.time() - self.TTL
        with self.lock:
            self.seen = {k: v for k, v in self.seen.items() if v > cutoff}
            return sorted(self.seen)


class Throttle:
    """Sliding-window lockout on failed tokens - what makes a short code safe."""

    def __init__(self, per_ip=FAILS_PER_IP, per_all=FAILS_GLOBAL, window=FAIL_WINDOW):
        self.per_ip = per_ip
        self.per_all = per_all
        self.window = window
        self.lock = threading.Lock()
        self.by_ip = {}
        self.all = []

    def _trim(self, seq, now):
        cutoff = now - self.window
        while seq and seq[0] < cutoff:
            seq.pop(0)
        return seq

    def blocked(self, ip):
        """Seconds the caller must wait, or 0."""
        now = time.time()
        with self.lock:
            hits = self._trim(self.by_ip.get(ip, []), now)
            if len(hits) >= self.per_ip:
                return max(1, int(hits[0] + self.window - now))
            everyone = self._trim(self.all, now)
            if len(everyone) >= self.per_all:
                return max(1, int(everyone[0] + self.window - now))
        return 0

    def fail(self, ip):
        now = time.time()
        with self.lock:
            self.by_ip.setdefault(ip, []).append(now)
            self.all.append(now)
            if len(self.by_ip) > 512:
                for key in [k for k, v in self.by_ip.items() if not self._trim(v, now)]:
                    self.by_ip.pop(key, None)

    def clear(self, ip):
        with self.lock:
            self.by_ip.pop(ip, None)


# --------------------------------------------------------------------------
# store
# --------------------------------------------------------------------------

class Store:
    """Flat on-disk store: one .json meta + one .bin payload per item."""

    def __init__(self, root, keep=200, cap_bytes=4 * 1024 ** 3):
        self.root = root
        self.dir = os.path.join(root, "items")
        self.keep = keep
        self.cap_bytes = cap_bytes
        os.makedirs(self.dir, exist_ok=True)
        self.cond = threading.Condition()
        self.version = int(time.time())

    # -- ids ---------------------------------------------------------------

    @staticmethod
    def new_id():
        return "%013d-%s" % (int(time.time() * 1000), secrets.token_hex(3))

    def meta_path(self, item_id):
        return os.path.join(self.dir, item_id + ".json")

    def blob_path(self, item_id):
        return os.path.join(self.dir, item_id + ".bin")

    def valid(self, item_id):
        return bool(re.fullmatch(r"\d{13}-[0-9a-f]{6}", item_id or ""))

    # -- reads -------------------------------------------------------------

    def list(self):
        out = []
        for name in os.listdir(self.dir):
            if not name.endswith(".json"):
                continue
            try:
                with open(os.path.join(self.dir, name), "r", encoding="utf-8") as fh:
                    out.append(json.load(fh))
            except (OSError, ValueError):
                continue
        out.sort(key=lambda m: m.get("id", ""), reverse=True)
        return out

    def get(self, item_id):
        if not self.valid(item_id):
            return None
        try:
            with open(self.meta_path(item_id), "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return None

    # -- writes ------------------------------------------------------------

    def add_stream(self, reader, length, kind, name, mime, sender):
        item_id = self.new_id()
        blob = self.blob_path(item_id)
        sha = hashlib.sha256()
        written = 0
        with open(blob, "wb") as fh:
            remaining = length
            while remaining > 0:
                chunk = reader.read(min(262144, remaining))
                if not chunk:
                    break
                fh.write(chunk)
                sha.update(chunk)
                written += len(chunk)
                remaining -= len(chunk)

        preview = ""
        if kind == "text":
            try:
                with open(blob, "rb") as fh:
                    preview = fh.read(PREVIEW_CHARS * 4).decode("utf-8", "replace")[:PREVIEW_CHARS]
            except OSError:
                preview = ""

        meta = {
            "id": item_id,
            "kind": kind,
            "name": name or ("snippet.txt" if kind == "text" else "file.bin"),
            "mime": mime or ("text/plain" if kind == "text" else "application/octet-stream"),
            "size": written,
            "sha256": sha.hexdigest(),
            "from": sender or "unknown",
            "created": time.time(),
            "preview": preview,
        }
        with open(self.meta_path(item_id), "w", encoding="utf-8") as fh:
            json.dump(meta, fh)
        self.prune()
        self.bump()
        return meta

    def delete(self, item_id):
        if not self.valid(item_id):
            return False
        gone = False
        for path in (self.meta_path(item_id), self.blob_path(item_id)):
            try:
                os.remove(path)
                gone = True
            except OSError:
                pass
        if gone:
            self.bump()
        return gone

    def clear(self):
        n = 0
        for meta in self.list():
            if self.delete(meta["id"]):
                n += 1
        return n

    def prune(self):
        metas = self.list()
        total = 0
        for i, meta in enumerate(metas):
            total += meta.get("size", 0)
            if i >= self.keep or total > self.cap_bytes:
                for path in (self.meta_path(meta["id"]), self.blob_path(meta["id"])):
                    try:
                        os.remove(path)
                    except OSError:
                        pass

    # -- change notification ----------------------------------------------

    def bump(self):
        with self.cond:
            self.version += 1
            self.cond.notify_all()

    def wait(self, since, timeout=POLL_TIMEOUT):
        deadline = time.time() + timeout
        with self.cond:
            while self.version <= since:
                left = deadline - time.time()
                if left <= 0:
                    break
                self.cond.wait(left)
            return self.version


# --------------------------------------------------------------------------
# internet bridge (opt-in forward proxy, stdlib only)
# --------------------------------------------------------------------------

PROXY_PORT = 8888
PROXY_MINUTES = 30
PROXY_ALLOW = [
    "pypi.org", "files.pythonhosted.org", "pypi.python.org",
    "github.com", "codeload.github.com", "raw.githubusercontent.com",
    "objects.githubusercontent.com",
    "registry.npmjs.org", "npmjs.org",
    "crates.io", "static.crates.io",
    "deb.debian.org", "security.debian.org",
    "archive.ubuntu.com", "security.ubuntu.com",
    "huggingface.co", "cdn-lfs.huggingface.co",
    "cran.r-project.org", "repo.anaconda.com", "conda.anaconda.org",
]


class ProxyState:
    """The opt-in forward proxy. Dormant unless somebody turns it on."""

    def __init__(self, enabled=False, port=PROXY_PORT, allow=None,
                 minutes=PROXY_MINUTES, bind="0.0.0.0"):
        self.enabled = enabled          # did --enable-proxy appear on the command line
        self.port = port
        self.bind = bind
        self.allow = list(allow) if allow else []
        self.minutes = minutes
        self.lock = threading.Lock()
        self.server = None
        self.thread = None
        self.timer = None
        self.closing = None
        self.started = 0
        self.expires = 0
        self.requests = 0
        self.blocked = 0
        self.bytes = 0
        self.recent = []

    # -- policy ------------------------------------------------------------

    def permitted(self, host):
        if not self.allow:              # allowlist disabled with --proxy-allow any
            return True
        host = (host or "").lower().rstrip(".")
        for rule in self.allow:
            if host == rule or host.endswith("." + rule):
                return True
        return False

    def record(self, host, ok):
        with self.lock:
            if ok:
                self.requests += 1
            else:
                self.blocked += 1
            self.recent.append((time.time(), host, ok))
            if len(self.recent) > 40:
                self.recent.pop(0)

    # -- lifecycle ---------------------------------------------------------

    def running(self):
        return self.server is not None

    def start(self, minutes=None):
        if not self.enabled:
            return False, "the internet bridge was not enabled on this server"
        if self.running():
            return True, "already open"
        # A previous close may still be tearing its listener down; wait for it,
        # otherwise reopening races against our own socket and fails to bind.
        if self.closing and self.closing.is_alive():
            self.closing.join(timeout=5)
        bound = type("BoundProxy", (ProxyHandler,), {"state": self})
        srv = None
        for attempt in range(4):
            try:
                srv = ThreadingHTTPServer((self.bind, self.port), bound)
                break
            except OSError as exc:
                if attempt == 3:
                    return False, ("cannot bind port %d (%s)" % (self.port, exc))
                time.sleep(0.4)
        srv.daemon_threads = True
        self.server = srv
        self.thread = threading.Thread(target=srv.serve_forever, daemon=True)
        self.thread.start()
        span = self.minutes if minutes is None else minutes
        self.started = time.time()
        self.expires = (self.started + span * 60) if span else 0
        if span:
            self.timer = threading.Timer(span * 60, self.stop)
            self.timer.daemon = True
            self.timer.start()
        return True, "open"

    def stop(self):
        if self.timer:
            self.timer.cancel()
            self.timer = None
        srv, self.server = self.server, None
        if srv:
            def teardown(s=srv):
                try:
                    s.shutdown()          # stop the accept loop
                finally:
                    s.server_close()      # and RELEASE the listening socket
            # shutdown() blocks until serve_forever exits, and stop() can be
            # called from a request thread, so this has to happen off to the side.
            self.closing = threading.Thread(target=teardown, daemon=True)
            self.closing.start()
        self.started = self.expires = 0
        return True, "closed"

    def status(self):
        left = int(self.expires - time.time()) if self.expires else 0
        return {
            "enabled": self.enabled,
            "running": self.running(),
            "port": self.port,
            # The address the OTHER machine must dial. A browser sitting on
            # localhost would otherwise be told 127.0.0.1, which on the isolated
            # machine means itself - the single most likely way to get this wrong.
            "lan": lan_ips()[0],
            "allow": self.allow,
            "unrestricted": not self.allow,
            "minutes": self.minutes,
            "expires_in": max(0, left),
            "requests": self.requests,
            "blocked": self.blocked,
            "bytes": self.bytes,
            "recent": [{"at": r[0], "host": r[1], "ok": r[2]}
                       for r in reversed(self.recent[-12:])],
        }


def _pump(a, b, state=None):
    """Blind byte relay between two sockets, both directions."""
    sel = selectors.DefaultSelector()
    sel.register(a, selectors.EVENT_READ, b)
    sel.register(b, selectors.EVENT_READ, a)
    moved = 0
    try:
        while True:
            events = sel.select(timeout=120)
            if not events:
                break
            for key, _ in events:
                try:
                    chunk = key.fileobj.recv(65536)
                except OSError:
                    return moved
                if not chunk:
                    return moved
                moved += len(chunk)
                try:
                    key.data.sendall(chunk)
                except OSError:
                    return moved
    finally:
        sel.close()
        if state:
            with state.lock:
                state.bytes += moved
    return moved


class ProxyHandler(BaseHTTPRequestHandler):
    """Forward proxy: absolute-URI requests, plus CONNECT tunnels for https."""

    server_version = "airlock-bridge/" + VERSION
    protocol_version = "HTTP/1.1"
    state = None

    def log_message(self, fmt, *args):
        if os.environ.get("AIRLOCK_QUIET"):
            return
        sys.stderr.write("  bridge  %s  %s\n" % (self.client_address[0], fmt % args))

    def _refuse(self, host):
        self.state.record(host, False)
        body = ("airlock bridge: %s is not on the allowlist\n" % host).encode()
        self.send_response(403)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_CONNECT(self):
        host, _, port = self.path.rpartition(":")
        host = host.strip("[]")
        if not self.state.permitted(host):
            return self._refuse(host)
        try:
            remote = socket.create_connection((host, int(port or 443)), 15)
        except (OSError, ValueError) as exc:
            self.state.record(host, False)
            self.send_error(502, "bridge cannot reach %s (%s)" % (host, exc))
            return
        self.state.record(host, True)
        self.connection.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        try:
            _pump(self.connection, remote, self.state)
        finally:
            remote.close()
        self.close_connection = True

    def _forward(self):
        parts = urllib.parse.urlsplit(self.path)
        if not parts.hostname:
            self.send_error(400, "the bridge only takes absolute URLs (set http_proxy)")
            return
        host = parts.hostname
        if not self.state.permitted(host):
            return self._refuse(host)
        target = urllib.parse.urlunsplit(("", "", parts.path or "/", parts.query, ""))
        try:
            remote = socket.create_connection((host, parts.port or 80), 15)
        except OSError as exc:
            self.state.record(host, False)
            self.send_error(502, "bridge cannot reach %s (%s)" % (host, exc))
            return
        self.state.record(host, True)

        head = ["%s %s HTTP/1.1" % (self.command, target)]
        for key, value in self.headers.items():
            if key.lower() in ("proxy-connection", "connection", "keep-alive",
                               "proxy-authorization", "te", "trailer",
                               "transfer-encoding", "upgrade"):
                continue
            head.append("%s: %s" % (key, value))
        head.append("Connection: close")
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        moved = 0
        try:
            remote.sendall(("\r\n".join(head) + "\r\n\r\n").encode("latin-1"))
            left = length
            while left > 0:
                chunk = self.rfile.read(min(65536, left))
                if not chunk:
                    break
                remote.sendall(chunk)
                left -= len(chunk)
            while True:
                chunk = remote.recv(65536)
                if not chunk:
                    break
                moved += len(chunk)
                self.connection.sendall(chunk)
        except OSError:
            pass
        finally:
            remote.close()
            with self.state.lock:
                self.state.bytes += moved
        self.close_connection = True

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_PATCH = do_OPTIONS = _forward


# --------------------------------------------------------------------------
# web ui
# --------------------------------------------------------------------------

INDEX_HTML = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>airlock</title>
<link rel="icon" href="/favicon.svg">
<style>
:root{color-scheme:dark;
  --bg:#0d1117;--panel:#151b23;--line:#232c38;--input:#0b0f14;--btn:#1f2733;
  --txt:#e6edf3;--dim:#8b98a5;--hov:#ffffff;
  --accent:#FF6B35;--on-accent:#111;--drop:rgba(255,107,53,.14);
  --ok:#3fb950;--err:#f85149;--shadow:none;
  --t-com:#8b949e;--t-str:#a5d6ff;--t-num:#79c0ff;--t-kw:#ff7b72;
  --t-fn:#d2a8ff;--t-typ:#7ee787;--t-pun:#8b98a5;--t-add:#3fb950;--t-del:#f85149;
  --gold:#d8b46a;--gold-line:rgba(216,180,106,.55);--gold-a:rgba(216,180,106,.20);
  --gold-b:rgba(150,112,45,.14);--gold-glow:rgba(216,180,106,.26)}
:root[data-theme="light"]{color-scheme:light;
  --bg:#f4f6f8;--panel:#ffffff;--line:#dde2e8;--input:#ffffff;--btn:#eceff3;
  --txt:#16202b;--dim:#5c6a78;--hov:#000000;
  --accent:#D9531E;--on-accent:#fff;--drop:rgba(217,83,30,.10);
  --ok:#1a7f37;--err:#c0392b;--shadow:0 1px 2px rgba(16,24,40,.06);
  --t-com:#6e7781;--t-str:#0a3069;--t-num:#0550ae;--t-kw:#cf222e;
  --t-fn:#8250df;--t-typ:#116329;--t-pun:#57606a;--t-add:#1a7f37;--t-del:#c0392b;
  --gold:#8a6a24;--gold-line:rgba(138,106,36,.45);--gold-a:rgba(214,178,102,.30);
  --gold-b:rgba(190,152,74,.20);--gold-glow:rgba(138,106,36,.22)}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;min-height:100vh;min-height:100dvh;display:flex;flex-direction:column}
header{display:flex;align-items:center;gap:12px;padding:14px 18px;border-bottom:1px solid var(--line);position:sticky;top:0;background:var(--bg);z-index:5}
header h1{font-size:15px;margin:0;letter-spacing:.14em;text-transform:uppercase}
header h1 span{color:var(--accent)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--ok);box-shadow:0 0 8px var(--ok)}
.dot.off{background:var(--err);box-shadow:0 0 8px var(--err)}
.spacer{flex:1}
.host{color:var(--dim);font-size:12px}
.who{display:flex;align-items:center;gap:7px;padding:5px 11px;border-radius:20px;font-size:11.5px;color:var(--dim);background:transparent}
.who:hover{color:var(--txt)}
.who .pen{opacity:0;font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:var(--accent);transition:.15s}
.who:hover .pen{opacity:1}
.chip{width:9px;height:9px;border-radius:50%;flex:none;display:inline-block}
.live{display:flex;align-items:center;gap:5px;padding:4px 9px;border:1px solid var(--line);border-radius:20px;font-size:11.5px;color:var(--dim);white-space:nowrap}
.live svg{width:11px;height:11px;fill:currentColor;opacity:.8}
.live b{color:var(--txt);font-weight:600}
.meta .chip{width:7px;height:7px;margin-right:5px;vertical-align:baseline}
main{max-width:960px;margin:0 auto;padding:18px;width:100%;flex:1 0 auto}
.compose{border:1px solid var(--line);background:var(--panel);border-radius:10px;padding:12px;box-shadow:var(--shadow)}
textarea{width:100%;min-height:110px;resize:vertical;background:var(--input);color:var(--txt);border:1px solid var(--line);border-radius:8px;padding:10px;font:13px/1.5 ui-monospace,Menlo,monospace;outline:none}
textarea:focus{border-color:var(--accent)}
.row{display:flex;gap:8px;align-items:center;margin-top:10px;flex-wrap:wrap}
button{background:var(--btn);color:var(--txt);border:1px solid var(--line);border-radius:7px;padding:7px 13px;font:12px ui-monospace,Menlo,monospace;cursor:pointer}
button:hover{border-color:var(--accent);color:var(--hov)}
button.primary{background:var(--accent);border-color:var(--accent);color:var(--on-accent);font-weight:700}
button.icon{padding:6px 9px;font-size:13px;line-height:1}
.hint{color:var(--dim);font-size:12px}
input[type=search]{flex:1;min-width:160px;background:var(--input);border:1px solid var(--line);border-radius:7px;color:var(--txt);padding:7px 10px;font:12px ui-monospace,Menlo,monospace;outline:none}
.item{border:1px solid var(--line);background:var(--panel);border-radius:10px;padding:11px 13px;margin-top:12px;box-shadow:var(--shadow)}
.item h3{margin:0;font-size:13px;font-weight:600;word-break:break-all}
.thumb{display:block;margin-top:9px;max-width:100%;max-height:320px;width:auto;border:1px solid var(--line);border-radius:8px;background:var(--input)}
.meta{color:var(--dim);font-size:11.5px;margin-top:3px}
pre{margin:9px 0 0;background:var(--input);border:1px solid var(--line);border-radius:8px;padding:10px 10px 10px 0;max-height:300px;overflow:auto;font-size:12.5px;line-height:1.55;tab-size:2}
pre code{display:block;counter-reset:ln;white-space:pre-wrap;word-break:break-word}
.ln{counter-increment:ln;display:block;position:relative;padding:0 4px 0 3.6em;min-height:1.55em}
.ln::before{content:counter(ln);position:absolute;left:0;width:2.7em;text-align:right;color:var(--t-com);opacity:.5;user-select:none;-webkit-user-select:none;font-variant-numeric:tabular-nums}
.ln:hover{background:color-mix(in srgb,var(--accent) 7%,transparent)}
.tc{color:var(--t-com);font-style:italic}
.ts{color:var(--t-str)}
.tn{color:var(--t-num)}
.tk{color:var(--t-kw)}
.tf{color:var(--t-fn)}
.tt{color:var(--t-typ)}
.tp{color:var(--t-pun)}
.ln.add{background:color-mix(in srgb,var(--t-add) 13%,transparent)}
.ln.add,.ln.add *{color:var(--t-add)}
.ln.del{background:color-mix(in srgb,var(--t-del) 13%,transparent)}
.ln.del,.ln.del *{color:var(--t-del)}
.ln.hunk,.ln.hunk *{color:var(--t-fn)}
.ln.metaline,.ln.metaline *{color:var(--t-com)}
.tag.lang{color:var(--accent);border-color:var(--accent)}
.tag{display:inline-block;border:1px solid var(--line);border-radius:5px;padding:1px 6px;font-size:10.5px;color:var(--dim);margin-right:6px;text-transform:uppercase;letter-spacing:.08em}
.tag.file{color:var(--accent);border-color:var(--accent)}
.sbody section.danger h4{color:var(--t-del)}
.sbody section.danger{border-left:2px solid var(--t-del);padding-left:13px;margin-left:-15px;background:color-mix(in srgb,var(--t-del) 5%,transparent)}
#bridge{position:fixed;right:20px;bottom:20px;z-index:55;display:flex;flex-direction:column;align-items:flex-end;gap:9px;max-width:min(420px,calc(100vw - 40px))}
.bbtn{display:flex;align-items:center;gap:9px;padding:11px 18px;border-radius:24px;white-space:nowrap;
  font-size:12px;font-weight:600;letter-spacing:.03em;color:var(--gold);
  border:1px solid var(--gold-line);
  background:linear-gradient(180deg,var(--gold-a),var(--gold-b));
  box-shadow:0 6px 22px rgba(0,0,0,.22),inset 0 1px 0 rgba(255,255,255,.10)}
.bbtn:hover{border-color:var(--gold);box-shadow:0 8px 26px var(--gold-glow),inset 0 1px 0 rgba(255,255,255,.16)}
.blamp{width:8px;height:8px;border-radius:50%;background:var(--gold);opacity:.55;flex:none;transition:.2s}
#bridge.on .bbtn{color:var(--t-del);border-color:var(--t-del);
  background:linear-gradient(180deg,color-mix(in srgb,var(--t-del) 16%,transparent),color-mix(in srgb,var(--t-del) 9%,transparent))}
#bridge.on .blamp{opacity:1}
#bridge.on .blamp{background:var(--t-del);box-shadow:0 0 0 0 rgba(240,80,70,.55);animation:beat 1.8s infinite}
@keyframes beat{70%{box-shadow:0 0 0 9px rgba(240,80,70,0)}100%{box-shadow:0 0 0 0 rgba(240,80,70,0)}}
.bcard{background:var(--panel);border:1px solid var(--line);border-left:2px solid var(--t-del);border-radius:10px;padding:12px 13px;box-shadow:0 10px 30px rgba(0,0,0,.28);font-size:11.5px;color:var(--dim);width:100%;max-height:min(66vh,560px);overflow-y:auto;overscroll-behavior:contain}
.bcard b{color:var(--txt);font-weight:600}
.bcard .cmd{margin-top:7px}
.bcard .warn{color:var(--t-del);font-size:10.5px;letter-spacing:.06em;text-transform:uppercase}
.bhead{display:flex;align-items:center;gap:9px;width:100%;padding:0;border:0;background:transparent;color:inherit;text-align:left;font:inherit;cursor:pointer;position:sticky;top:-12px;background:var(--panel);padding:12px 0 6px;margin-top:-12px;z-index:1}
.bhead:hover{border:0}
.bhead .chev{margin-left:auto;color:var(--dim);font-size:11px;transition:transform .18s}
.bcard.open .bhead .chev{transform:rotate(90deg)}
.btally{margin-top:6px;font-size:11px}
.bbody{margin-top:10px;padding-top:10px;border-top:1px solid var(--line)}
[hidden]{display:none!important}
#docs{position:fixed;inset:0;background:rgba(8,12,17,.55);backdrop-filter:blur(3px);display:flex;align-items:flex-start;justify-content:center;padding:5vh 16px;z-index:60;overflow:auto}
.sheet{width:100%;max-width:760px;background:var(--panel);border:1px solid var(--line);border-radius:12px;box-shadow:0 18px 50px rgba(0,0,0,.32);overflow:hidden}
.shead{display:flex;align-items:center;gap:12px;padding:13px 16px;border-bottom:1px solid var(--line);position:sticky;top:0;background:var(--panel)}
.shead strong{font-size:12.5px;font-weight:600;letter-spacing:.06em}
.sbody{padding:4px 16px 20px}
.sbody section{padding:16px 0;border-bottom:1px solid var(--line)}
.sbody section:last-child{border-bottom:0}
.sbody h4{margin:0 0 7px;font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--accent)}
.sbody p{margin:0 0 11px;font-size:12.5px;line-height:1.65;color:var(--dim);max-width:64ch}
.cmd{display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding:6px 9px;margin-top:5px;background:var(--input);border:1px solid var(--line);border-radius:7px}
.cmd code{font-size:12px;color:var(--txt);word-break:break-all}
.cwhat{flex:1;min-width:120px;font-size:11px;color:var(--dim);text-align:right}
.cp{background:transparent;border:1px solid var(--line);border-radius:5px;padding:3px 8px;font-size:10px;letter-spacing:.06em;text-transform:uppercase;color:var(--dim);cursor:pointer}
.cp:hover{border-color:var(--accent);color:var(--accent)}
#drop{position:fixed;inset:0;background:var(--drop);backdrop-filter:blur(2px);border:3px dashed var(--accent);display:none;align-items:center;justify-content:center;font-size:20px;letter-spacing:.2em;z-index:50}
#drop.on{display:flex}
#toast{position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:var(--accent);color:var(--on-accent);padding:8px 16px;border-radius:20px;font-size:12px;font-weight:700;opacity:0;transition:.2s;pointer-events:none}
#toast.on{opacity:1}
.empty{color:var(--dim);text-align:center;padding:50px 0;font-size:13px}
footer{max-width:960px;width:100%;flex-shrink:0;margin:30px auto 0;padding:15px 18px 26px;border-top:1px solid var(--line);display:flex;flex-wrap:wrap;gap:6px 18px;align-items:baseline;color:var(--dim)}
footer .stat{font-size:10.5px;letter-spacing:.1em;text-transform:uppercase;white-space:nowrap}
footer .sig{font-size:11.5px;font-style:italic;opacity:.85}
footer .sig b{color:var(--accent);font-weight:400;font-style:normal}
progress{width:100%;margin-top:8px;height:4px}
</style>
<script>
(function(){
  var t;
  try{ t = localStorage.getItem('airlock_theme'); }catch(e){}
  if(t !== 'light' && t !== 'dark'){
    t = matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  }
  document.documentElement.setAttribute('data-theme', t);
})();
</script>
</head><body>
<header>
  <div class="dot" id="dot"></div>
  <h1>air<span>lock</span></h1>
  <div class="spacer"></div>
  <button class="who" id="me" onclick="renameMe()" title="Click to rename yourself"></button>
  <span class="live" id="live" hidden></span>
  <button class="icon" onclick="openDocs()" title="How to use airlock">docs</button>
  <button class="icon" id="theme" onclick="toggleTheme()" title="Light / dark"></button>
</header>
<main>
  <div class="compose">
    <textarea id="txt" placeholder="Paste code, a log, a command… then Cmd/Ctrl+Enter. Or drop a file anywhere."></textarea>
    <div class="row">
      <button class="primary" onclick="sendText()">Send text</button>
      <button onclick="fileInput.click()">Send file…</button>
      <input type="file" id="fileInput" multiple hidden>
      <span class="spacer"></span>
      <span class="hint" id="count"></span>
    </div>
    <progress id="prog" hidden></progress>
  </div>
  <div class="row" style="margin:16px 0 0">
    <input type="search" id="q" placeholder="filter…" oninput="render()">
    <button onclick="load()">Refresh</button>
    <button onclick="clearAll()">Clear all</button>
  </div>
  <div id="list"></div>
</main>
<footer>
  <span class="stat" id="stats">airlock __VERSION__</span>
  <span class="spacer"></span>
  <span class="sig">Codé avec amour <b>&#9829;</b> par Genereux &amp; Claude</span>
</footer>
<div id="bridge" hidden>
  <div class="bcard" id="bcard" hidden></div>
  <button class="bbtn" id="bbtn" onclick="toggleBridge()">
    <i class="blamp"></i><span id="btext">internet bridge</span>
  </button>
</div>
<div id="docs" hidden onclick="if(event.target===this)closeDocs()">
  <div class="sheet">
    <div class="shead">
      <strong>airlock &middot; how to use it</strong>
      <span class="spacer"></span>
      <button class="icon" onclick="closeDocs()" title="Close (Esc)">&times;</button>
    </div>
    <div class="sbody" id="docsBody"></div>
  </div>
</div>
<div id="drop">RELEASE TO SEND</div>
<div id="toast"></div>
<script>
function applyTheme(t){
  document.documentElement.setAttribute('data-theme', t);
  document.getElementById('theme').textContent = t === 'dark' ? '\u263C' : '\u263E';
  try{ localStorage.setItem('airlock_theme', t); }catch(e){}
}
function toggleTheme(){
  applyTheme(document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
}
applyTheme(document.documentElement.getAttribute('data-theme') || 'dark');
matchMedia('(prefers-color-scheme: light)').addEventListener('change', function(e){
  var saved; try{ saved = localStorage.getItem('airlock_theme'); }catch(err){}
  if(!saved) applyTheme(e.matches ? 'light' : 'dark');
});

const BUILD = '__VERSION__';
const tok = new URLSearchParams(location.search).get('t') || localStorage.getItem('airlock_token') || '';
if (tok) localStorage.setItem('airlock_token', tok);
let items = [], version = 0, me = '';

function H(){
  const h = me ? {'X-Airlock-From': encodeURIComponent(me)} : {};
  if(tok) h['X-Airlock-Token'] = tok;
  return h;
}
function toast(m){ const t=document.getElementById('toast'); t.textContent=m; t.classList.add('on'); setTimeout(()=>t.classList.remove('on'),1400); }
function bytes(n){ const u=['B','KB','MB','GB']; let i=0; while(n>=1024&&i<3){n/=1024;i++;} return n.toFixed(i?1:0)+u[i]; }
function ago(ts){ const s=(Date.now()/1000)-ts; if(s<60)return Math.max(0,s|0)+'s ago'; if(s<3600)return (s/60|0)+'m ago'; if(s<86400)return (s/3600|0)+'h ago'; return new Date(ts*1000).toLocaleString(); }
function esc(s){ return s.replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }

/* ---- session pseudonyms: memorable, colour-coded, renameable ---- */
const ADJ = ['amber','arctic','atomic','brisk','cobalt','crimson','dusky','electric','ember','feral','gilded','hollow','iron','lucid','lunar','neon','nocturnal','obsidian','phantom','prime','quantum','rogue','silent','solar','stellar','swift','tidal','umbral','velvet','vivid','wired','zephyr'];
const NOUN = ['otter','falcon','mantis','comet','cipher','lynx','viper','quasar','badger','raven','tapir','orca','heron','panther','gecko','moth','kestrel','ibex','marten','pangolin','caracal','axolotl','narwhal','jackal','osprey','serval','tamarin','vulture','wombat','yak','zebu','dingo'];

function pick(a){ return a[Math.floor(Math.random() * a.length)]; }
function makeAlias(){ return pick(ADJ) + '-' + pick(NOUN); }

function cleanAlias(v){
  v = (v || '').trim().replace(/\s+/g, '-').replace(/[^\w.-]/g, '');
  v = v.replace(/[-._]{2,}/g, '-').replace(/^[-._]+|[-._]+$/g, '');
  return v.slice(0, 32);
}

function loadAlias(){
  let a;
  try{ a = localStorage.getItem('airlock_alias'); }catch(e){}
  if(!cleanAlias(a)){
    a = makeAlias();
    try{ localStorage.setItem('airlock_alias', a); }catch(e){}
  }
  return a;
}

function saveAlias(a){
  try{ localStorage.setItem('airlock_alias', a); }catch(e){}
}

/* Stable colour per pseudonym, so the same person keeps the same chip. */
function hueOf(name){
  let h = 0;
  for(let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) % 360;
  return h;
}
function chip(name){
  return '<i class="chip" style="background:hsl(' + hueOf(name) + ' 62% 52%)"></i>';
}

const USER_ICON = '<svg viewBox="0 0 16 16"><circle cx="8" cy="5" r="3"/>'
  + '<path d="M2 15c0-3.3 2.7-5 6-5s6 1.7 6 5z"/></svg>';

function paintLive(names, count){
  const el = document.getElementById('live');
  if(!count){ el.hidden = true; return; }
  el.hidden = false;
  el.innerHTML = USER_ICON + '<b>' + count + '</b>';
  el.title = count === 1 ? 'only you are here' : 'here now: ' + names.join(', ');
}

function paintMe(){
  document.getElementById('me').innerHTML =
    chip(me) + '<span>' + esc(me) + '</span><span class="pen">rename</span>';
}

function renameMe(){
  const next = cleanAlias(prompt('Your name in this lock:', me));
  if(!next || next === me) return;
  me = next;
  saveAlias(me);
  paintMe();
  toast('you are ' + me);
}

/* ---- in-page manual: the lab machine cannot open a README online ---- */
function oneLiner(){
  const h = (onLoopback() && bridgeSt && bridgeSt.lan) ? bridgeSt.lan : location.hostname;
  const p = location.port ? ':' + location.port : '';
  return 'eval "$(curl -s \'' + location.protocol + '//' + h + p + '/bridge.sh'
       + (tok ? '?t=' + encodeURIComponent(tok) : '') + '\')"';
}

function docSections(){
  const base = location.protocol + '//' + location.host;
  const url  = base + '/' + (tok ? '?t=' + tok : '');
  const link = tok ? "airlock link '" + url + "'" : "airlock link " + location.host;
  const secs = [
    {h:'What this is',
     p:'A drop box shared by every machine that can reach this page. It is a plain HTTP '
      +'server on your local network - the same technology as any website, except it talks '
      +'to a small Python process on one of your machines instead of the internet. Nothing '
      +'here ever leaves the local link, which is why the isolated machine can use it.',
     c:[]},
    {h:'On this page',
     p:'Paste code in the box and press Cmd/Ctrl+Enter. Drag a file anywhere on the window, '
      +'or paste one straight from the clipboard. Whatever you send appears on the other '
      +'machines within a second, no refresh. Copy puts a snippet on your clipboard, '
      +'Download saves a file. Click your name up top to rename yourself.',
     c:[]},
    {h:'Connect another machine',
     p:'Open the URL below in its browser, or wire up its terminal with the link command. '
      +'Anyone who can reach this address and knows the code joins the same lock.',
     c:[[url, 'open this in the other browser'],
        [link, 'or point its CLI here, once']]},
    {h:'Send things from the terminal',
     p:'Everything the page does has a command. Pipes work, which is the point.',
     c:[['airlock push src/api/http.js', 'send one file'],
        ['airlock push a.js b.js c.js', 'send several'],
        ['git diff | airlock push --name fix.patch', 'send anything on stdin'],
        ['docker logs auth | airlock push --name auth.log', 'ship a log across']]},
    {h:'Receive things',
     p:'Pull writes text to stdout so it composes with the rest of your shell.',
     c:[['airlock pull', 'latest snippet to stdout'],
        ['airlock pull > fix.patch', 'so redirection just works'],
        ['airlock pull --out .', 'latest item, saved as a file'],
        ['airlock pull --all --out ./inbox', 'take everything'],
        ['airlock ls', 'see what is in the lock']]},
    {h:'Keep a folder in sync',
     p:'The one to leave running while you work. New drops land in the folder as they '
      +'arrive, so you push from one machine and the file simply appears on the other.',
     c:[['airlock watch ~/inbox', 'auto-download new items'],
        ['airlock watch ~/inbox --rm', 'and clear them from the server after']]},
    {h:'Who is who',
     p:'Each participant carries a pseudonym so a three-way session stays readable. It is '
      +'a label, not a login - the access code is what controls who gets in.',
     c:[['airlock alias', 'show your name'],
        ['airlock alias new', 'roll a fresh one'],
        ['airlock alias "Genereux"', 'or pick your own'],
        ['airlock push notes.md --as lab', 'one-off, without renaming yourself']]},
    {h:'When the LAN path is blocked',
     p:'If the lab machine cannot reach this server directly but you can SSH into it, push '
      +'the port through SSH instead. The tunnel encrypts the traffic too, which plain HTTP '
      +'does not. Or move the server onto the lab machine entirely.',
     c:[['airlock tunnel user@lab', 'server becomes 127.0.0.1 on the remote'],
        ['airlock deploy user@lab', 'copy the script there and run it instead']]},
    {h:'Good to know',
     p:'The lock keeps the 200 newest items, up to 4 GB, then drops the oldest - it is a '
      +'transit area, not storage. Everyone with the code sees everything. Wrong codes are '
      +'throttled to 10 tries a minute. Files stream to disk and are checksummed, so '
      +'binaries come out byte-for-byte identical.',
     c:[['airlock rm all', 'empty the lock when you are done']]},
    {h:'Danger zone &middot; internet bridge', danger:true,
     p:'airlock can also lend the isolated machine your internet, by running a small HTTP '
      +'proxy on this host that it dials out through. Understand what that means: it opens '
      +'a hole in the air gap, which is the one property the isolated machine is supposed '
      +'to have. Many labs forbid it outright. Check that it is allowed where you work '
      +'before you use it, and prefer to leave it shut the rest of the time.',
     p2:'It is off unless the server was started with --enable-proxy. Run that, and a '
      +'toggle appears at the bottom right of this page. By default only package mirrors '
      +'are reachable (pypi, npm, github, apt, huggingface) and it auto-closes after 30 '
      +'minutes. For ordinary web browsing you have to widen it with --proxy-allow any.',
     c:[['airlock serve --enable-proxy', 'arm it - then the toggle appears here'],
        ['airlock serve --enable-proxy --proxy-allow any', 'let any site through, for real browsing'],
        ['airlock serve --enable-proxy --proxy-minutes 0', 'no auto-close (not recommended)'],
        ['airlock bridge on', 'open it from a terminal instead'],
        ['airlock bridge status', 'see what went through it'],
        ['airlock bridge off', 'shut it now']]},
    {h:'Using the bridge on the isolated machine', danger:true,
     p:'Nothing to install over there. The fastest way is the one-liner below: it asks this '
      +'server for the right settings and applies them to your shell, so you never retype an '
      +'IP address. It only works while the bridge is open - otherwise it says so and changes '
      +'nothing. Everything it sets lives in that one shell.',
     p2:'After that, that shell\'s pip, npm, apt, git and curl reach the internet through this '
      +'machine. Browsers ignore those variables, so they get their own commands. You do not '
      +'browse from inside airlock; airlock is only the pipe. And ping will never work - it is '
      +'ICMP, not HTTP.',
     c:[[oneLiner(), 'the whole setup, one line'],
        ['export https_proxy=http://HOST:PORT', 'or set it by hand'],
        ['curl -I https://pypi.org', 'check it works'],
        ['unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY', 'hand the internet back'],
        ['google-chrome --proxy-server="http://HOST:PORT" --user-data-dir=/tmp/chrome-airlock',
         'Chrome, sandboxed profile']]}
  ];

  // Last section, and only while sharing is actually live on this machine:
  // the exact line to paste on the isolated box, address and code filled in.
  if(bridgeSt && bridgeSt.enabled && bridgeSt.running){
    const left = bridgeSt.expires_in || 0;
    secs.push({h:'&#9679; Internet sharing is ON right now', danger:true,
      p:'This machine is currently lending its internet to anything that can reach it at '
       + bridgeAddr() + '. '
       + (bridgeSt.unrestricted ? 'Any host is reachable.'
          : bridgeSt.allow.length + ' domains are reachable, everything else is refused.')
       + (left ? ' It closes itself in ' + Math.ceil(left/60) + ' minutes.' : '')
       + ' ' + bridgeSt.requests + ' requests have gone through so far.',
      p2:'Paste this on the isolated machine and its shell is set up - nothing to install, '
       + 'no address to retype. Run it again after the bridge auto-closes and reopens.',
      c:[[oneLiner(), 'paste this on the isolated machine'],
         ['curl -I https://pypi.org', 'then check it works']]});
  }
  return secs;
}

/* ---- the internet bridge toggle (only shown when armed) ---- */
let bridgeSt = null, bridgeTick = null, cardSig = '';

/* The command list starts folded away - the warning line is what matters at a
   glance. Click it to unfold; the choice is remembered per browser. */
let cardOpen = false;
try{ cardOpen = localStorage.getItem('airlock_bridge_card') === '1'; }catch(e){}

function toggleCard(){
  cardOpen = !cardOpen;
  try{ localStorage.setItem('airlock_bridge_card', cardOpen ? '1' : '0'); }catch(e){}
  cardSig = '';
  paintBridge();
}

function onLoopback(){
  return location.hostname === '127.0.0.1' || location.hostname === 'localhost'
      || location.hostname === '::1' || location.hostname === '[::1]';
}
/* The address the OTHER machine dials. Never hand it a loopback address:
   on the isolated machine 127.0.0.1 is itself, not this laptop. */
function bridgeAddr(){
  const host = (onLoopback() && bridgeSt && bridgeSt.lan) ? bridgeSt.lan : location.hostname;
  return host + ':' + (bridgeSt ? bridgeSt.port : '');
}

async function loadBridge(){
  try{
    const r = await fetch('/api/proxy', {headers: H()});
    if(!r.ok) return;
    bridgeSt = await r.json();
    paintBridge();
  }catch(e){}
}

function paintBridge(){
  const box = document.getElementById('bridge');
  if(!bridgeSt || !bridgeSt.enabled){ box.hidden = true; return; }
  box.hidden = false;
  const on = !!bridgeSt.running;
  box.classList.toggle('on', on);
  const left = bridgeSt.expires_in || 0;
  const clock = left ? '  ' + Math.floor(left/60) + ':' + String(left%60).padStart(2,'0') : '';
  document.getElementById('btext').textContent = on ? ('internet open' + clock) : 'internet bridge';
  const card = document.getElementById('bcard');
  card.hidden = !on;
  if(!on) return;
  const addr = bridgeAddr();
  const ip = addr.split(':')[0], port = addr.split(':')[1];
  // Firefox has no --proxy-server flag: the setting lives in a profile. This
  // builds a throwaway one and launches it, with no airlock needed over there.
  const ff = "mkdir -p ~/airlock-firefox && printf 'user_pref(\"network.proxy.type\",1);\\n"
    + "user_pref(\"network.proxy.http\",\"" + ip + "\");\\n"
    + "user_pref(\"network.proxy.http_port\"," + port + ");\\n"
    + "user_pref(\"network.proxy.ssl\",\"" + ip + "\");\\n"
    + "user_pref(\"network.proxy.ssl_port\"," + port + ");\\n"
    + "user_pref(\"network.proxy.share_proxy_settings\",true);\\n' > ~/airlock-firefox/user.js"
    + " && firefox -no-remote -profile ~/airlock-firefox";
  // The server's own address as the OTHER machine must dial it - loopback would
  // point the isolated machine back at itself.
  const srvHost = (onLoopback() && bridgeSt && bridgeSt.lan) ? bridgeSt.lan : location.hostname;
  const srvPort = location.port ? ':' + location.port : '';
  const oneliner = 'eval "$(curl -s \'' + location.protocol + '//' + srvHost + srvPort
    + '/bridge.sh' + (tok ? '?t=' + encodeURIComponent(tok) : '') + '\')"';
  const rows = [
    [oneliner, 'the whole setup, one line'],
    ['export https_proxy=http://' + addr + ' http_proxy=http://' + addr,
     'or set it by hand'],
    ['curl -I https://pypi.org', 'check it works'],
    ['google-chrome --proxy-server="http://' + addr + '" --user-data-dir=/tmp/chrome-airlock',
     'Chrome, sandboxed profile'],
    [ff, 'Firefox, throwaway profile'],
    ['unset http_proxy https_proxy', 'hand the internet back']
  ];
  const tally =
      (bridgeSt.unrestricted ? '<b>any host</b> allowed'
                             : '<b>' + bridgeSt.allow.length + ' domains</b> allowed, everything else refused')
    + ' &middot; <b>' + bridgeSt.requests + '</b> through, <b>' + bridgeSt.blocked + '</b> blocked'
    + ' &middot; ' + bytes(bridgeSt.bytes);

  // Rebuild only when something actually changed. The clock ticks every second,
  // and re-writing innerHTML that often would cancel any text you were selecting.
  const sig = [addr, cardOpen, bridgeSt.requests, bridgeSt.blocked, bridgeSt.bytes,
               bridgeSt.unrestricted, (bridgeSt.allow||[]).length].join('|');
  if(sig === cardSig) return;
  cardSig = sig;

  card.classList.toggle('open', cardOpen);
  card.innerHTML =
      '<button class="bhead" onclick="toggleCard()" title="' + (cardOpen ? 'Hide' : 'Show') + ' the commands">'
    + '<span class="warn">&#9888; the air gap is open</span>'
    + '<span class="chev">&#9656;</span></button>'
    + '<div class="btally">' + tally + '</div>'
    + (cardOpen ?
        ('<div class="bbody">'
       + 'Run these <b>on the isolated machine</b>. Its own pip, npm, git and browser then '
       + 'reach the internet through this one.'
       + rows.map(function(r){
           return '<div class="cmd"><code>' + esc(r[0]) + '</code>'
                + '<span class="cwhat">' + esc(r[1]) + '</span>'
                + '<button class="cp" data-cmd="' + encodeURIComponent(r[0]) + '">copy</button></div>';
         }).join('')
       + '<div style="margin-top:9px;color:var(--t-com)">ping will not work through a proxy '
       + '(it is ICMP, not HTTP) - test with curl. Chrome needs its own --user-data-dir, or a '
       + 'running instance swallows the flag.</div></div>')
      : '');
}

async function toggleBridge(){
  const want = !(bridgeSt && bridgeSt.running);
  if(want && !confirm('Open the internet bridge?\n\nThe isolated machine will be able to reach the '
      + 'internet through this one. Make sure your lab allows that.')) return;
  try{
    const r = await fetch('/api/proxy', {method:'POST',
      headers: Object.assign({'Content-Type':'application/json'}, H()),
      body: JSON.stringify({on: want})});
    bridgeSt = await r.json();
    cardSig = '';
    paintBridge();
    if(want && !bridgeSt.running){
      // The server refused to open it - say why instead of just "closed".
      alert('The bridge could not be opened.\n\n' + (bridgeSt.message || 'unknown reason')
        + '\n\nMost often port ' + bridgeSt.port + ' is already taken by another process '
        + '(an airlock still running?). Free it, or restart the server with '
        + '--proxy-port on a different port.');
      toast('could not open');
      return;
    }
    toast(bridgeSt.running ? 'internet bridge open' : 'internet bridge closed');
  }catch(e){ toast('failed'); }
}

function startBridgeClock(){
  if(bridgeTick) return;
  bridgeTick = setInterval(function(){
    if(bridgeSt && bridgeSt.running && bridgeSt.expires_in > 0){
      bridgeSt.expires_in--;
      if(bridgeSt.expires_in === 0) loadBridge(); else paintBridge();
    }
  }, 1000);
  setInterval(loadBridge, 20000);
}

function openDocs(){
  const secs = docSections();
  document.getElementById('docsBody').innerHTML = secs.map(function(s){
    return '<section' + (s.danger ? ' class="danger"' : '') + '><h4>' + s.h + '</h4><p>' + esc(s.p) + '</p>'
      + (s.p2 ? '<p>' + esc(s.p2) + '</p>' : '')
      + s.c.map(function(row, n){
          return '<div class="cmd"><code>' + esc(row[0]) + '</code>'
               + '<span class="cwhat">' + esc(row[1]) + '</span>'
               + '<button class="cp" data-cmd="' + encodeURIComponent(row[0]) + '">copy</button></div>';
        }).join('')
      + '</section>';
  }).join('');
  document.getElementById('docs').hidden = false;
  document.body.style.overflow = 'hidden';
}

function closeDocs(){
  document.getElementById('docs').hidden = true;
  document.body.style.overflow = '';
}

document.addEventListener('click', function(e){
  const b = e.target.closest ? e.target.closest('.cp') : null;
  if(!b) return;
  const text = decodeURIComponent(b.getAttribute('data-cmd'));
  const done = function(){ b.textContent = 'copied'; setTimeout(function(){ b.textContent = 'copy'; }, 1200); };
  if(navigator.clipboard){ navigator.clipboard.writeText(text).then(done, done); }
  else {
    const a = document.createElement('textarea');
    a.value = text; document.body.appendChild(a); a.select();
    try{ document.execCommand('copy'); }catch(err){}
    a.remove(); done();
  }
});

addEventListener('keydown', function(e){
  if(e.key === 'Escape' && !document.getElementById('docs').hidden) closeDocs();
});

/* ---- self-contained syntax highlighter: no library, no network ---- */
const KW = {
  js:'as async await break case catch class const continue debugger default delete do else export extends finally for from function get if import in instanceof let new of return set static super switch this throw try typeof var void while with yield true false null undefined',
  ts:'abstract any as async await boolean break case catch class const constructor continue declare default delete do else enum export extends finally for from function get if implements import in instanceof interface let namespace never new number of private protected public readonly return set static string super switch this throw try type typeof undefined var void while yield true false null',
  py:'and as assert async await break class continue def del elif else except finally for from global if import in is lambda nonlocal not or pass raise return try while with yield True False None self cls match case',
  sh:'if then else elif fi for while until do done case esac function return export local readonly source shift exit set unset trap read echo cd eval exec',
  sql:'select from where insert into values update set delete create table alter drop add column index unique primary key foreign references constraint join left right inner outer full on group by order asc desc limit offset having distinct as and or not null is in between like exists union all case when then else end with returning cascade default check',
  json:'true false null',
  yaml:'true false null yes no on off',
  css:'important inherit initial unset auto none',
  html:'',
  prisma:'model enum datasource generator provider url relationMode String Int BigInt Boolean DateTime Float Decimal Json Bytes',
  docker:'FROM RUN CMD LABEL MAINTAINER EXPOSE ENV ADD COPY ENTRYPOINT VOLUME USER WORKDIR ARG ONBUILD STOPSIGNAL HEALTHCHECK SHELL AS',
  ini:'true false',
  plain:''
};
const TQ_D = '\u0022\u0022\u0022', TQ_S = '\u0027\u0027\u0027';
const LANGS = {
  js    :{lc:['//'],    bc:[['/*','*/']],    q:['"',"'",'`']},
  ts    :{lc:['//'],    bc:[['/*','*/']],    q:['"',"'",'`']},
  py    :{lc:['#'],     bc:[],               q:['"',"'"], tq:[TQ_D, TQ_S]},
  sh    :{lc:['#'],     bc:[],               q:['"',"'"]},
  sql   :{lc:['--'],    bc:[['/*','*/']],    q:["'",'"'], ci:true},
  json  :{lc:[],        bc:[],               q:['"']},
  yaml  :{lc:['#'],     bc:[],               q:['"',"'"]},
  css   :{lc:['//'],    bc:[['/*','*/']],    q:['"',"'"]},
  html  :{lc:[],        bc:[['<!--','-->']], q:['"',"'"], tag:true},
  prisma:{lc:['//'],    bc:[['/*','*/']],    q:['"']},
  docker:{lc:['#'],     bc:[],               q:['"',"'"]},
  ini   :{lc:['#',';'], bc:[],               q:['"',"'"]},
  plain :{lc:[],        bc:[],               q:[]}
};
for(const k in LANGS){
  const words = (KW[k]||'').split(/\s+/).filter(Boolean);
  LANGS[k].set = new Set(LANGS[k].ci ? words.map(w=>w.toLowerCase()) : words);
}

const EXT = {js:'js',mjs:'js',cjs:'js',jsx:'js',ts:'ts',tsx:'ts',vue:'html',html:'html',htm:'html',
  xml:'html',svg:'html',css:'css',scss:'css',less:'css',py:'py',pyw:'py',sh:'sh',bash:'sh',zsh:'sh',
  sql:'sql',json:'json',yaml:'yaml',yml:'yaml',diff:'diff',patch:'diff',prisma:'prisma',
  dockerfile:'docker',env:'ini',ini:'ini',toml:'ini',cfg:'ini',conf:'ini'};

function detectLang(name, code){
  const base = (name||'').toLowerCase();
  if(/^dockerfile/.test(base)) return 'docker';
  if(/^\.?env(\.|$)/.test(base)) return 'ini';
  const ext = base.indexOf('.') >= 0 ? base.split('.').pop() : '';
  if(EXT[ext]) return EXT[ext];
  const head = (code||'').slice(0, 800);
  if(!head.trim()) return 'plain';
  if(/^(diff --git |index [0-9a-f]+\.\.|@@ -|\+\+\+ |--- )/m.test(head)) return 'diff';
  if(/^#!.*\b(bash|sh|zsh)\b/.test(head)) return 'sh';
  if(/^#!.*\bpython/.test(head)) return 'py';
  if(/^\s*[[{]/.test(head) && /"[^"\n]*"\s*:/.test(head)) return 'json';
  if(/^\s*(def |class |import |from )/m.test(head) && /:\s*$/m.test(head)) return 'py';
  if(/\b(const |let |var |function |=>|require\(|export default|console\.)/.test(head)) return 'js';
  if(/\b(SELECT|INSERT INTO|CREATE TABLE|ALTER TABLE)\b/i.test(head)) return 'sql';
  if(/^\s*</.test(head)) return 'html';
  if(/^\s*[\w.-]+\s*:\s*\S/m.test(head) && !/[;{}]/.test(head)) return 'yaml';
  if(/^[A-Z][A-Z0-9_]*=/m.test(head)) return 'ini';
  if(/^\s*[.#@]?[\w-]+\s*\{[^}]*:/m.test(head)) return 'css';
  return 'plain';
}

function tokenize(code, L){
  const out = [], n = code.length;
  const push = (k,v) => { if(v) out.push([k,v]); };
  let i = 0;
  while(i < n){
    const c = code[i];
    let hit = false;

    for(const pair of (L.bc||[])){
      if(code.startsWith(pair[0], i)){
        let e = code.indexOf(pair[1], i + pair[0].length);
        e = e < 0 ? n : e + pair[1].length;
        push('c', code.slice(i, e)); i = e; hit = true; break;
      }
    }
    if(hit) continue;

    for(const a of (L.lc||[])){
      if(code.startsWith(a, i)){
        let e = code.indexOf('\n', i); if(e < 0) e = n;
        push('c', code.slice(i, e)); i = e; hit = true; break;
      }
    }
    if(hit) continue;

    for(const q of (L.tq||[])){
      if(code.startsWith(q, i)){
        let e = code.indexOf(q, i + q.length);
        e = e < 0 ? n : e + q.length;
        push('s', code.slice(i, e)); i = e; hit = true; break;
      }
    }
    if(hit) continue;

    if((L.q||[]).indexOf(c) >= 0){
      let j = i + 1;
      while(j < n){
        if(code[j] === '\\') { j += 2; continue; }
        if(code[j] === c){ j++; break; }
        if(code[j] === '\n' && c !== '`') break;
        j++;
      }
      push('s', code.slice(i, j)); i = j; continue;
    }

    if(L.tag && c === '<' && /[a-zA-Z\/!]/.test(code[i+1] || '')){
      let j = i + 1; if(code[j] === '/') j++;
      while(j < n && /[\w:.-]/.test(code[j])) j++;
      push('p', '<'); push('t', code.slice(i+1, j)); i = j; continue;
    }

    if(c >= '0' && c <= '9' && !/[\w$]/.test(code[i-1] || '')){
      let j = i; while(j < n && /[\w.]/.test(code[j])) j++;
      push('n', code.slice(i, j)); i = j; continue;
    }

    if(/[A-Za-z_$@]/.test(c)){
      let j = i; if(c === '@') j++;
      while(j < n && /[\w$]/.test(code[j])) j++;
      const word = code.slice(i, j);
      const probe = L.ci ? word.toLowerCase() : word;
      let a = j; while(a < n && code[a] === ' ') a++;
      let k = 'w';
      if(L.set.has(probe)) k = 'k';
      else if(code[a] === '(') k = 'f';
      else if(word.charAt(0) === '@') k = 'k';
      else if(/^[A-Z]/.test(word) && /[a-z]/.test(word)) k = 't';
      push(k, word); i = j; continue;
    }

    if(/[{}()[\].,;:+\-*/%<>=!&|^~?]/.test(c)){ push('p', c); i++; continue; }
    push('w', c); i++;
  }
  return out;
}

function diffClass(line){
  if(/^(diff |index |new file|deleted file|similarity |rename )/.test(line)) return 'metaline';
  if(/^@@/.test(line)) return 'hunk';
  if(/^(\+\+\+|---)/.test(line)) return 'metaline';
  if(line.charAt(0) === '+') return 'add';
  if(line.charAt(0) === '-') return 'del';
  return '';
}

function highlight(code, lang){
  code = (code || '').replace(/\r\n?/g, '\n').replace(/\n$/, '');
  if(lang === 'diff'){
    return code.split('\n').map(function(l){
      return '<span class="ln ' + diffClass(l) + '">' + (esc(l) || ' ') + '</span>';
    }).join('');
  }
  const toks = tokenize(code, LANGS[lang] || LANGS.plain);
  const lines = [];
  let cur = '';
  for(const t of toks){
    const parts = t[1].split('\n');
    for(let x = 0; x < parts.length; x++){
      if(x > 0){ lines.push(cur); cur = ''; }
      if(!parts[x]) continue;
      cur += (t[0] === 'w') ? esc(parts[x])
           : '<span class="t' + t[0] + '">' + esc(parts[x]) + '</span>';
    }
  }
  lines.push(cur);
  return lines.map(function(l){ return '<span class="ln">' + (l || ' ') + '</span>'; }).join('');
}


async function load(){
  try{
    const r = await fetch('/api/items',{headers:H()});
    if(r.status===401){ document.getElementById('list').innerHTML='<div class="empty">Unauthorized. Open the link with ?t=&lt;token&gt;</div>'; return; }
    const d = await r.json();
    items = d.items; version = d.version;
    paintLive(d.live || [], d.live_count || 0);
    document.getElementById('me').title = 'you are ' + me + ' at ' + (d.you || '?') + ' - click to rename';
    const total = items.reduce((n, i) => n + i.size, 0);
    document.getElementById('stats').textContent =
      'airlock ' + BUILD + '  ·  ' + items.length + ' item' + (items.length === 1 ? '' : 's') +
      '  ·  ' + bytes(total) + ' held';
    document.getElementById('dot').classList.remove('off');
    render();
  }catch(e){ document.getElementById('dot').classList.add('off'); }
}

function render(){
  const q = document.getElementById('q').value.toLowerCase();
  const list = document.getElementById('list');
  const rows = items.filter(i => !q || (i.name+' '+(i.preview||'')+' '+i.from).toLowerCase().includes(q));
  if(!rows.length){ list.innerHTML = '<div class="empty">nothing in the lock</div>'; return; }
  list.innerHTML = rows.map(i => {
    const lang = i.kind === 'text' ? detectLang(i.name, i.preview || '') : null;
    const isImg = i.kind === 'file' && /^image\//.test(i.mime || '');
    const raw = '/api/items/' + i.id + '/raw?t=' + encodeURIComponent(tok);
    const tag = isImg ? (i.mime.split('/')[1] || 'image') : (lang || 'file');
    return `
    <div class="item">
      <div><span class="tag ${i.kind==='file'?'file':'lang'}">${esc(tag)}</span><span class="meta">${bytes(i.size)} · ${chip(i.from)}${esc(i.from)} · ${ago(i.created)}</span></div>
      ${isSnippet(i.name) ? '' : `<h3>${esc(i.name)}</h3>`}
      ${isImg ? `<a href="${raw}" target="_blank" rel="noopener"><img class="thumb" src="${raw}" alt="${esc(i.name)}" loading="lazy"></a>` : ''}
      ${i.kind==='text' ? `<pre><code>${highlight(i.preview||'', lang)}</code></pre>` : ''}
      <div class="row">
        ${i.kind==='text' ? `<button onclick="copy('${i.id}')">Copy</button>` : ''}
        <a href="/api/items/${i.id}/raw?t=${encodeURIComponent(tok)}&dl=1" download="${encodeURIComponent(i.name)}"><button>Download</button></a>
        <button onclick="del('${i.id}')">Delete</button>
        <span class="hint">${i.id}</span>
      </div>
    </div>`; }).join('');
}

async function copy(id){
  const r = await fetch('/api/items/'+id+'/raw',{headers:H()});
  const t = await r.text();
  try{ await navigator.clipboard.writeText(t); toast('copied'); }
  catch(e){ const a=document.createElement('textarea'); a.value=t; document.body.appendChild(a); a.select(); document.execCommand('copy'); a.remove(); toast('copied'); }
}
async function del(id){ await fetch('/api/items/'+id,{method:'DELETE',headers:H()}); load(); }
async function clearAll(){ if(!confirm('Delete everything in the lock?'))return; await fetch('/api/items',{method:'DELETE',headers:H()}); load(); }

async function post(body, kind, name, mime){
  const p = document.getElementById('prog');
  p.hidden = false; p.removeAttribute('value');
  try{
    const r = await fetch('/api/items', {method:'POST', headers:Object.assign({
      'X-Airlock-Kind':kind, 'X-Airlock-Name':encodeURIComponent(name),
      'X-Airlock-From':me, 'Content-Type':mime||'application/octet-stream'}, H()), body});
    if(!r.ok) throw new Error(await r.text());
    toast('sent'); load();
  }catch(e){ toast('failed'); alert(e.message); }
  finally{ p.hidden = true; }
}

function sendText(){
  const el = document.getElementById('txt');
  const v = el.value;
  if(!v.trim()) return;
  // Naming a snippet after its own first line produced things like
  // "def hello():.txt". A plain timestamp is honest and keeps downloads unique.
  const t = new Date();
  const stamp = [t.getHours(), t.getMinutes(), t.getSeconds()]
    .map(function(n){ return String(n).padStart(2,'0'); }).join('');
  post(new Blob([v]), 'text', 'snippet-' + stamp + '.txt', 'text/plain; charset=utf-8');
  el.value = '';
}
function isSnippet(name){ return /^snippet-\d{6}\.txt$/.test(name || ''); }
function sendFiles(files){ for(const f of files) post(f, 'file', f.name, f.type||'application/octet-stream'); }

document.getElementById('fileInput').addEventListener('change', e => { sendFiles(e.target.files); e.target.value=''; });
document.getElementById('txt').addEventListener('keydown', e => { if((e.metaKey||e.ctrlKey)&&e.key==='Enter') sendText(); });
document.addEventListener('paste', e => { const f=[...(e.clipboardData?.files||[])]; if(f.length){ e.preventDefault(); sendFiles(f);} });
let dc = 0;
addEventListener('dragenter', e => { e.preventDefault(); if(++dc) document.getElementById('drop').classList.add('on'); });
addEventListener('dragover', e => e.preventDefault());
addEventListener('dragleave', e => { if(--dc<=0){ dc=0; document.getElementById('drop').classList.remove('on'); } });
addEventListener('drop', e => { e.preventDefault(); dc=0; document.getElementById('drop').classList.remove('on'); sendFiles(e.dataTransfer.files); });

async function poll(){
  for(;;){
    try{
      const r = await fetch('/api/wait?since='+version,{headers:H()});
      const d = await r.json();
      if(d.version !== version) await load();
      document.getElementById('dot').classList.remove('off');
    }catch(e){ document.getElementById('dot').classList.add('off'); await new Promise(r=>setTimeout(r,3000)); }
  }
}
me = loadAlias();
paintMe();
load(); poll();
loadBridge(); startBridgeClock();
</script></body></html>"""

FAVICON = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">'
           '<circle cx="50" cy="50" r="30" fill="none" stroke="#FF6B35" stroke-width="11"'
           ' stroke-linecap="round" stroke-dasharray="150 39"'
           ' transform="rotate(-105 50 50)"/></svg>')


# --------------------------------------------------------------------------
# server
# --------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "airlock/" + VERSION
    protocol_version = "HTTP/1.1"

    store = None
    token = None
    throttle = None
    proxy = None
    presence = None

    # -- helpers -----------------------------------------------------------

    def log_message(self, fmt, *args):
        if os.environ.get("AIRLOCK_QUIET"):
            return
        sys.stderr.write("  %s  %s\n" % (self.client_address[0], fmt % args))

    def token_ok(self, given):
        if hmac.compare_digest(given, self.token):
            return True
        # A short code is compared case- and dash-insensitively so it can be
        # read off one screen and typed on the other machine without fuss.
        if is_short_code(self.token):
            return hmac.compare_digest(normalize_code(given), normalize_code(self.token))
        return False

    def gate(self):
        """True when the request may proceed; otherwise the reply is already sent."""
        if not self.token:
            self.presence.touch(_unquote(self.headers.get("X-Airlock-From") or ""))
            return True
        ip = self.client_address[0]
        wait = self.throttle.blocked(ip)
        if wait:
            self.send(429, json.dumps({"error": "too many attempts", "retry_after": wait}),
                      "application/json", {"Retry-After": str(wait)})
            return False
        given = self.headers.get("X-Airlock-Token") or self.qs().get("t") or ""
        if self.token_ok(given):
            self.throttle.clear(ip)
            self.presence.touch(_unquote(self.headers.get("X-Airlock-From") or ""))
            return True
        self.throttle.fail(ip)
        self.json(401, {"error": "unauthorized"})
        return False

    def qs(self):
        out = {}
        if "?" in self.path:
            for part in self.path.split("?", 1)[1].split("&"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    out[k] = _unquote(v)
        return out

    def route(self):
        return self.path.split("?", 1)[0]

    def send(self, code, body=b"", ctype="application/json", extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def json(self, code, obj):
        self.send(code, json.dumps(obj), "application/json")

    # -- verbs -------------------------------------------------------------

    def do_GET(self):
        path = self.route()

        if path == "/favicon.svg":
            return self.send(200, FAVICON, "image/svg+xml")

        if path in ("/", "/index.html"):
            page = INDEX_HTML.replace("__VERSION__", VERSION)
            return self.send(200, page, "text/html; charset=utf-8")

        if path == "/api/ping":
            return self.json(200, {"ok": True, "version": VERSION, "auth": bool(self.token)})

        if not self.gate():
            return

        if path == "/api/items":
            live = self.presence.live()
            return self.json(200, {
                "items": self.store.list(),
                "version": self.store.version,
                "you": self.client_address[0],
                "live": live,
                "live_count": len(live),
            })

        if path == "/api/wait":
            try:
                since = int(self.qs().get("since", "0"))
            except ValueError:
                since = 0
            return self.json(200, {"version": self.store.wait(since)})

        if path == "/api/proxy":
            return self.json(200, self.proxy.status())

        if path in ("/bridge.sh", "/api/bridge.sh"):
            # Meant to be eval'd on the isolated machine, which has no airlock
            # installed and should not have to retype anyone's IP address:
            #   eval "$(curl -s 'http://<host>:<port>/bridge.sh?t=<code>')"
            st = self.proxy.status()
            addr = "%s:%d" % (st["lan"], st["port"])
            if not st["enabled"]:
                body = ("echo 'airlock: the internet bridge is not armed on the server.' >&2\n"
                        "echo '        Restart it there with: airlock serve --enable-proxy' >&2\n")
            elif not st["running"]:
                body = ("echo 'airlock: the internet bridge is closed.' >&2\n"
                        "echo '        Open it from the page toggle, or: airlock bridge on' >&2\n")
            else:
                left = st.get("expires_in") or 0
                policy = ("any host" if st["unrestricted"]
                          else "%d allowed domains" % len(st["allow"]))
                body = (
                    "export https_proxy='http://%s'\n"
                    "export http_proxy=\"$https_proxy\"\n"
                    "export HTTPS_PROXY=\"$https_proxy\"\n"
                    "export HTTP_PROXY=\"$https_proxy\"\n"
                    "export no_proxy='localhost,127.0.0.1,::1'\n"
                    "export NO_PROXY=\"$no_proxy\"\n"
                    "echo 'airlock: internet on via %s (%s%s)' >&2\n"
                    "echo '         test: curl -I https://pypi.org' >&2\n"
                    "echo '         off:  unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY' >&2\n"
                ) % (addr, addr, policy,
                     (", %d min left" % ((left + 59) // 60)) if left else "")
            return self.send(200, body, "text/plain; charset=utf-8")

        m = re.fullmatch(r"/api/items/([^/]+)/raw", path)
        if m:
            meta = self.store.get(m.group(1))
            if not meta:
                return self.json(404, {"error": "not found"})
            blob = self.store.blob_path(meta["id"])
            try:
                size = os.path.getsize(blob)
            except OSError:
                return self.json(404, {"error": "no payload"})
            disp = "attachment" if self.qs().get("dl") else "inline"
            self.send_response(200)
            self.send_header("Content-Type", meta.get("mime") or "application/octet-stream")
            self.send_header("Content-Length", str(size))
            self.send_header("Content-Disposition",
                             '%s; filename="%s"' % (disp, _safe_name(meta["name"])))
            self.send_header("X-Airlock-Name", _quote(meta["name"]))
            self.send_header("X-Airlock-Sha256", meta.get("sha256", ""))
            self.end_headers()
            with open(blob, "rb") as fh:
                shutil.copyfileobj(fh, self.wfile, 262144)
            return

        return self.json(404, {"error": "no route"})

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        if not self.gate():
            return

        if self.route() == "/api/proxy":
            try:
                size = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(size) or b"{}")
            except (ValueError, OSError):
                body = {}
            want_on = bool(body.get("on"))
            minutes = body.get("minutes")
            if want_on:
                ok, msg = self.proxy.start(int(minutes) if minutes else None)
            else:
                ok, msg = self.proxy.stop()
            out = self.proxy.status()
            out["message"] = msg
            return self.json(200 if ok else 409, out)

        if self.route() != "/api/items":
            return self.json(404, {"error": "no route"})
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0:
            return self.json(400, {"error": "empty body"})
        if length > MAX_BODY:
            return self.json(413, {"error": "too large"})

        kind = (self.headers.get("X-Airlock-Kind") or "file").lower()
        kind = "text" if kind == "text" else "file"
        name = _unquote(self.headers.get("X-Airlock-Name") or "")
        sender = (self.headers.get("X-Airlock-From") or self.client_address[0])[:64]
        mime = self.headers.get("Content-Type") or None

        meta = self.store.add_stream(self.rfile, length, kind, name, mime, sender)
        return self.json(201, meta)

    def do_DELETE(self):
        if not self.gate():
            return
        path = self.route()
        if path == "/api/items":
            return self.json(200, {"deleted": self.store.clear()})
        m = re.fullmatch(r"/api/items/([^/]+)", path)
        if m:
            ok = self.store.delete(m.group(1))
            return self.json(200 if ok else 404, {"deleted": 1 if ok else 0})
        return self.json(404, {"error": "no route"})


def _unquote(s):
    from urllib.parse import unquote
    return unquote(s)


def _quote(s):
    from urllib.parse import quote
    return quote(s)


def _safe_name(name):
    return re.sub(r'[^\w.\- ]+', "_", os.path.basename(name or "file"))[:120] or "file"


def lan_ips():
    ips = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("10.255.255.255", 1))
        ips.append(sock.getsockname()[0])
        sock.close()
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127.") and ip not in ips:
                ips.append(ip)
    except OSError:
        pass
    return ips or ["127.0.0.1"]


def cmd_serve(args):
    root = os.path.expanduser(args.dir)
    os.makedirs(root, exist_ok=True)

    token_file = os.path.join(root, "token")
    token = args.token or os.environ.get("AIRLOCK_TOKEN")
    if not token and not args.open:
        if os.path.exists(token_file) and not args.new_token:
            token = open(token_file).read().strip()
        else:
            token = make_code(args.code_length) if not args.long_token else secrets.token_urlsafe(18)
            with open(token_file, "w") as fh:
                fh.write(token)
            os.chmod(token_file, 0o600)

    Handler.store = Store(root, keep=args.keep, cap_bytes=args.cap * 1024 ** 3)
    Handler.token = token
    Handler.throttle = Throttle()
    Handler.presence = Presence()

    allow = PROXY_ALLOW
    if args.proxy_allow:
        allow = [] if args.proxy_allow.strip().lower() in ("any", "all", "*") \
            else [d.strip().lower() for d in args.proxy_allow.split(",") if d.strip()]
    Handler.proxy = ProxyState(enabled=args.enable_proxy, port=args.proxy_port,
                               allow=allow, minutes=args.proxy_minutes, bind=args.bind)
    if args.enable_proxy and args.proxy_on:
        Handler.proxy.start()

    httpd = ThreadingHTTPServer((args.bind, args.port), Handler)
    httpd.daemon_threads = True

    suffix = ("/?t=" + token) if token else "/"
    print("\n  airlock %s   store: %s" % (VERSION, root))
    print("  " + "-" * 58)
    for ip in lan_ips():
        print("  http://%s:%d%s" % (ip, args.port, suffix))
    print("  http://127.0.0.1:%d%s" % (args.port, suffix))
    if token:
        print("\n  code:  %s" % token)
        if is_short_code(token):
            print("         (type it as you like - case and dashes are ignored)")
        print("\n  on the other machine, either open the URL above, or:")
        print("    airlock link 'http://%s:%d%s'" % (lan_ips()[0], args.port, suffix))
        print("  wrong codes are throttled to %d tries/min per machine." % FAILS_PER_IP)
    else:
        print("\n  NO CODE - open server, trusted LAN only.")

    if args.enable_proxy:
        pol = "ANY host" if not Handler.proxy.allow else "%d allowed domains" % len(Handler.proxy.allow)
        print("\n  ! internet bridge ARMED on port %d - %s, %d min auto-close"
              % (args.proxy_port, pol, args.proxy_minutes))
        print("    it is %s. toggle it from the page, or: airlock bridge on|off|status"
              % ("OPEN NOW" if Handler.proxy.running() else "closed until someone opens it"))
        print("    this deliberately breaches the air gap. make sure that is allowed.")
    print("  " + "-" * 58 + "\n")
    sys.stdout.flush()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  bye")


# --------------------------------------------------------------------------
# client
# --------------------------------------------------------------------------

def load_config():
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def save_config(cfg):
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2)
    os.chmod(CONFIG_PATH, 0o600)


def endpoint(args):
    cfg = load_config()
    host = getattr(args, "host", None) or os.environ.get("AIRLOCK_HOST") or cfg.get("host")
    token = getattr(args, "token", None) or os.environ.get("AIRLOCK_TOKEN") or cfg.get("token")
    if not host:
        die("no server configured. run:  airlock.py link http://<ip>:8787/?t=<token>")
    return host.rstrip("/"), token


def call(host, token, path, method="GET", body=None, headers=None, stream=False, soft=False):
    req = urllib.request.Request(host + path, data=body, method=method)
    if token:
        req.add_header("X-Airlock-Token", token)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        resp = urllib.request.urlopen(req, timeout=None if path.startswith("/api/wait") else 60)
    except urllib.error.HTTPError as exc:
        payload = exc.read()
        if soft:
            return payload          # caller wants to read the error body itself
        die("server said %s: %s" % (exc.code, payload.decode("utf-8", "replace")[:300]))
    except urllib.error.URLError as exc:
        die("cannot reach %s (%s)" % (host, exc.reason))
    return resp if stream else resp.read()


def die(msg, code=1):
    sys.stderr.write("airlock: %s\n" % msg)
    raise SystemExit(code)


def make_alias():
    return "%s-%s" % (secrets.choice(ADJECTIVES), secrets.choice(NOUNS))


def clean_alias(value):
    out = re.sub(r"\s+", "-", (value or "").strip())
    out = re.sub(r"[^\w.-]", "", out)
    out = re.sub(r"[-._]{2,}", "-", out).strip("-._")
    return out[:32]


def whoami():
    """This machine's pseudonym, minted once and kept in the config."""
    override = clean_alias(os.environ.get("AIRLOCK_ALIAS"))
    if override:
        return override
    cfg = load_config()
    alias = clean_alias(cfg.get("alias"))
    if not alias:
        alias = make_alias()
        cfg["alias"] = alias
        save_config(cfg)
    return alias


def cmd_alias(args):
    if args.name:
        cfg = load_config()
        alias = clean_alias(args.name) if args.name != "new" else make_alias()
        if not alias:
            die("that name has nothing usable in it")
        cfg["alias"] = alias
        save_config(cfg)
        print("you are now %s" % alias)
    else:
        print(whoami())


def cmd_link(args):
    url = args.url
    token = args.code
    if "?" in url:
        base, query = url.split("?", 1)
        for part in query.split("&"):
            if part.startswith("t="):
                token = _unquote(part[2:])
        url = base
    url = url.rstrip("/")
    if not url.startswith("http"):
        url = "http://" + url
    if url.count(":") < 2 and not url.rsplit(":", 1)[-1].isdigit():
        url = "%s:%d" % (url, DEFAULT_PORT)
    cfg = load_config()
    cfg["host"] = url
    if token:
        cfg["token"] = token
    save_config(cfg)
    ping = json.loads(call(url, token, "/api/ping"))
    items = json.loads(call(url, token, "/api/items"))
    print("linked to %s (airlock %s) - %d item(s) in the lock"
          % (url, ping.get("version"), len(items["items"])))


def cmd_push(args):
    host, token = endpoint(args)
    sent = []
    if args.files:
        for path in args.files:
            if not os.path.isfile(path):
                die("not a file: %s" % path)
            size = os.path.getsize(path)
            mime = mimetypes.guess_type(path)[0] or "application/octet-stream"
            with open(path, "rb") as fh:
                data = fh.read()
            meta = json.loads(call(host, token, "/api/items", "POST", data, {
                "X-Airlock-Kind": "text" if args.text else "file",
                "X-Airlock-Name": _quote(os.path.basename(path)),
                "X-Airlock-From": args.sender or whoami(),
                "Content-Type": mime,
                "Content-Length": str(size),
            }))
            sent.append(meta)
    else:
        data = sys.stdin.buffer.read()
        if not data:
            die("nothing on stdin")
        name = args.name or "stdin-%s.txt" % time.strftime("%H%M%S")
        meta = json.loads(call(host, token, "/api/items", "POST", data, {
            "X-Airlock-Kind": "file" if args.binary else "text",
            "X-Airlock-Name": _quote(name),
            "X-Airlock-From": args.sender or whoami(),
            "Content-Type": "text/plain; charset=utf-8",
            "Content-Length": str(len(data)),
        }))
        sent.append(meta)
    for meta in sent:
        print("pushed %s  %s  (%s)" % (meta["id"], meta["name"], human(meta["size"])))


def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return "%.0f%s" % (n, unit) if unit == "B" else "%.1f%s" % (n, unit)
        n /= 1024.0


def cmd_ls(args):
    host, token = endpoint(args)
    data = json.loads(call(host, token, "/api/items"))
    if not data["items"]:
        print("(empty)")
        return
    for meta in data["items"]:
        when = time.strftime("%m-%d %H:%M", time.localtime(meta["created"]))
        print("%s  %-5s %8s  %s  %-28s %s" % (
            meta["id"], meta["kind"], human(meta["size"]), when,
            meta["from"][:28], meta["name"]))


def _fetch(host, token, meta, out_dir, force=False):
    resp = call(host, token, "/api/items/%s/raw" % meta["id"], stream=True)
    target = os.path.join(out_dir, _safe_name(meta["name"]))
    if os.path.exists(target) and not force:
        stem, ext = os.path.splitext(target)
        target = "%s.%s%s" % (stem, meta["id"][-6:], ext)
    os.makedirs(out_dir, exist_ok=True)
    with open(target, "wb") as fh:
        shutil.copyfileobj(resp, fh, 262144)
    return target


def cmd_pull(args):
    host, token = endpoint(args)
    data = json.loads(call(host, token, "/api/items"))
    items = data["items"]
    if not items:
        die("lock is empty")
    if args.id:
        items = [m for m in items if m["id"] == args.id or m["id"].endswith(args.id)]
        if not items:
            die("no item matching %s" % args.id)
    picked = items if args.all else items[:1]
    for meta in picked:
        if args.stdout or (meta["kind"] == "text" and not args.out and not args.all):
            resp = call(host, token, "/api/items/%s/raw" % meta["id"], stream=True)
            shutil.copyfileobj(resp, sys.stdout.buffer)
            sys.stdout.buffer.flush()
        else:
            path = _fetch(host, token, meta, args.out or ".", args.force)
            print("saved %s  (%s)" % (path, human(meta["size"])), file=sys.stderr)
        if args.rm:
            call(host, token, "/api/items/%s" % meta["id"], "DELETE")


def cmd_rm(args):
    host, token = endpoint(args)
    if args.id == "all":
        out = json.loads(call(host, token, "/api/items", "DELETE"))
        print("deleted %d" % out["deleted"])
        return
    data = json.loads(call(host, token, "/api/items"))
    hits = [m for m in data["items"] if m["id"] == args.id or m["id"].endswith(args.id)]
    if not hits:
        die("no item matching %s" % args.id)
    for meta in hits:
        call(host, token, "/api/items/%s" % meta["id"], "DELETE")
        print("deleted %s %s" % (meta["id"], meta["name"]))


def cmd_watch(args):
    host, token = endpoint(args)
    out_dir = os.path.abspath(args.dir)
    os.makedirs(out_dir, exist_ok=True)
    seen_path = os.path.join(out_dir, ".airlock-seen")
    seen = set()
    if os.path.exists(seen_path):
        seen = set(open(seen_path).read().split())
    data = json.loads(call(host, token, "/api/items"))
    version = data["version"]
    if args.catchup:
        pending = [m for m in reversed(data["items"]) if m["id"] not in seen]
    else:
        seen |= {m["id"] for m in data["items"]}
        pending = []
    print("watching %s -> %s  (ctrl-c to stop)" % (host, out_dir), file=sys.stderr)
    try:
        while True:
            for meta in pending:
                path = _fetch(host, token, meta, out_dir, args.force)
                seen.add(meta["id"])
                print("new  %s" % path, file=sys.stderr)
                if args.rm:
                    call(host, token, "/api/items/%s" % meta["id"], "DELETE")
            with open(seen_path, "w") as fh:
                fh.write("\n".join(sorted(seen)))
            try:
                res = json.loads(call(host, token, "/api/wait?since=%d" % version))
                version = res["version"]
            except SystemExit:
                time.sleep(5)
                continue
            data = json.loads(call(host, token, "/api/items"))
            version = data["version"]
            pending = [m for m in reversed(data["items"]) if m["id"] not in seen]
    except KeyboardInterrupt:
        print("\nstopped", file=sys.stderr)


def _bridge_report(host, token, st):
    where = urllib.parse.urlsplit(host).hostname or "the-server"
    # Never print a loopback address as the one to dial: on the isolated
    # machine 127.0.0.1 is itself, not the machine running the bridge.
    if where in ("127.0.0.1", "localhost", "::1") and st.get("lan"):
        where = st["lan"]
    if not st.get("enabled"):
        print("bridge: not enabled on this server")
        print("        restart it with:  airlock serve --enable-proxy")
        return
    if st.get("running"):
        left = st.get("expires_in") or 0
        print("bridge: OPEN on %s:%d%s" % (where, st["port"],
              ("  (closes in %d min)" % ((left + 59) // 60)) if left else ""))
        print()
        parts = urllib.parse.urlsplit(host)
        srv = "%s://%s:%s" % (parts.scheme or "http", where, parts.port or 8787)
        print("  on the isolated machine, the whole setup in one line:")
        print("    eval \"$(curl -s '%s/bridge.sh%s')\""
              % (srv, ("?t=" + token) if token else ""))
        print()
        print("  or by hand:")
        print("    export https_proxy=http://%s:%d" % (where, st["port"]))
        print("    export http_proxy=$https_proxy")
        print()
        print("  check it:  curl -I https://pypi.org")
        print("  (ping will not work through a proxy - it is ICMP, not HTTP)")
        print()
        print("  a browser there - it ignores the variables above:")
        print('    google-chrome --proxy-server="http://%s:%d" --user-data-dir=/tmp/chrome-airlock'
              % (where, st["port"]))
        print("    airlock bridge firefox        # or a throwaway proxied Firefox")
        print()
        print("  then pip/npm/apt/git work as usual. undo with:  unset http_proxy https_proxy")
    else:
        print("bridge: closed on port %d" % st["port"])
    pol = "any host (no allowlist)" if st.get("unrestricted") else \
        "%d allowed domains: %s" % (len(st["allow"]), ", ".join(st["allow"][:6]) +
                                    (" ..." if len(st["allow"]) > 6 else ""))
    print("  policy: %s" % pol)
    print("  traffic: %d allowed, %d blocked, %s relayed"
          % (st.get("requests", 0), st.get("blocked", 0), human(st.get("bytes", 0))))
    for entry in (st.get("recent") or [])[:8]:
        print("    %s  %-6s %s" % (time.strftime("%H:%M:%S", time.localtime(entry["at"])),
                                   "ok" if entry["ok"] else "BLOCK", entry["host"]))


def cmd_bridge_check(args):
    """Run this ON THE ISOLATED MACHINE. Tests each layer and names the broken one."""
    host, token = endpoint(args)
    ok = lambda m: print("  \033[32mOK\033[0m    %s" % m)
    bad = lambda m: print("  \033[31mFAIL\033[0m  %s" % m)

    print("airlock bridge check\n")

    # 1. can we reach the airlock server at all
    try:
        st = json.loads(call(host, token, "/api/proxy"))
    except SystemExit:
        bad("cannot reach the airlock server at %s" % host)
        print("\n  So the two machines have no path, or the code is wrong.")
        print("  Fix that first - the bridge cannot work before this does.")
        return 1
    ok("reached the airlock server at %s" % host)

    # 2. is the bridge armed, and open
    if not st.get("enabled"):
        bad("the bridge is not armed on the server")
        print("\n  On the OTHER machine, restart it with:  airlock serve --enable-proxy")
        return 1
    ok("the bridge is armed")
    if not st.get("running"):
        bad("the bridge is closed")
        print("\n  Open it from the page's toggle, or on the other machine:  airlock bridge on")
        return 1
    left = st.get("expires_in") or 0
    ok("the bridge is open%s" % (" (%d min left)" % ((left + 59) // 60) if left else ""))

    where = urllib.parse.urlsplit(host).hostname or ""
    if where in ("127.0.0.1", "localhost", "::1") and st.get("lan"):
        where = st["lan"]
    addr = (where, st["port"])
    print("  ->    proxy should be at %s:%d\n" % addr)

    # 3. plain TCP to the proxy port
    try:
        sock = socket.create_connection(addr, 8)
    except OSError as exc:
        bad("cannot open a TCP connection to %s:%d (%s)" % (addr[0], addr[1], exc))
        print("\n  The web port works but this one does not, so it is not the network path.")
        print("  On the machine running the bridge, check:")
        print("    lsof -nP -iTCP:%d -sTCP:LISTEN     # is anything listening" % addr[1])
        print("  If it is bound to 127.0.0.1 only, restart the server without --bind 127.0.0.1.")
        print("  A host firewall blocking that port would look exactly like this too.")
        return 1
    ok("TCP connection to the proxy port")

    # 4. CONNECT tunnel through it
    probe = "pypi.org"
    try:
        sock.sendall(("CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n" % (probe, probe)).encode())
        reply = sock.recv(200).decode("latin-1", "replace").splitlines()[0]
    except OSError as exc:
        bad("the proxy accepted the connection then dropped it (%s)" % exc)
        return 1
    finally:
        sock.close()
    if " 200 " not in reply:
        bad("CONNECT %s refused: %s" % (probe, reply.strip()))
        if "403" in reply:
            print("\n  That is the allowlist, not the network - the bridge IS reachable.")
            print("  Restart the server with --proxy-allow any, or add the domain you need.")
        return 1
    ok("CONNECT tunnel to %s (%s)" % (probe, reply.strip()))

    # 5. a real request end to end
    url = "https://%s/simple/" % probe
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": "http://%s:%d" % addr,
                                     "https": "http://%s:%d" % addr}))
    try:
        with opener.open(url, timeout=25) as resp:
            got = len(resp.read(2048))
        ok("fetched %s through the bridge (%d+ bytes)" % (url, got))
    except Exception as exc:
        bad("the tunnel opened but the request failed (%s)" % exc)
        return 1

    print("\n  The bridge works. Use it in this shell with:")
    print("    export https_proxy=http://%s:%d" % addr)
    print("    export http_proxy=$https_proxy")
    print("\n  Remember: ping will still fail. It is ICMP and ignores proxies entirely.")
    return 0


FIREFOX_CANDIDATES = [
    "/Applications/Firefox.app/Contents/MacOS/firefox",
    "/Applications/Firefox Developer Edition.app/Contents/MacOS/firefox",
    "/snap/bin/firefox", "/usr/bin/firefox", "/usr/bin/firefox-esr",
    "/usr/local/bin/firefox", "firefox", "firefox-esr",
]


def cmd_bridge_firefox(args):
    """Launch a throwaway Firefox whose proxy is set, leaving the system alone."""
    host, token = endpoint(args)
    st = json.loads(call(host, token, "/api/proxy"))
    if not st.get("enabled"):
        die("the bridge is not armed. On the other machine: airlock serve --enable-proxy")
    if not st.get("running"):
        die("the bridge is closed. Open it with:  airlock bridge on")

    where = urllib.parse.urlsplit(host).hostname or ""
    if where in ("127.0.0.1", "localhost", "::1") and st.get("lan"):
        where = st["lan"]
    port = st["port"]

    exe = args.browser
    if not exe:
        for cand in FIREFOX_CANDIDATES:
            found = cand if os.path.isfile(cand) else shutil.which(cand)
            if found:
                exe = found
                break
    if not exe:
        die("no firefox found. Install it, or point at it with --browser /path/to/firefox")

    profile = os.path.expanduser(args.profile)
    # Snap-packaged Firefox (the default on Ubuntu 22.04+) is confined by the
    # "home" interface, which does NOT grant access to dot-directories or /tmp.
    # A hidden profile path there fails with a bare "cannot open profile".
    snapish = "/snap/" in exe or os.path.exists("/snap/bin/firefox")
    hidden = any(part.startswith(".") for part in profile.split(os.sep) if part)
    if snapish and (hidden or profile.startswith("/tmp")):
        safe = os.path.expanduser("~/airlock-firefox")
        print("note: snap Firefox cannot read %s (hidden or /tmp paths are blocked by\n"
              "      snap confinement). Using %s instead." % (profile, safe))
        profile = safe
    try:
        os.makedirs(profile, exist_ok=True)
    except OSError as exc:
        die("cannot create the profile directory %s (%s)" % (profile, exc))
    prefs = [
        ('network.proxy.type', 1),                    # 1 = manual
        ('network.proxy.http', where), ('network.proxy.http_port', port),
        ('network.proxy.ssl', where), ('network.proxy.ssl_port', port),
        ('network.proxy.share_proxy_settings', True),
        ('network.proxy.socks_remote_dns', True),
        # The isolated machine has no DNS of its own; the proxy resolves names.
        ('network.dns.disablePrefetch', True),
        ('network.prefetch-next', False),
        # Quieten the background chatter that the allowlist would refuse anyway.
        ('network.connectivity-service.enabled', False),
        ('captivedetect.canonicalURL', ''),
        ('browser.safebrowsing.malware.enabled', False),
        ('browser.safebrowsing.phishing.enabled', False),
        ('app.update.enabled', False),
        ('datareporting.healthreport.uploadEnabled', False),
        ('toolkit.telemetry.enabled', False),
        ('browser.shell.checkDefaultBrowser', False),
        ('browser.startup.homepage', 'about:blank'),
    ]
    lines = []
    for key, value in prefs:
        if isinstance(value, bool):
            rendered = "true" if value else "false"
        elif isinstance(value, int):
            rendered = str(value)
        else:
            rendered = '"%s"' % value
        lines.append('user_pref("%s", %s);' % (key, rendered))
    with open(os.path.join(profile, "user.js"), "w") as fh:
        fh.write("\n".join(lines) + "\n")

    print("firefox    %s" % exe)
    print("profile    %s  (throwaway, your normal Firefox is untouched)" % profile)
    print("proxy      %s:%d" % (where, port))
    if not st.get("unrestricted"):
        print("\n  Note: only %d domains are allowed, so most of the web will show an error"
              % len(st.get("allow") or []))
        print("  page from airlock. For real browsing restart the server with --proxy-allow any.")
    print("\nlaunching. close the window when you are done.")
    try:
        subprocess.Popen([exe, "-no-remote", "-profile", profile] + (args.url and [args.url] or []),
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError as exc:
        die("could not launch firefox (%s)" % exc)


def cmd_bridge(args):
    if args.action == "check":
        raise SystemExit(cmd_bridge_check(args) or 0)
    if args.action == "firefox":
        return cmd_bridge_firefox(args)
    host, token = endpoint(args)
    if args.action in ("on", "off"):
        payload = {"on": args.action == "on"}
        if args.minutes:
            payload["minutes"] = args.minutes
        body = json.dumps(payload).encode()
        st = json.loads(call(host, token, "/api/proxy", "POST", body,
                             {"Content-Type": "application/json",
                              "Content-Length": str(len(body))}, soft=True))
        if not st.get("enabled"):
            die("bridge: %s\n         restart the server with:  airlock serve --enable-proxy"
                % st.get("message", "not enabled on this server"))
        if st.get("message") and not st.get("running") and args.action == "on":
            die("bridge: %s" % st["message"])
    else:
        st = json.loads(call(host, token, "/api/proxy"))
    _bridge_report(host, token, st)


# --------------------------------------------------------------------------
# ssh helpers
# --------------------------------------------------------------------------

def cmd_deploy(args):
    me = os.path.abspath(__file__)
    remote_path = args.path
    print("copying %s -> %s:%s" % (os.path.basename(me), args.target, remote_path))
    run(["scp", "-q", me, "%s:%s" % (args.target, remote_path)])
    run(["ssh", args.target, "chmod +x %s" % _sh(remote_path)])
    if args.start:
        cmd = ("nohup python3 %s serve --port %d --bind %s > ~/.airlock.log 2>&1 & sleep 1; "
               "tail -n 20 ~/.airlock.log") % (_sh(remote_path), args.port, _sh(args.bind))
        run(["ssh", args.target, cmd])
        print("\nserver started on %s. Copy the http:// line above." % args.target)
    else:
        print("done. Now:  ssh %s 'python3 %s serve'" % (args.target, remote_path))


def cmd_tunnel(args):
    """Publish the server running on THIS machine onto the remote's localhost."""
    port = args.port or DEFAULT_PORT
    token = args.token or os.environ.get("AIRLOCK_TOKEN")
    if not token:
        token_file = os.path.join(os.path.expanduser(args.dir), "token")
        if os.path.exists(token_file):
            token = open(token_file).read().strip()
    suffix = ("/?t=" + token) if token else "/"
    print("forwarding %s:%d  ->  127.0.0.1:%d here" % (args.target, args.remote_port, port))
    print("on %s, open or link:  http://127.0.0.1:%d%s" % (args.target, args.remote_port, suffix))
    print("(leave this running; ctrl-c closes the tunnel)\n")
    run(["ssh", "-N", "-R", "%d:127.0.0.1:%d" % (args.remote_port, port), args.target], check=False)


def _sh(s):
    return "'" + s.replace("'", "'\\''") + "'"


def run(cmd, check=True):
    proc = subprocess.run(cmd)
    if check and proc.returncode != 0:
        die("command failed: %s" % " ".join(cmd), proc.returncode)


# --------------------------------------------------------------------------
# cli
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(prog="airlock", description="two-way drop box for an air-gapped machine")
    ap.add_argument("--version", action="version", version="airlock " + VERSION)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("serve", help="run the server")
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--bind", default="0.0.0.0")
    p.add_argument("--dir", default=DEFAULT_ROOT)
    p.add_argument("--token", help="pick your own code, e.g. --token lab42")
    p.add_argument("--new-token", action="store_true", help="throw away the saved code and make a new one")
    p.add_argument("--code-length", type=int, default=CODE_LENGTH,
                   help="letters in the generated code (default %d)" % CODE_LENGTH)
    p.add_argument("--long-token", action="store_true",
                   help="generate a long random token instead of a typeable code")
    p.add_argument("--open", action="store_true", help="no code at all (trusted LAN only)")
    p.add_argument("--enable-proxy", action="store_true",
                   help="arm the internet bridge so it CAN be opened (breaches the air gap)")
    p.add_argument("--proxy-on", action="store_true", help="open the bridge immediately at startup")
    p.add_argument("--proxy-port", type=int, default=PROXY_PORT)
    p.add_argument("--proxy-minutes", type=int, default=PROXY_MINUTES,
                   help="auto-close after N minutes (0 = never, default %d)" % PROXY_MINUTES)
    p.add_argument("--proxy-allow", metavar="DOMAINS",
                   help="comma-separated allowlist, or 'any' to drop it (default: package mirrors)")
    p.add_argument("--keep", type=int, default=200, help="max items retained")
    p.add_argument("--cap", type=float, default=4.0, help="max store size in GB")
    p.set_defaults(func=cmd_serve)

    def client_args(parser):
        parser.add_argument("--host", help="http://ip:port of the server")
        parser.add_argument("--token")

    p = sub.add_parser("link", help="remember a server: paste the ?t= link, or host + code")
    p.add_argument("url", help="full ?t= url, or just 192.168.1.42:8787")
    p.add_argument("code", nargs="?", help="the short code, when not part of the url")
    p.set_defaults(func=cmd_link)

    p = sub.add_parser("push", help="send files, or stdin")
    p.add_argument("files", nargs="*")
    p.add_argument("--name", help="name to use for stdin")
    p.add_argument("--as", dest="sender", help="send under a different pseudonym, just this once")
    p.add_argument("--text", action="store_true", help="treat files as text (previewable)")
    p.add_argument("--binary", action="store_true", help="treat stdin as binary")
    client_args(p)
    p.set_defaults(func=cmd_push)

    p = sub.add_parser("pull", help="fetch the latest item (or one by id)")
    p.add_argument("id", nargs="?")
    p.add_argument("--out", help="directory to save into")
    p.add_argument("--all", action="store_true", help="pull everything")
    p.add_argument("--stdout", action="store_true", help="always write to stdout")
    p.add_argument("--rm", action="store_true", help="delete from server after pulling")
    p.add_argument("--force", action="store_true", help="overwrite existing files")
    client_args(p)
    p.set_defaults(func=cmd_pull)

    p = sub.add_parser("alias", help="show or change your pseudonym")
    p.add_argument("name", nargs="?", help="the new name, or 'new' to roll a fresh one")
    p.set_defaults(func=cmd_alias)

    p = sub.add_parser("bridge", help="open/close the internet bridge for the isolated machine")
    p.add_argument("action", nargs="?", default="status",
                   choices=["on", "off", "status", "check", "firefox"],
                   help="'check' diagnoses FROM the isolated machine, "
                        "'firefox' opens a proxied browser there")
    p.add_argument("--minutes", type=int, help="auto-close after N minutes (0 = never)")
    p.add_argument("--profile", default="~/.airlock-firefox",
                   help="throwaway firefox profile directory")
    p.add_argument("--browser", help="path to the firefox binary, if it is not found")
    p.add_argument("--url", help="page to open on launch")
    client_args(p)
    p.set_defaults(func=cmd_bridge)

    p = sub.add_parser("ls", help="list items")
    client_args(p)
    p.set_defaults(func=cmd_ls)

    p = sub.add_parser("rm", help="delete an item, or 'all'")
    p.add_argument("id")
    client_args(p)
    p.set_defaults(func=cmd_rm)

    p = sub.add_parser("watch", help="auto-download new items into a folder")
    p.add_argument("dir")
    p.add_argument("--catchup", action="store_true", help="also pull items already in the lock")
    p.add_argument("--rm", action="store_true")
    p.add_argument("--force", action="store_true")
    client_args(p)
    p.set_defaults(func=cmd_watch)

    p = sub.add_parser("deploy", help="scp this script to a remote host and start it")
    p.add_argument("target", help="user@host")
    p.add_argument("--path", default="~/airlock.py")
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--bind", default="0.0.0.0")
    p.add_argument("--no-start", dest="start", action="store_false")
    p.set_defaults(func=cmd_deploy)

    p = sub.add_parser("tunnel", help="push this machine's server onto a remote over ssh")
    p.add_argument("target", help="user@host")
    p.add_argument("--remote-port", type=int, default=DEFAULT_PORT)
    p.add_argument("--port", type=int, default=DEFAULT_PORT, help="local server port")
    p.add_argument("--dir", default=DEFAULT_ROOT, help="local store (to read the token)")
    p.add_argument("--token")
    p.set_defaults(func=cmd_tunnel)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
