#!/usr/bin/env bash
# Put `airlock` on your PATH. macOS and Linux, no dependencies.
# Usage:  ./install.sh [target-dir]        default: ~/.local/bin
# POSIX sh syntax throughout, so `sh install.sh` works too.
set -eu

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="$SRC_DIR/airlock.py"
DEST="${1:-$HOME/.local/bin}"
LINK="$DEST/airlock"

if [ ! -f "$SRC" ]; then
  echo "install.sh: cannot find airlock.py next to this script ($SRC_DIR)" >&2
  exit 1
fi

# airlock needs python3 3.8+. Check now rather than at first run.
PY=""
for cand in python3 python; do
  if command -v "$cand" >/dev/null 2>&1; then
    if "$cand" -c 'import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)' 2>/dev/null; then
      PY="$cand"
      break
    fi
  fi
done
if [ -z "$PY" ]; then
  echo "install.sh: need python3 3.8 or newer on this machine." >&2
  echo "            Debian/Ubuntu:  sudo apt install python3" >&2
  echo "            macOS:          xcode-select --install   (or brew install python)" >&2
  exit 1
fi
PYV="$("$PY" -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])')"

if ! mkdir -p "$DEST" 2>/dev/null; then
  echo "install.sh: cannot create $DEST - try another directory, or use sudo:" >&2
  echo "            sudo ./install.sh /usr/local/bin" >&2
  exit 1
fi
if [ ! -w "$DEST" ]; then
  echo "install.sh: $DEST is not writable - try another directory, or use sudo." >&2
  exit 1
fi

PYPATH="$(command -v "$PY")"
chmod +x "$SRC"

# A launcher rather than a symlink: it pins the interpreter we just verified,
# so a broken or ancient `python3` earlier on PATH cannot hijack the shebang.
# If that interpreter ever disappears, it falls back to whatever PATH offers.
rm -f "$LINK"
cat > "$LINK" <<LAUNCHER
#!/bin/sh
PY="$PYPATH"
[ -x "\$PY" ] || PY="\$(command -v python3 || command -v python)"
exec "\$PY" "$SRC" "\$@"
LAUNCHER
chmod +x "$LINK"

echo "airlock installed"
echo "  $LINK -> $SRC"
echo "  python $PYV ($PYPATH)"

case ":${PATH:-}:" in
  *":$DEST:"*)
    echo
    echo "Next:  airlock serve"
    ;;
  *)
    echo
    echo "$DEST is not on your PATH yet. Add it:"
    case "${SHELL:-}" in
      *zsh)  echo "  echo 'export PATH=\"$DEST:\$PATH\"' >> ~/.zshrc  && exec zsh" ;;
      *bash) echo "  echo 'export PATH=\"$DEST:\$PATH\"' >> ~/.bashrc && exec bash" ;;
      *)     echo "  export PATH=\"$DEST:\$PATH\"    (add this to your shell rc)" ;;
    esac
    echo
    echo "Or skip the PATH entirely:  $PY $SRC serve"
    ;;
esac
