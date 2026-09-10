#!/usr/bin/env bash
# Run airlock in the background on Ubuntu/Debian, and start it again on reboot.
# Installs a systemd *user* service - no root needed except for the linger step.
#
#   ./autostart-linux.sh --token lab42          # install and start
#   sudo loginctl enable-linger $USER           # keep running with nobody logged in

#   ./autostart-linux.sh --print --token lab42  # show the unit, install nothing
#   ./autostart-linux.sh --status               # is it running
#   ./autostart-linux.sh --logs                 # follow the log
#   ./autostart-linux.sh --uninstall            # stop and remove
#
# Anything you pass is handed to `airlock serve`, so --port, --dir, --keep all work.
set -eu

NAME="airlock"
UNIT_DIR="$HOME/.config/systemd/user"
UNIT="$UNIT_DIR/$NAME.service"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="$SRC_DIR/airlock.py"

MODE="install"
ARGS=""
for a in "$@"; do
  case "$a" in
    --uninstall) MODE="uninstall" ;;
    --status)    MODE="status" ;;
    --logs)      MODE="logs" ;;
    --print)     MODE="print" ;;
    *)           ARGS="$ARGS $a" ;;
  esac
done

have_systemd(){ command -v systemctl >/dev/null 2>&1; }

case "$MODE" in
uninstall)
  have_systemd || { echo "no systemctl here"; exit 1; }
  systemctl --user disable --now "$NAME" 2>/dev/null || true
  rm -f "$UNIT"
  systemctl --user daemon-reload 2>/dev/null || true
  echo "$NAME removed. Linger, if you enabled it, stays on:"
  echo "  sudo loginctl disable-linger $USER"
  exit 0 ;;
status)
  systemctl --user status "$NAME" --no-pager || true
  exit 0 ;;
logs)
  journalctl --user -u "$NAME" -f
  exit 0 ;;
esac

# --- find an interpreter, same rule as install.sh --------------------------
[ -f "$SRC" ] || { echo "autostart-linux.sh: airlock.py is not next to this script ($SRC_DIR)" >&2; exit 1; }
PY=""
for c in python3 python; do
  if command -v "$c" >/dev/null 2>&1 && \
     "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)' 2>/dev/null; then
    PY="$(command -v "$c")"; break
  fi
done
[ -n "$PY" ] || { echo "autostart-linux.sh: need python3 3.8+  (sudo apt install python3)" >&2; exit 1; }

# A service that arms the air gap on every boot is not what you want.
case "$ARGS" in
  *--enable-proxy*)
    echo
    echo "  !! --enable-proxy in an autostart service arms the internet bridge"
    echo "     every time this machine boots. Install the service without it, and"
    echo "     open the bridge by hand for the sessions where you actually need it."
    echo
    ;;
esac

UNIT_TEXT="[Unit]
Description=airlock - drop box between this machine and the isolated one
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$PY $SRC serve$ARGS
WorkingDirectory=$SRC_DIR
Restart=always
RestartSec=3
# journald already timestamps every line
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=default.target
"

if [ "$MODE" = "print" ]; then
  printf '%s' "$UNIT_TEXT"
  exit 0
fi

have_systemd || { echo "autostart-linux.sh: no systemd here. Use nohup, or your init system." >&2; exit 1; }

mkdir -p "$UNIT_DIR"
printf '%s' "$UNIT_TEXT" > "$UNIT"
systemctl --user daemon-reload
systemctl --user enable --now "$NAME"

echo "airlock installed as a user service"
echo "  unit    $UNIT"
echo "  runs    $PY $SRC serve$ARGS"
echo
systemctl --user --no-pager --lines=0 status "$NAME" 2>/dev/null | sed -n '1,3p' || true
echo
echo "It restarts on crash and comes back when you log in. To have it run"
echo "even with nobody logged in - which is what you want on a server:"
echo "  sudo loginctl enable-linger $USER"
echo
echo "  logs       ./autostart-linux.sh --logs"
echo "  status     ./autostart-linux.sh --status"
echo "  remove     ./autostart-linux.sh --uninstall"
