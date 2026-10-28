#!/bin/sh
# package.sh -- assemble an unsigned GhostDrive .spk for DSM 7 (x86_64).
#
# This is scaffolding, not a signing pipeline. It has been validated with
# `sh -n` and its output tree structurally reviewed; it has NOT been run on a
# real DSM box. DSM refuses unsigned packages through the normal UI — see
# SPK_BUILD.md before spending your evening on this route.
#
# Build-host requirements (the NAS itself is NOT one of them):
#   - python3 (override with PYTHON=/path/to/python3)
#   - network access (pip resolves deps from pyproject.toml ranges)
#   - C toolchain + libsqlcipher headers, because sqlcipher3 builds from
#     source (same story as the Docker build stage)
#
# Usage:  sh packaging/synology/package.sh
# Output: packaging/synology/ghostdrive.spk

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)

PYTHON="${PYTHON:-python3}"
STAGING="$SCRIPT_DIR/build/spk"
OUT="$SCRIPT_DIR/ghostdrive.spk"

command -v "$PYTHON" >/dev/null 2>&1 || {
    echo "error: $PYTHON not found; set PYTHON= to a python3 interpreter" >&2
    exit 1
}

echo "==> staging tree at $STAGING"
rm -rf "$STAGING"
mkdir -p "$STAGING/package" "$STAGING/scripts" "$STAGING/conf"

# ── INFO ─────────────────────────────────────────────────────────────────────
cp "$SCRIPT_DIR/INFO" "$STAGING/INFO"

# ── package.tgz: the app in a venv, extracted to /var/packages/ghostdrive/target ──
echo "==> creating venv and installing ghostdrive (needs network + sqlcipher build deps)"
"$PYTHON" -m venv "$STAGING/package/venv"
"$STAGING/package/venv/bin/pip" install --quiet --upgrade pip
"$STAGING/package/venv/bin/pip" install --quiet "$REPO_ROOT"

echo "==> creating package.tgz"
tar -czf "$STAGING/package.tgz" -C "$STAGING/package" .
rm -rf "$STAGING/package"

# ── scripts/start-stop-status (written inline; see SPK_BUILD.md) ────────────
cat > "$STAGING/scripts/start-stop-status" <<'EOF'
#!/bin/sh
# GhostDrive DSM7 start/stop/status handler.
# Launches the web vault loopback-only (see packaging/synology/SPK_BUILD.md
# for why, and for the honest status of this whole route).
PACKAGE="ghostdrive"
TARGET="/var/packages/${PACKAGE}/target"
VAR="/var/packages/${PACKAGE}/var"
VENV="${TARGET}/venv"
PIDFILE="${VAR}/ghostdrive.pid"
LOGFILE="${VAR}/ghostdrive.log"
# Persist across upgrades; overridable from the environment DSM gives us.
DATA_DIR="${GHOSTDRIVE_DATA_DIR:-${VAR}/data}"

is_running() {
    [ -f "${PIDFILE}" ] || return 1
    pid=$(cat "${PIDFILE}" 2>/dev/null) || return 1
    [ -n "${pid}" ] || return 1
    kill -0 "${pid}" 2>/dev/null
}

case "$1" in
    start)
        is_running && exit 0
        mkdir -p "${VAR}" "${DATA_DIR}"
        # --host 127.0.0.1 is the app's own default; spelled out because this
        # is the one place a future edit could silently widen the bind.
        # --no-browser: no desktop session here.
        GHOSTDRIVE_DATA_DIR="${DATA_DIR}" nohup "${VENV}/bin/ghostdrive-cli" \
            serve --host 127.0.0.1 --port 8000 --no-browser \
            >> "${LOGFILE}" 2>&1 &
        echo $! > "${PIDFILE}"
        ;;
    stop)
        if is_running; then
            pid=$(cat "${PIDFILE}")
            kill "${pid}" 2>/dev/null
            i=0
            while [ "$i" -lt 30 ] && kill -0 "${pid}" 2>/dev/null; do
                sleep 1
                i=$((i + 1))
            done
            kill -9 "${pid}" 2>/dev/null
        fi
        rm -f "${PIDFILE}"
        ;;
    status)
        if is_running; then
            echo "running"
            exit 0
        fi
        echo "stopped"
        exit 3
        ;;
    *)
        echo "Usage: $0 {start|stop|status}" >&2
        exit 1
        ;;
esac
EOF
chmod 755 "$STAGING/scripts/start-stop-status"

# ── conf/privilege: minimal DSM7 privilege file (scaffolding-grade) ─────────
cat > "$STAGING/conf/privilege" <<'EOF'
{
    "defaults": {
        "actions": {
            "start": "yes",
            "stop": "yes",
            "status": "yes"
        },
        "username": "root",
        "group": "root"
    }
}
EOF

# ── pack the spk (a spk is just a tar.gz of INFO + package.tgz + scripts + conf)
echo "==> writing $OUT"
rm -f "$OUT"
tar -czf "$OUT" -C "$STAGING" INFO package.tgz scripts conf

echo "==> done: $OUT"
echo "    UNSIGNED. DSM will not install this via the normal UI - read SPK_BUILD.md."
