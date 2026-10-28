# GhostDrive — self-hosted / NAS image.
# Syntax-validated only; there is no Docker daemon in this repo's CI, so the
# build itself is untested here. See packaging/docker/README.md for the honest
# status and the loopback-binding story.

# ── Stage 1: build the app wheel plus every dependency wheel ─────────────────
# sqlcipher3 publishes no prebuilt manylinux wheels — it compiles a SQLite
# amalgamation against the system libsqlcipher — so the build stage carries a
# compiler toolchain. Everything else (cryptography, zstandard, blake3, ...)
# installs from manylinux wheels and merely needs the compiler for stragglers.
FROM python:3.12-slim-bookworm AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential libsqlcipher-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
# pyproject's `readme = "README.md"` means the wheel build needs it too.
COPY pyproject.toml README.md ./
COPY ghostdrive ./ghostdrive

# Build the app wheel AND all dependency wheels into one wheelhouse, so the
# runtime stage below installs fully offline. `pip` here understands the
# poetry-core build backend declared in pyproject.toml.
RUN pip wheel --no-cache-dir --wheel-dir /wheels .

# ── Stage 2: slim runtime, non-root ──────────────────────────────────────────
FROM python:3.12-slim-bookworm

# libsqlcipher0 is the runtime shared library the sqlcipher3 extension links
# against; ca-certificates for the HTTPS backends (httpx).
RUN apt-get update \
    && apt-get install -y --no-install-recommends libsqlcipher0 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 1000 --create-home ghostdrive

# Install from the wheelhouse only — no network, no compilers at image-build
# time for the final layer.
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels ghostdrive \
    && rm -rf /wheels

# GHOSTDRIVE_DATA_DIR is the real, supported override (ghostdrive/utils/
# platform.py: get_app_data_dir()); without it the app would use
# $APPDATA/.ghostdrive or ~/.ghostdrive. /data is the single persistent
# directory: keystore.json, ghostdrive.db, and backups of settings.
ENV GHOSTDRIVE_DATA_DIR=/data

# WORKDIR must be /data too: server.py writes ghostdrive.log relative to the
# CWD, and we want the log on the volume instead of the container layer.
WORKDIR /data
RUN mkdir -p /data && chown ghostdrive:ghostdrive /data
VOLUME /data

# 8000 is the app's default port (find_available_port(8000) in
# ghostdrive/web/server.py). EXPOSE is documentation only — the compose file
# performs the actual publish.
EXPOSE 8000

USER ghostdrive

# The plain `ghostdrive` entrypoint hardcodes a 127.0.0.1 bind in
# ghostdrive/web/server.py:main(). `ghostdrive-cli serve` is the ONE place
# with a --host override (ghostdrive/cli/ghostdrive_cli.py). 0.0.0.0 here is
# the *container's own* network namespace, not the host's; the compose file
# publishes it on the host's loopback (127.0.0.1:8000:8000) by default, which
# is the same exposure posture as running GhostDrive on a desktop. --no-browser
# suppresses the webbrowser.open() timer, which is meaningless in a container.
ENTRYPOINT ["ghostdrive-cli", "serve", "--host", "0.0.0.0", "--port", "8000", "--no-browser"]

# GET /api/auth/status answers while the vault is locked and only stats a
# file (ghostdrive/web/routes/auth.py) — a cheap liveness probe. Slim images
# have no curl, so the probe is stdlib urllib. If you change the path, update
# tests/test_nas_packaging.py, which pins it to the real route.
HEALTHCHECK --interval=30s --timeout=6s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/auth/status', timeout=5)"
