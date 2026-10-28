# GhostDrive — Docker (self-hosted / NAS)

This is the container packaging for running GhostDrive's web vault on a
NAS or other self-hosted box, typically so the machine can act as (or manage)
a backup target.

**Status, honestly:** the Dockerfile and compose file are maintained and
syntax-reviewed, but this repo's CI has **no Docker daemon** — the image has
**not been built or run in CI**. Treat the first build on your machine as the
actual test. Known-risky spots are called out below.

## Build and run

From this directory:

```sh
docker compose build
docker compose up -d
```

Or without compose, from the repo root:

```sh
docker build -f packaging/docker/Dockerfile -t ghostdrive .
docker run -d --name ghostdrive --restart unless-stopped \
  -p 127.0.0.1:8000:8000 \
  -v ghostdrive-data:/data \
  -e GHOSTDRIVE_DATA_DIR=/data \
  ghostdrive
```

Then open `http://127.0.0.1:8000` **on the NAS itself** (see the next section
for why, and how to reach it from elsewhere).

## The loopback story (read this before opening a ticket)

`ghostdrive/web/server.py` hardcodes a `127.0.0.1` bind — that is the app's
threat model, and `docs/REMOTE_ACCESS.md` explains why it never binds
`0.0.0.0` on its own. There is exactly **one** host override in the codebase:
the `ghostdrive` CLI's `serve` subcommand
(`ghostdrive-cli serve --host ... --port ... --no-browser`,
`ghostdrive/cli/ghostdrive_cli.py`). The Dockerfile's `ENTRYPOINT` uses it to
bind `0.0.0.0` **inside the container's own network namespace** — not on the
host.

The compose file then publishes the port on the **host's loopback**:
`127.0.0.1:8000:8000`. That means after `docker compose up`, the UI is
reachable from the NAS itself at `http://127.0.0.1:8000` — exactly the same
exposure posture as running GhostDrive on a desktop. To reach it from another
machine you deliberately choose one of:

- edit `ports:` to your LAN IP (plain HTTP — anyone on the segment sees
  filenames and the unlock flow; see `docs/REMOTE_ACCESS.md` §6),
- put a reverse proxy with TLS in front (nginx/Caddy/Traefik — all fine,
  GhostDrive has no TLS of its own),
- or tunnel it (Tailscale/WireGuard on the NAS, then hit the container from
  the tailnet).

We ship the loopback default so that `docker compose up` can never be an
accidental LAN exposure.

## Volumes and what you must back up

Everything persistent lives in `/data` (mounted as the named volume
`ghostdrive-data`):

- `keystore.json` — the vault keystore. **Lose this and the passphrase alone
  cannot recover the vault;** your 24-word seed phrase is the recovery path.
  Write the seed on paper; do not store it in the volume you are backing up.
- `ghostdrive.db` — the encrypted metadata database.
- `ghostdrive.log` — the app writes its log relative to the CWD, and the image
  sets `WORKDIR /data` so the log lands on the volume (rotated by the compose
  `logging:` options at the Docker layer too).

`GHOSTDRIVE_DATA_DIR=/data` is the app's real, supported override
(`ghostdrive/utils/platform.py: get_app_data_dir()`); the image sets it as an
`ENV`, and the compose file sets it explicitly so you can see it.

A named volume under `/var/lib/docker/volumes/` is **not** a backup location.
Copy `/data` out (the app's own backup/waste/air-gap features, or your NAS's
snapshot tooling pointed at a bind mount like the commented `/backup` example
in the compose file).

## Using a NAS as the backup target vs. running GhostDrive on the NAS

Two different setups, often confused:

1. **App on a desktop, NAS as target (the common case).** No container needed.
   Add the NAS as a backend in the app — SFTP (paramiko) or SMB/CIFS
   (smbprotocol) are both in the dependency set — and the NAS is just an
   encrypted target like any other.
2. **App on the NAS (what this directory is for).** The containerized web
   vault runs on the NAS itself. The UI, as shipped, is reachable from the
   NAS's loopback; see the loopback story above for reaching it remotely. Use
   case: keeping the vault manager on the same always-on box as the storage.

## Upgrades

```sh
cd packaging/docker
docker compose build        # or: docker compose pull  (if you use a published image)
docker compose up -d
docker image prune          # optional: drop the old image layers
```

Vault state is in the named volume and survives upgrades. **No automated
migration testing has been done for schema changes across versions** — back up
`/data` before upgrading past an alpha.

## What is NOT included

- **No TLS.** The app serves plain HTTP. Put a reverse proxy in front if the
  UI leaves loopback. There is no certificate handling to configure here
  because there is none.
- **No auth beyond the app's own.** Anyone who can reach the web UI sees the
  lock screen; anyone who can reach it *and* knows the passphrase gets the
  vault. There is no token, no SSO, no reverse-proxy auth baked in — add it
  at the proxy if you expose the port.
- **No healthcheck-driven vault unlock, no auto-backup daemon.** The
  `HEALTHCHECK` only proves the HTTP process answers
  (`GET /api/auth/status` works while locked); it says nothing about vault
  health.
- **No x86/arm multi-arch image in CI.** `sqlcipher3` compiles from source at
  image build, so a multi-arch manifest needs per-arch builds (buildx) — not
  set up here. Build on the architecture you run.

## Known-fragile points

- `sqlcipher3` (declared in `pyproject.toml`) has no prebuilt manylinux
  wheels; the build stage compiles it against `libsqlcipher-dev`, and the
  runtime image needs `libsqlcipher0`. If a future base image drops either
  package, the build breaks — loudly, at `apt-get` time.
- The image installs from wheels built at image-build time; `poetry.lock` is
  **not** consulted (pip resolves from `pyproject.toml` ranges), so exact
  versions can drift from a poetry-installed desktop.
- The compose build context is the repo root, so the `.dockerignore` in this
  directory is only enforced if you copy it to the repo root or rename it
  `Dockerfile.dockerignore` next to the Dockerfile (BuildKit). See the note at
  the top of that file.
