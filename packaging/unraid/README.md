# GhostDrive — Unraid container template

**Status, honestly:** this template is maintained and XML-valid, but has
**not been installed on a real Unraid box** — treat your first install as the
test. The image it points at builds from `packaging/docker/Dockerfile`; read
`packaging/docker/README.md` first, because the loopback-binding story applies
here unchanged.

## Install

### Via Community Applications (CA)

1. Publish the image somewhere CA can see it (e.g. build
   `packaging/docker/Dockerfile` and push to `ghcr.io/youruser/ghostdrive`),
   or build locally on the NAS with the Dockerfile in this repo.
2. In CA, use "Install Docker Image" / template import with
   `packaging/unraid/ghostdrive.xml` — CA reads the same
   `<Container>` schema this file uses. Replace `ghcr.io/youruser/ghostdrive`
   with wherever your image actually lives.

### Manual (no CA)

Unraid's web UI has no first-class template import outside CA, so the manual
route is to create the container from the template's values — either paste
them into **Docker → Add Container**, or run the equivalent `docker run`
(see `packaging/docker/README.md`) with:

- port `8000:8000`
- path `/mnt/user/appdata/ghostdrive` → `/data` (rw)
- env `GHOSTDRIVE_DATA_DIR=/data`
- restart policy `unless-stopped`

## Where data lives

`/mnt/user/appdata/ghostdrive` on the host, mounted as `/data` in the
container. Contents:

- `keystore.json` — the vault keystore. **If this is lost and you don't have
  the 24-word seed phrase written down somewhere physical, the vault is
  gone.** That is the design, not a bug.
- `ghostdrive.db` — encrypted metadata database.
- `ghostdrive.log` — the app log (WORKDIR is /data so it lands on the volume).

`GHOSTDRIVE_DATA_DIR=/data` is the app's real data-dir override mechanism
(`ghostdrive/utils/platform.py`); the image sets it as an `ENV` default and
the template keeps it visible.

## Backup advice

- **Back the appdata folder up, but never rely on it alone.** A backup that
  includes `keystore.json` but not the seed phrase is one stolen disk away
  from total loss; a backup without the keystore is unreadable without the
  seed. Keep the seed phrase offline (paper), the way you'd treat a hardware
  wallet.
- **The app's own hostility/waste/air-gap features** exist precisely so the
  vault's backups are unattractive to an attacker who grabs them. Point your
  array snapshots (or the app's backup flow, from a desktop instance) at the
  vault data; conceptual details live in the app docs, not here.
- The named-volume location under `/var/lib/docker` is not a backup; this
  template bind-mounts to appdata precisely so your existing Appdata
  snapshot/backup jobs can see it.

## Networking (the important limitation)

The image binds `0.0.0.0` inside its own container namespace — it has to,
because `ghostdrive/web/server.py` hardcodes `127.0.0.1` and the only override
in the codebase is the CLI's `serve --host` flag. The published port therefore
appears on the Unraid host's `eth0`/br0 address. GhostDrive has **no TLS and
no auth beyond the vault's own lock screen**. Keep it on your LAN, or front it
with the Unraid-approved reverse proxy of your day, or reach it over
Tailscale. Never port-forward 8000.

## Limitations

- x86_64 assumed; `sqlcipher3` compiles at image build, so ARM NAS boxes need
  their own image build.
- No multi-arch manifest, no published image from this repo yet — the
  `Repository` tag is a placeholder.
- The `WebUI` button opens `http://IP:8000` from your browser to the Unraid
  host; that works because the port is host-published, unlike the desktop
  app's loopback-only posture. See the networking section before celebrating.
- Health: the image has a container `HEALTHCHECK` against
  `GET /api/auth/status` (answers while locked). Unraid's "healthy" badge is
  therefore liveness only, not vault health.
