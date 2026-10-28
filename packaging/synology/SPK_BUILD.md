# GhostDrive Synology `.spk` — build notes and honest status

**Read this first:** on Synology, the **Docker route (Container Manager) is
the recommended path** — build from `packaging/docker/Dockerfile`, same
compose file, same loopback story. Everything below is scaffolding for people
who specifically want a native DSM package, and it is the *less* tested of the
two.

## Status, honestly

| Thing | State |
| --- | --- |
| `INFO` metadata | Written to DSM7 format; fields reviewed against the standard layout. Untested on a real DSM. |
| `package.sh` | `sh -n` clean (syntax-validated); the spk tree it assembles (INFO, `package.tgz`, `scripts/start-stop-status`, `conf/privilege`) matches the classic minimal DSM package layout. **Never run on a real DSM.** |
| `start-stop-status` | Handles start/stop/status with a `nohup` launch and a pidfile under `/var/packages/ghostdrive/var/`. Never executed by DSM. |
| `conf/privilege` | Minimal scaffolding. A real package usually narrows this further (DSM7 package users, `dsmuidir`, explicit exec allow-lists); expect to iterate. |
| Signing | **Not done. See below.** |
| Install on DSM | **Untested. Requires a real Synology.** |

## The signing problem (why "just install it" does not work)

DSM 7 will not install an unsigned `.spk` through the normal Package Center
flow. Synology signs packages through their developer/publisher program
(Developer Center account, per-package signing with their tooling) — that is
an account-and-portal process on Synology's side, entirely manual, and not
something a build script can do. Consequences:

- The `ghostdrive.spk` produced by `package.sh` is **unsigned**.
- Getting it onto a box requires whatever unsigned-package acceptance your
  DSM version permits (SSH `synopkg install`, dev-mode tricks) — all
  unsupported, all liable to differ per DSM update. We do not document a
  specific bypass here because they churn and none of them are blessed.
- If native packages ever become a supported deliverable, the signing step
  will be a manual, maintainer-side step with a Synology Developer Center
  account — never in CI.

This is the main reason the Docker route is recommended even on Synology:
Container Manager installs without any of this.

## Building the (unsigned) spk

Build host requirements — **not** the NAS:

- `python3` (override with `PYTHON=...`)
- network access (pip resolves from `pyproject.toml` ranges — `poetry.lock`
  is not consulted, so versions can drift from a poetry-managed install)
- C toolchain + libsqlcipher headers: `sqlcipher3` compiles from source,
  same as in the Docker build stage

```sh
sh packaging/synology/package.sh
# -> packaging/synology/ghostdrive.spk
```

What it produces, concretely:

```
ghostdrive.spk                      # tar.gz of the four entries below
├── INFO                            # copied from packaging/synology/INFO
├── package.tgz                     # extracts to /var/packages/ghostdrive/target/
│   └── venv/                       #   venv with ghostdrive + all deps
├── scripts/
│   └── start-stop-status           # start/stop/status, pidfile under .../var/
└── conf/
    └── privilege                   # minimal DSM7 privilege file
```

At install time DSM extracts `package.tgz` into
`/var/packages/ghostdrive/target/`; the start script launches
`venv/bin/ghostdrive-cli serve --host 127.0.0.1 --port 8000 --no-browser`
with `GHOSTDRIVE_DATA_DIR` pointing at `/var/packages/ghostdrive/var/data`
(package state dir, survives upgrades).

## The loopback caveat, native-package edition

The native package binds **`127.0.0.1` on the NAS itself** — deliberately, per
the app's threat model (`ghostdrive/web/server.py` hardcodes the loopback
bind; the CLI `serve --host` flag is the only override and we point it back at
loopback here). So the web UI is reachable only from the NAS, an SSH tunnel,
or a tunneling tool like Tailscale running on the NAS. There is no TLS and no
auth beyond the vault lock screen — the same caveats as
`docs/REMOTE_ACCESS.md`, minus the "it never leaves this machine" part that a
desktop install gets.

If you want a LAN-reachable, reverse-proxied setup: that is the Docker route
with a proxy in front, not this.

## Versioning

`INFO`'s `version="0.1.0"` mirrors the leading numeric part of
`ghostdrive.__version__` (currently `0.1.0-alpha`); DSM's version field does
not take the PEP 440 pre-release suffix. `tests/test_nas_packaging.py` pins
the two together, so bumping the package version means updating
`packaging/synology/INFO` too.
