# Running the GhostDrive test suite

GhostDrive is developed and tested primarily on **Windows**, but the suite is
platform-neutral wherever it can be: the CI workflow
(`.github/workflows/ci.yml`) runs the full suite on both `windows-latest` and
`ubuntu-latest`.

## 1. Install dependencies

Requires **Python 3.11+ (3.12 recommended)** — `pyproject.toml` declares
`python = "^3.11"`.

### Option A — Poetry (recommended, matches the repo)

The project uses Poetry (`poetry-core` is its build backend) and ships a
`poetry.lock`. All dependency groups in `pyproject.toml`
(`backends`, `web`, `phase2`, `tray`, `dev`) are **non-optional**, so a plain
install brings in everything the suite needs — including `paramiko` +
`smbprotocol` + `zeroconf` (NAS tests), `Telethon`/`discord.py` (cloud backend
tests), `zfec` (erasure coding), `fastapi` (web tests) and
`pytest`/`pytest-asyncio`/`hypothesis`:

```powershell
pip install poetry
poetry install            # README also shows: poetry install --with backends,web
```

### Option B — plain `py -m pip`

If you prefer to run against the ambient interpreter (this is what the
`py`-launcher commands in this doc and in CI-compatible flags assume):

```powershell
py -m pip install -e .                              # core deps from pyproject
py -m pip install paramiko smbprotocol zeroconf     # NAS backend deps (backends group)
py -m pip install Telethon discord-py aiohttp       # cloud backend deps
py -m pip install fastapi "uvicorn[standard]" websockets python-multipart
py -m pip install zfec pystray Pillow               # phase2 + tray groups
py -m pip install pytest pytest-asyncio hypothesis pytest-cov
```

> The NAS dependencies (`paramiko`, `smbprotocol`) live in the `backends`
> group, not in the core dependency set — installing only `pip install .`
> does **not** pull them in, and `tests/test_nas_backend.py` will fail to
> import without them.

### SQLCipher (required for the suite)

`tests/test_database.py` imports `sqlcipher3` directly, so the suite needs it
installed regardless of platform:

```powershell
py -m pip install sqlcipher3          # wheels exist for CPython 3.12 on Win/Linux/macOS
# Windows fallback (pre-built binary bundle): py -m pip install sqlcipher3-binary
```

See [`setup_sqlcipher_windows.md`](setup_sqlcipher_windows.md) for details,
including the honest fallback: without SQLCipher the app still runs with an
**unencrypted** index and only logs a warning.

## 2. Run the tests

Full suite (the flags used everywhere in this repo and in CI):

```powershell
py -m pytest -q --no-header -p no:cacheprovider
```

Under Poetry:

```powershell
poetry run python -m pytest -q --no-header -p no:cacheprovider
```

A subset (fast sanity check, used as the packaging/web gate):

```powershell
py -m pytest tests/test_packaging.py tests/test_web_app.py -q --no-header -p no:cacheprovider
```

Notes:

- **`py` is the Windows Python launcher.** On Linux/macOS substitute `python3`
  (or `python` in a virtualenv). Every command in this doc is otherwise
  identical.
- `pyproject.toml` sets `addopts = "-v --tb=short"` under
  `[tool.pytest.ini_options]`, so short tracebacks come for free; `-q` keeps
  passing runs compact.
- `-p no:cacheprovider` disables writing `.pytest_cache` (keeps concurrent
  agents/sessions from tripping over each other's cache).
- Expected runtime: **~1–2 minutes** for the full suite on a developer
  machine (currently ~722 tests).

## 3. Markers and collection

Configured in `pyproject.toml` → `[tool.pytest.ini_options]`:

| Setting | Value | Meaning |
|---|---|---|
| `asyncio_mode` | `"auto"` | async test functions need no decorator |
| `testpaths` | `["tests"]` | bare `pytest` runs the suite from repo root |
| `addopts` | `"-v --tb=short"` | default verbosity + short tracebacks |
| `markers` | `integration` | *"live network tests requiring real credentials (deselect with `-m 'not integration'`)"* |

Only files matching `test_*.py` are collected, so the credential-gated
`tests/smoke_telegram_backend.py` / `tests/smoke_discord_backend.py` (both
also `@pytest.mark.integration` + `skipif` without credentials) and the manual
`tests/integration_*.py` scripts are **never** run by a plain invocation.

## 4. How the tests stay hermetic (no network)

- Backend tests replace the network layer rather than using it:
  `tests/test_nas_backend.py` monkeypatches paramiko/smbprotocol references
  ("hermetic regardless of import order"), `tests/test_s3_backend.py` is
  explicitly *"Unit tests for S3Backend (hermetic, no network)"*, and
  `tests/test_sharing_engine.py` stubs `asyncio.open_connection` and even
  `socket.gethostbyname`.
- Web-route tests build a local FastAPI app instead of starting a server
  (e.g. `tests/test_alerts.py`, `tests/test_restore_drills.py` — both say
  *"hermetic"* in their docstrings); the tray tests use a stand-in tray server
  with **no sockets** (`tests/test_tray.py`).
- Crypto/keystore tests use `FAST_ARGON2_PARAMS` from `tests/conftest.py`
  (`time_cost=1`, 8 MB memory, `parallelism=1`) so nothing waits for the
  production-calibrated ~1 s Argon2id derivation.
- Real-credential flows are opt-in only via the `integration` marker.

## 5. Platform quirks

- **Windows-only code paths** (`msvcrt`/`LockFileEx` in
  `ghostdrive/pipeline/file_lock.py`, drive monitors, tray, installer
  packaging) are exercised only on Windows — `tests/test_file_lock.py`
  covers both the POSIX `fcntl` and Windows LockFileEx/sidecar (`.gdl`)
  implementations, so a green run on Linux alone does not prove the Windows
  behaviour, and vice versa. This is why CI runs both OSes
  (`.github/workflows/ci.yml`, `.github/workflows/nightly.yml`).
- **Headless Linux**: no display server is needed; tray tests never open a
  real icon/window.
- **Console encoding on Windows**: passphrases/secrets in tests are plain
  ASCII; no `PYTHONIOENCODING` tweaks needed.

## 6. Related docs

- [`THREAT_MODEL.md`](THREAT_MODEL.md) — maps security claims to the tests
  that prove them (§6 "Verification").
- `setup_sqlcipher_windows.md` — SQLCipher install/fallback.
- CI: `.github/workflows/ci.yml` (push/PR, lint + full suite on two OSes) and
  `.github/workflows/nightly.yml` (daily full suite).
