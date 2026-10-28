# Browser Extension

GhostDrive ships a Chromium (Manifest V3) browser extension that encrypts
right-clicked text — a selection, a link, or the current page URL — straight
into the local vault. It is a deliberately thin client: vanilla JS, no build
step, no dependencies, and it can only ever talk to this machine's loopback
interface. Install steps, settings, and the full API contract live next to
the code in [packaging/extension/README.md](../packaging/extension/README.md).

Server endpoints referenced here (implemented in
`ghostdrive/web/routes/extension.py`):

- `GET /api/extension/status` — lock-tolerant probe (`installed_hint`,
  `app_url`, `docs`). Answerable while the vault is locked; safe for a popup
  "is the app running?" check.
- `GET /api/extension/download` — `packaging/extension/` zipped in memory and
  served as `ghostdrive-extension.zip`. This is the "get the extension"
  button for the web UI; it always reflects the files on disk.
- `POST /api/extension/upload?path=<vault path incl. filename>&mime_type=…`
  — raw request bytes stored as one encrypted file. The last component of
  `path` is the filename, the prefix the directory. Empty body → 400; locked
  vault → 401 with a JSON `detail`.
- `OPTIONS /api/extension/upload` — 204 with permissive CORS headers,
  belt-and-braces only (see §3).

---

## 1. Why a dedicated `/api/extension/upload` route

`POST /api/files/upload` expects a multipart file field plus form fields.
That contract is fine for the web UI, but a service worker posting text from
a context menu gains nothing from multipart: one POST with the raw bytes and
a query parameter is simpler and easier to audit. The extension route calls
the same `files_service.upload_stream(...)` pipeline, so encrypted-at-rest
behavior, tiers, backends, and the locked-vault check are identical to every
other upload.

## 2. Trust model: loopback, same as the web UI

The app binds `127.0.0.1` (see [REMOTE_ACCESS.md](REMOTE_ACCESS.md) §1). The
extension's `host_permissions` pin it to `http://127.0.0.1/*` and
`http://localhost/*`, and `background.js` refuses any other base URL before
uploading. There is no token, cookie, or CSRF challenge — the API trusts
whoever can reach the loopback port, which is the same model the web UI
already operates under. Anyone who can open your loopback port is already
local-user territory; a browser extension adds no new surface beyond what
`curl` on the same machine could do.

## 3. CORS, honestly

`server.py` configures no `CORSMiddleware`. Chromium exempts extension
requests covered by `host_permissions` from CORS, so the extension works
against the unmodified server — no preflight, no `Access-Control-Allow-`
`Origin` negotiation on the critical path. The `OPTIONS /api/extension/upload`
204 exists only so a stray preflight gets a truthful answer instead of 405.
If a future browser tightened the exemption, the fix would be either
declarativeNetRequest response-header rewriting in the extension or an
explicit CORS flag in the server — neither is needed today, and neither was
added speculatively.

## 4. Known limitations

- Chromium only. MV3 `background.service_worker` is not the Firefox model;
  no Firefox signing has been done.
- Context menus cannot read local files, so there is no "upload file" menu
  item — that path stays in the app's own UI.
- `info.selectionText` is whitespace-collapsed by Chromium.
- Clipboard reads from the popup are gated by a Chrome permission gesture;
  the popup falls back to a manual paste box and requests no `clipboardRead`
  permission.
- "Connected" (status endpoint answers) never implies "unlocked" — only the
  upload attempt tells you that, with a 401 the extension renders as
  "vault is locked — unlock in the desktop app".

## 5. Server-side wiring

The router (`ghostdrive/web/routes/extension.py`, prefix `/api/extension`)
must be included in the app alongside the other routers. Nothing in the
router touches the database unless an upload runs; `/status` and `/download`
work with a locked vault, which is what makes the popup's connection check
useful before unlock.
