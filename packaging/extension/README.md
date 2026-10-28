# GhostDrive Browser Extension ("Encrypt to GhostDrive")

A thin Manifest V3 extension for Chromium that encrypts right-clicked text
straight into your local GhostDrive vault. No dependencies, no build step, no
remote code — four small files and three PNG icons.

## Install (Chromium: Chrome, Edge, Brave, ...)

1. Start the GhostDrive desktop/web app (it binds `127.0.0.1`).
2. Get the extension:
   - open `http://127.0.0.1:PORT/api/extension/download` in the browser —
     it returns `ghostdrive-extension.zip` — **or**
   - unzip the copy already sitting in `packaging/extension/` of the repo.
3. Open `chrome://extensions`, enable **Developer mode**, click
   **Load unpacked**, and select the `extension/` folder (the one containing
   `manifest.json`).
4. Right-click any selection → **Encrypt selection to GhostDrive**, or
   right-click a page/link → **Encrypt link to page**.

Firefox caveats: this is MV3 with a `background.service_worker`, which
Firefox does not support the same way (it wants an MV3 "event page"
background script, and unsigned extensions require developer-mode or
signing). Nothing here has been tested on Firefox; treat Chromium as the
supported target.

## What it talks to (the exact API calls)

All requests go to the configured app URL, which must be loopback
(`http://127.0.0.1:PORT` or `http://localhost:PORT` — the extension refuses
anything else, and the manifest's `host_permissions` only grant loopback
hosts anyway).

- `GET {baseUrl}/api/extension/status` — connection check from the popup and
  options page. Answers while the vault is **locked** (`installed_hint`,
  `app_url`, `docs`); "connected" never implies "unlocked".
- `POST {baseUrl}/api/extension/upload?path=<vault path incl. filename>&mime_type=text/plain`
  — the one write path. The body is the **raw text bytes** (not multipart).
  The last component of `path` becomes the filename, everything before it the
  directory. Success returns the usual GhostDrive file dict; an empty body is
  `400`; a locked vault is `401` with a JSON `detail` the extension surfaces
  in its notification.
- The extension does **not** call `POST /api/files/upload` (that route wants
  a multipart file field plus form fields; the raw-body route above is the
  deliberate browser-friendly equivalent, implemented server-side in
  `ghostdrive/web/routes/extension.py`).
- `GET {baseUrl}/api/extension/download` is used by humans (and the web UI's
  "get the extension" button), not by the extension itself.

Uploads land as `text/plain` tier `IMPORTANT` files under the configured
vault folder (default `browser/`), e.g. `browser/selection-2026-10-28T…-Z.txt`.

## Settings

Popup and options page store two values in `chrome.storage.sync`:

- **App URL** (default `http://127.0.0.1:8000`) — loopback only.
- **Vault folder** (default `browser/`) — destination directory inside the
  vault.

## Clipboard button

"Send clipboard to vault" uses `navigator.clipboard.readText()`. Chromium
gates clipboard reads from extension pages behind a permission gesture/prompt;
if the read is refused, the popup shows a hint and provides a manual paste
box, which takes the exact same upload path. The extension requests no
`clipboardRead` permission — a silent clipboard sniffer is not what
"right-click → encrypt" should mean.

## Why there is no "Upload file" context menu item

Context menus cannot read local files. A browser extension would need the
`downloads` API (read-back through the download shelf) or drag-and-drop into
a page — both worse than the app's own upload UI. Honest limitation, not an
oversight.

## CORS: how this works without server-side CORS

`ghostdrive/web/server.py` configures **no** `CORSMiddleware`. A
`chrome-extension://` origin fetching `http://127.0.0.1:PORT` is
cross-origin, but Chromium exempts requests covered by the manifest's
`host_permissions` (`http://127.0.0.1/*`, `http://localhost/*`) from CORS —
the browser attaches no preflight and demands no
`Access-Control-Allow-Origin` back. So the extension works against the
unmodified server. The server additionally answers
`OPTIONS /api/extension/upload` with a 204 + permissive CORS headers as
belt-and-braces, but that is not on the critical path. Do not remove the
`host_permissions`; without them every call would fail CORS.

## Trust model and security notes (read this)

- **No auth beyond loopback.** There is no token, no cookie, no CSRF
  challenge: the web API trusts anyone who can reach `127.0.0.1:PORT`, and
  that is the same model the web UI itself uses (see
  `docs/REMOTE_ACCESS.md`). Anyone who can connect to your loopback port is
  already you — or has already won on your machine.
- **The extension can only reach loopback.** `host_permissions` pin it to
  `http://127.0.0.1/*` and `http://localhost/*`; `background.js` re-checks
  the configured URL before every upload. It cannot exfiltrate to a remote
  host even if settings are hand-corrupted.
- **Text travels in request bodies to your own machine.** Selections/links
  are encrypted at rest by the vault pipeline like any other upload.
- **`storage.sync` holds only a URL and a folder name.** No keys, no
  passphrase. If your browser profile syncs extension storage to a vendor
  cloud, that is a URL and `browser/` leaving the machine — nothing else.
- **Notifications show upload results** (including the vault path) via the
  standard Chrome notification permission.

## Limitations

- MV3 service workers are ephemeral: state lives in `chrome.storage.sync`,
  not in globals.
- `info.selectionText` is whitespace-collapsed by Chromium; multi-paragraph
  selections may arrive flattened.
- Firefox is unsupported (see caveats above).
- The server-side `/api/extension/*` routes must be mounted by the app
  (`ghostdrive/web/routes/extension.py`); `GET /api/extension/status` is the
  cheap way to check they are.
