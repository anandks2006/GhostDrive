/*
 * background.js -- GhostDrive MV3 service worker.
 *
 * Thin client over the GhostDrive localhost API. No dependencies, no build
 * step, no remote code: the only hosts it may ever talk to are 127.0.0.1 and
 * localhost (enforced by manifest host_permissions and by the URL guard
 * below). The single write path is:
 *
 *   POST {baseUrl}/api/extension/upload?path=<vault path incl. filename>&mime_type=...
 *   body: the raw text bytes
 *
 * A locked vault answers 401 with a JSON "detail"; anything else surfaces the
 * status code + message in a notification.
 */

"use strict";

const DEFAULT_CONFIG = {
  baseUrl: "http://127.0.0.1:8000",
  vaultPath: "browser/",
};

const MENU_SELECTION = "ghostdrive-encrypt-selection";
const MENU_PAGE = "ghostdrive-encrypt-page";

// ── Config ──────────────────────────────────────────────────────────────────

function getConfig() {
  return chrome.storage.sync.get(DEFAULT_CONFIG);
}

function joinVaultPath(vaultPath, filename) {
  const dir = String(vaultPath || "").trim().replace(/^\/+|\/+$/g, "");
  return dir ? `${dir}/${filename}` : filename;
}

function timestampName(prefix) {
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  return `${prefix}-${stamp}.txt`;
}

// Last line of defense: never fetch anything that is not loopback, even if
// storage was corrupted by hand. The manifest would block it anyway.
function isLoopbackUrl(url) {
  try {
    const parsed = new URL(url);
    const host = parsed.hostname;
    return (
      parsed.protocol === "http:" &&
      (host === "127.0.0.1" || host === "localhost")
    );
  } catch (_err) {
    return false;
  }
}

// ── Upload ──────────────────────────────────────────────────────────────────

/**
 * Send one text payload to the vault.
 * Resolves {ok: true, path, name} or {ok: false, error, locked?}.
 */
async function uploadTextToVault(text, prefix) {
  const config = await getConfig();
  const baseUrl = String(config.baseUrl || DEFAULT_CONFIG.baseUrl).replace(/\/+$/, "");
  if (!isLoopbackUrl(baseUrl)) {
    return { ok: false, error: `Refusing non-loopback base URL: ${baseUrl}` };
  }

  const name = timestampName(prefix);
  const vaultPath = joinVaultPath(config.vaultPath, name);
  const url =
    `${baseUrl}/api/extension/upload` +
    `?path=${encodeURIComponent(vaultPath)}` +
    `&mime_type=${encodeURIComponent("text/plain")}`;

  let response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: text,
    });
  } catch (_err) {
    return {
      ok: false,
      error: `GhostDrive is not reachable at ${baseUrl} -- is the app running?`,
    };
  }

  if (response.ok) {
    return { ok: true, path: vaultPath, name };
  }

  let detail = "";
  try {
    const payload = await response.json();
    detail = payload && payload.detail ? String(payload.detail) : "";
  } catch (_err) {
    /* non-JSON error body */
  }
  if (response.status === 401) {
    return {
      ok: false,
      locked: true,
      error: "GhostDrive vault is locked -- unlock in the desktop app",
    };
  }
  return { ok: false, error: `${response.status}${detail ? ` ${detail}` : ""}` };
}

function notify(title, message) {
  chrome.notifications.create({
    type: "basic",
    iconUrl: "icons/icon128.png",
    title,
    message,
  });
}

function notifyResult(result, what) {
  if (result.ok) {
    notify("GhostDrive", `Encrypted ${what} to ${result.path}`);
  } else {
    notify("GhostDrive upload failed", result.error);
  }
}

// ── Context menus ───────────────────────────────────────────────────────────

chrome.runtime.onInstalled.addListener(() => {
  // create() throws if a menu with the same id already exists, so clear first.
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: MENU_SELECTION,
      title: "Encrypt selection to GhostDrive",
      contexts: ["selection"],
    });
    // "page" covers empty-space right-click; "link" covers link context. A
    // file-upload menu item is deliberately absent: context menus cannot read
    // local files (see README).
    chrome.contextMenus.create({
      id: MENU_PAGE,
      title: "Encrypt link to page",
      contexts: ["page", "link"],
    });
  });
});

chrome.contextMenus.onClicked.addListener((info) => {
  if (info.menuItemId === MENU_SELECTION) {
    const text = info.selectionText || "";
    uploadTextToVault(text, "selection").then((result) =>
      notifyResult(result, "selection")
    );
  } else if (info.menuItemId === MENU_PAGE) {
    const text = info.linkUrl || info.pageUrl || "";
    uploadTextToVault(text, "link").then((result) => notifyResult(result, "link"));
  }
});

// ── Popup bridge (popup.js reuses this one upload path) ─────────────────────

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message && message.type === "ghostdrive-upload-text") {
    uploadTextToVault(String(message.text || ""), String(message.prefix || "paste"))
      .then(sendResponse)
      .catch((err) => sendResponse({ ok: false, error: String(err) }));
    return true; // keep the message channel open for the async response
  }
  if (message && message.type === "ghostdrive-status") {
    getConfig().then((config) =>
      sendResponse({
        ok: true,
        baseUrl: config.baseUrl,
        vaultPath: config.vaultPath,
      })
    );
    return true;
  }
  return false;
});
