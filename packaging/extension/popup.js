/*
 * popup.js -- GhostDrive popup: connection check, settings, clipboard upload.
 *
 * The clipboard button asks background.js to do the actual upload (one shared
 * upload path). navigator.clipboard.readText() in an extension popup is gated
 * by a Chrome permission gesture; when that read is refused the manual paste
 * box is the fallback.
 */

"use strict";

const DEFAULT_CONFIG = {
  baseUrl: "http://127.0.0.1:8000",
  vaultPath: "browser/",
};

const $ = (id) => document.getElementById(id);

function isLoopbackUrl(url) {
  try {
    const parsed = new URL(url);
    return (
      parsed.protocol === "http:" &&
      (parsed.hostname === "127.0.0.1" || parsed.hostname === "localhost")
    );
  } catch (_err) {
    return false;
  }
}

function normalizeBaseUrl(raw) {
  return String(raw || "").trim().replace(/\/+$/, "");
}

function normalizeVaultPath(raw) {
  let dir = String(raw || "").trim().replace(/\\/g, "/").replace(/^\/+/, "");
  if (dir && !dir.endsWith("/")) dir += "/";
  return dir || DEFAULT_CONFIG.vaultPath;
}

function setStatus(text, kind) {
  const status = $("status");
  status.textContent = text;
  status.className = kind || "";
}

function setConn(text, kind) {
  $("conn-text").textContent = text;
  $("conn-dot").className = `dot ${kind || ""}`.trim();
}

async function checkConnection() {
  const baseUrl = normalizeBaseUrl($("base-url").value) || DEFAULT_CONFIG.baseUrl;
  if (!isLoopbackUrl(baseUrl)) {
    setConn("Refusing non-loopback URL", "err");
    return;
  }
  setConn("Checking…", "");
  try {
    const response = await fetch(`${baseUrl}/api/extension/status`, {
      method: "GET",
    });
    if (!response.ok) {
      setConn(`App answered HTTP ${response.status}`, "err");
      return;
    }
    const payload = await response.json();
    setConn(`Connected — app at ${payload.app_url}`, "ok");
  } catch (_err) {
    setConn(`Not reachable at ${baseUrl} — is GhostDrive running?`, "err");
  }
}

async function loadSettings() {
  const config = await chrome.storage.sync.get(DEFAULT_CONFIG);
  $("base-url").value = config.baseUrl;
  $("vault-path").value = config.vaultPath;
}

async function saveSettings() {
  const baseUrl = normalizeBaseUrl($("base-url").value);
  if (!isLoopbackUrl(baseUrl)) {
    setStatus("Only http://127.0.0.1 or http://localhost is allowed.", "err");
    return;
  }
  const vaultPath = normalizeVaultPath($("vault-path").value);
  await chrome.storage.sync.set({ baseUrl, vaultPath });
  $("base-url").value = baseUrl;
  $("vault-path").value = vaultPath;
  setStatus("Saved.", "ok");
  checkConnection();
}

async function sendText(text, prefix) {
  if (!text) {
    setStatus("Nothing to send (empty text).", "warn");
    return;
  }
  setStatus("Uploading…", "");
  const result = await chrome.runtime.sendMessage({
    type: "ghostdrive-upload-text",
    text,
    prefix,
  });
  if (result && result.ok) {
    setStatus(`Encrypted to ${result.path}`, "ok");
  } else {
    setStatus((result && result.error) || "Upload failed.", "err");
  }
}

async function sendClipboard() {
  try {
    const text = await navigator.clipboard.readText();
    await sendText(text, "clipboard");
  } catch (_err) {
    setStatus(
      "Clipboard read blocked — paste into the box below (Chrome gates clipboard reads in extensions).",
      "warn"
    );
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  await loadSettings();
  checkConnection();
  $("save").addEventListener("click", saveSettings);
  $("clipboard").addEventListener("click", sendClipboard);
  $("send-manual").addEventListener("click", () =>
    sendText($("manual").value, "paste")
  );
  $("base-url").addEventListener("change", checkConnection);
});
