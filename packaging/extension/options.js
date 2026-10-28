/*
 * options.js -- GhostDrive options page: settings plus a Test connection
 * button. Test connection hits GET /api/extension/status, which the app
 * answers even while the vault is locked, so "connected" never implies
 * "unlocked".
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
}

async function testConnection() {
  const baseUrl = normalizeBaseUrl($("base-url").value);
  if (!isLoopbackUrl(baseUrl)) {
    setStatus("Only http://127.0.0.1 or http://localhost is allowed.", "err");
    return;
  }
  setStatus("Testing…", "");
  let payload;
  try {
    const response = await fetch(`${baseUrl}/api/extension/status`, {
      method: "GET",
    });
    if (!response.ok) {
      setStatus(`App answered HTTP ${response.status}.`, "err");
      return;
    }
    payload = await response.json();
  } catch (_err) {
    setStatus(`Not reachable at ${baseUrl} — is the GhostDrive app running?`, "err");
    return;
  }
  const lines = [
    `Connected to ${payload.app_url}.`,
    payload.installed_hint
      ? "Extension pack available on the server."
      : "Extension pack not found on the server (download button will 404).",
    "Vault lock state is not checked here — a locked vault rejects uploads with 401.",
  ];
  setStatus(lines.join(" "), "ok");
}

document.addEventListener("DOMContentLoaded", async () => {
  await loadSettings();
  $("save").addEventListener("click", saveSettings);
  $("test").addEventListener("click", testConnection);
});
