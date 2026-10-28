(() => {
  "use strict";

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

  const state = {
    unlocked: false,
    view: "files",
    files: [],
    category: "all",
    search: "",
    selectedFile: null,
    versions: [],
    secretPayload: "",
    trash: [],
    shares: [],
    secrets: [],
    backends: [],
    settings: null,
    smart: null,
    seedPhrase: "",
    uploadFile: null,
    uploadRecommendedTier: "",
    uploading: false,
    shareFileId: null,
    confirmResolve: null,
    telemetrySocket: null,
    telemetryReconnect: null,
    telemetryEvents: [],
    lastTelemetryMessage: "",
    healthRunning: false,
    backendFieldsToken: 0,
    themePreference: "dark",
    searchTimer: null,
    scrubTimer: null,
    recoveryStatus: null,
    portableStatus: null,
    recoveryPreviewTimer: null,
    syncStatus: null,
    syncFiles: [],
    syncFileId: "",
    syncVersions: [],
    monitorAlerts: [],
    alertToasted: new Set(),
    alertTimer: null,
    envelopeFileId: null,
  };

  const VIEW_META = {
    files: ["Workspace", "Files"],
    shares: ["Delivery", "Shared links"],
    trash: ["Recovery", "Trash"],
    backends: ["Infrastructure", "Backends"],
    health: ["Reliability", "Health"],
    sync: ["Automation", "Sync & versions"],
    monitoring: ["Reliability", "Monitor"],
    analytics: ["Insights", "Analytics"],
    smart: ["Automation", "Smart engine"],
    vault: ["Security", "Vault"],
    recovery: ["Disaster recovery", "Recovery kit"],
    telemetry: ["Monitor", "Telemetry"],
    settings: ["Preferences", "Settings"],
    security: ["Protection", "Tripwires"],
    airgap: ["Protection", "Air-gap & waste"],
    cloud: ["Protection", "Cloud import"],
    remote: ["Protection", "Remote access"],
  };

  const TIER_COLORS = {
    CRITICAL: "var(--danger)",
    IMPORTANT: "var(--accent)",
    DISPOSABLE: "var(--info)",
  };

  const SHARE_CREATE_LABEL = `<svg class="icon"><use href="#i-link"/></svg> Create link`;
  const ENVELOPE_CREATE_LABEL = `<svg class="icon"><use href="#i-lock"/></svg> Create envelope link`;
  // Background alert polling follows the same chained window.setTimeout pattern
  // as scrubTimer/telemetryReconnect — one timer field, rescheduled per pass.
  const ALERT_POLL_MS = 60000;

  document.addEventListener("DOMContentLoaded", init);

  function init() {
    bindEvents();
    applyTheme("dark");
    setAuthView("unlock");
    runDiagnostics(false);
    checkAuth();
    setupPwa();
    window
      .matchMedia("(prefers-color-scheme: dark)")
      .addEventListener("change", () => {
        if (state.themePreference === "system") applyTheme("system");
      });
  }

  let installPromptEvent = null;

  function setupPwa() {
    // Service workers need a secure context — only register over https or localhost.
    const isSecure =
      window.location.protocol === "https:" ||
      ["localhost", "127.0.0.1", "[::1]"].includes(window.location.hostname);
    if (isSecure && "serviceWorker" in navigator) {
      navigator.serviceWorker.register("/serviceworker.js", { scope: "/" }).catch(() => {
        /* offline support is best-effort — never block the app on it */
      });
    }

    const button = $("#btn-install-app");
    const note = $("#install-note");
    if (!button || !note) return;

    const standalone =
      window.matchMedia("(display-mode: standalone)").matches || window.navigator.standalone === true;
    if (standalone) {
      // Already installed — hide the button and explain instead.
      note.textContent = "GhostDrive is installed and running in its own window.";
      note.classList.remove("hidden");
      return;
    }

    window.addEventListener("beforeinstallprompt", (event) => {
      // Chrome/Edge fire this once the app is deemed installable.
      event.preventDefault();
      installPromptEvent = event;
      button.classList.remove("hidden");
    });

    window.addEventListener("appinstalled", () => {
      installPromptEvent = null;
      button.classList.add("hidden");
      note.textContent = "GhostDrive was installed.";
      note.classList.remove("hidden");
    });

    button.addEventListener("click", async () => {
      if (!installPromptEvent) return;
      installPromptEvent.prompt();
      installPromptEvent = null;
      button.classList.add("hidden");
    });
  }

  function api(path, options = {}) {
    const opts = { ...options };
    opts.headers = { ...(options.headers || {}) };
    if (opts.body && !(opts.body instanceof FormData)) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(opts.body);
    }
    return fetch(path, opts).then(async (response) => {
      const contentType = response.headers.get("content-type") || "";
      let payload = null;
      if (contentType.includes("application/json")) {
        payload = await response.json().catch(() => null);
      } else {
        payload = await response.text().catch(() => "");
      }
      if (!response.ok) {
        let detail = payload && payload.detail ? payload.detail : payload;
        if (Array.isArray(detail)) {
          detail = detail.map((item) => item.msg || String(item)).join("; ");
        }
        throw new Error(detail || response.statusText || `Request failed (${response.status})`);
      }
      return payload;
    });
  }

  function esc(value) {
    return String(value ?? "").replace(/[&<>"']/g, (character) => {
      const map = {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      };
      return map[character];
    });
  }

  function icon(name, extra = "") {
    return `<svg class="icon ${extra}"><use href="#i-${name}"/></svg>`;
  }

  function formatBytes(value) {
    const bytes = Number(value) || 0;
    if (bytes <= 0) return "0 B";
    const units = ["B", "KB", "MB", "GB", "TB", "PB"];
    const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    const amount = bytes / 1024 ** index;
    return `${amount >= 100 || index === 0 ? amount.toFixed(0) : amount.toFixed(1)} ${units[index]}`;
  }

  function formatNumber(value) {
    return Number(value || 0).toLocaleString();
  }

  function parseDate(value) {
    if (!value) return null;
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? null : date;
  }

  function formatDate(value) {
    const date = parseDate(value);
    if (!date) return "—";
    return date.toLocaleDateString(undefined, {
      month: "short",
      day: "numeric",
      year: "numeric",
    });
  }

  function formatTime(value) {
    const date = parseDate(value) || new Date();
    return date.toLocaleTimeString(undefined, {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  }

  function formatSpeed(kilobytes) {
    const value = Number(kilobytes) || 0;
    if (value >= 1024) return `${(value / 1024).toFixed(2)} MB/s`;
    return `${value.toFixed(1)} KB/s`;
  }

  function formatPercent(value) {
    const number = Number(value) || 0;
    return `${number >= 100 ? number.toFixed(0) : number.toFixed(1)}%`;
  }

  function clamp(value, min, max) {
    return Math.min(max, Math.max(min, value));
  }

  function kindLabel(kind) {
    return String(kind || "secret")
      .replace(/_/g, " ")
      .replace(/\b\w/g, (letter) => letter.toUpperCase());
  }

  function fileGlyph(file) {
    const name = (file.filename || file.name || "").toLowerCase();
    const mime = (file.mime_type || "").toLowerCase();
    const extension = name.includes(".") ? name.split(".").pop() : "";
    if (mime.startsWith("image/") || ["jpg", "jpeg", "png", "gif", "webp", "bmp", "svg"].includes(extension)) {
      return ["image", "image"];
    }
    if (mime.startsWith("video/") || mime.startsWith("audio/") || ["mp4", "mkv", "mp3", "wav", "flac", "avi", "mov", "webm"].includes(extension)) {
      return ["video", "video"];
    }
    if (["pdf", "txt", "doc", "docx", "md", "csv", "json", "xml", "yaml", "yml"].includes(extension)) {
      return ["doc", "doc"];
    }
    if (["zip", "tar", "gz", "7z", "rar", "bz2", "xz"].includes(extension)) {
      return ["archive", "archive"];
    }
    return ["other", "file"];
  }

  function toast(message, type = "success") {
    const stack = $("#toast-stack");
    if (!stack) return;
    const item = document.createElement("div");
    item.className = `toast ${type}`;
    const iconName = type === "error" ? "alert" : type === "warn" ? "alert" : "check";
    item.innerHTML = `${icon(iconName)}<span>${esc(message)}</span>`;
    stack.appendChild(item);
    window.setTimeout(() => {
      item.style.opacity = "0";
      item.style.transform = "translateY(6px)";
      window.setTimeout(() => item.remove(), 180);
    }, 4800);
  }

  function showError(id, message) {
    const element = document.getElementById(id);
    if (!element) return;
    element.textContent = message;
    element.classList.remove("hidden");
  }

  function clearError(id) {
    const element = document.getElementById(id);
    if (!element) return;
    element.textContent = "";
    element.classList.add("hidden");
  }

  function setBusy(button, busy, label = "Working") {
    if (!button) return;
    if (busy) {
      if (!button.dataset.idle) button.dataset.idle = button.innerHTML;
      button.disabled = true;
      button.innerHTML = `<span class="spinner"></span>${esc(label)}`;
    } else {
      if (button.dataset.idle) {
        button.innerHTML = button.dataset.idle;
        delete button.dataset.idle;
      }
      button.disabled = false;
    }
  }

  function openModal(element) {
    const modal = typeof element === "string" ? document.getElementById(element) : element;
    if (!modal) return;
    $$(".modal.open").forEach((other) => {
      if (other !== modal) closeModal(other);
    });
    modal.classList.add("open");
    modal.setAttribute("aria-hidden", "false");
  }

  function closeModal(element) {
    const modal = typeof element === "string" ? document.getElementById(element) : element;
    if (!modal) return;
    modal.classList.remove("open");
    modal.setAttribute("aria-hidden", "true");
    if (modal.id === "confirm-modal" && state.confirmResolve) {
      const resolve = state.confirmResolve;
      state.confirmResolve = null;
      resolve(false);
    }
  }

  function confirmAction(title, message, actionLabel = "Continue") {
    $("#confirm-title").textContent = title;
    $("#confirm-message").textContent = message;
    $("#btn-confirm-action").textContent = actionLabel;
    openModal("confirm-modal");
    return new Promise((resolve) => {
      state.confirmResolve = resolve;
    });
  }

  function copyText(value) {
    const text = String(value ?? "");
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text).catch(() => fallbackCopy(text));
    }
    return fallbackCopy(text);
  }

  function fallbackCopy(text) {
    const area = document.createElement("textarea");
    area.value = text;
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    const copied = document.execCommand("copy");
    area.remove();
    return copied ? Promise.resolve() : Promise.reject(new Error("Clipboard access was denied."));
  }

  function openDrawer(title, eyebrow = "File details") {
    const drawer = $("#detail-drawer");
    drawer.querySelector(".eyebrow").textContent = eyebrow;
    $("#detail-title").textContent = title;
    drawer.classList.add("open");
    drawer.setAttribute("aria-hidden", "false");
  }

  function closeDrawer() {
    const drawer = $("#detail-drawer");
    drawer.classList.remove("open");
    drawer.setAttribute("aria-hidden", "true");
  }

  function bindEvents() {
    $$("[data-reveal]").forEach((button) => {
      button.addEventListener("click", () => {
        const input = document.getElementById(button.dataset.reveal);
        if (!input) return;
        input.type = input.type === "password" ? "text" : "password";
      });
    });

    $("#unlock-form-el").addEventListener("submit", handleUnlock);
    $("#setup-form-el").addEventListener("submit", handleSetup);
    $("#restore-form-el").addEventListener("submit", handleRestore);
    $("#link-restore").addEventListener("click", () => {
      setAuthView("restore");
      $("#restore-seed").focus();
    });
    $("#link-back-unlock").addEventListener("click", () => setAuthView("unlock"));

    // Factory reset: type-to-confirm gate, then POST; on success reload so the
    // first-run setup screen appears (the keystore no longer exists).
    const factoryResetInput = $("#factory-reset-confirm-input");
    const factoryResetExecute = $("#btn-factory-reset-execute");
    const factoryResetPhrase = "ERASE EVERYTHING";
    function openFactoryReset() {
      factoryResetInput.value = "";
      factoryResetExecute.disabled = true;
      $("#factory-reset-error").classList.add("hidden");
      openModal("factory-reset-modal");
      factoryResetInput.focus();
    }
    $("#link-factory-reset").addEventListener("click", openFactoryReset);
    factoryResetInput.addEventListener("input", () => {
      factoryResetExecute.disabled = factoryResetInput.value !== factoryResetPhrase;
    });
    factoryResetExecute.addEventListener("click", async () => {
      const errorBox = $("#factory-reset-error");
      errorBox.classList.add("hidden");
      try {
        setBusy(factoryResetExecute, true, "Erasing");
        const result = await api("/api/auth/factory-reset", {
          method: "POST",
          body: { confirm: factoryResetInput.value },
        });
        toast(result.message || "Vault erased.");
        closeModal("factory-reset-modal");
        window.setTimeout(() => window.location.reload(), 600);
      } catch (error) {
        errorBox.textContent = error.message;
        errorBox.classList.remove("hidden");
        setBusy(factoryResetExecute, false);
      }
    });

    $("#btn-copy-seed").addEventListener("click", () => {
      copyText(state.seedPhrase)
        .then(() => toast("Recovery phrase copied."))
        .catch((error) => toast(error.message, "error"));
    });
    $("#btn-confirm-seed").addEventListener("click", async () => {
      try {
        await api("/api/resilience/recovery/confirm", { method: "POST" });
      } catch (error) {
        toast(error.message, "error");
      }
      showWorkspace();
    });

    ["btn-system-details", "btn-open-diagnostics", "btn-open-diagnostics-2"].forEach((id) => {
      const button = document.getElementById(id);
      if (button) button.addEventListener("click", openDiagnostics);
    });
    $("#btn-rerun-diagnostics").addEventListener("click", () => runDiagnostics(true));

    $$(".nav-item").forEach((button) => {
      button.addEventListener("click", () => navigate(button.dataset.view));
    });

    $("#btn-lock-vault").addEventListener("click", handleLock);

    $("#global-search").addEventListener("input", handleSearch);
    document.addEventListener("keydown", (event) => {
      const target = event.target;
      const typing = target && ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName);
      if (event.key === "Escape") {
        const openModalElement = $(".modal.open");
        if (openModalElement) {
          closeModal(openModalElement);
        } else if ($("#detail-drawer").classList.contains("open")) {
          closeDrawer();
        }
      }
      if (event.key === "/" && !typing && state.unlocked) {
        event.preventDefault();
        $("#global-search").focus();
      }
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k" && state.unlocked) {
        event.preventDefault();
        $("#global-search").focus();
      }
    });

    $("#category-filters").addEventListener("click", (event) => {
      const button = event.target.closest("[data-category]");
      if (!button) return;
      $$("#category-filters button").forEach((item) => item.classList.toggle("active", item === button));
      state.category = button.dataset.category;
      loadFiles().catch((error) => toast(error.message, "error"));
    });

    ["btn-quick-upload", "btn-browse-files", "btn-empty-upload"].forEach((id) => {
      document.getElementById(id).addEventListener("click", openUploadModal);
    });
    $("#btn-refresh-files").addEventListener("click", () => loadFiles().catch((error) => toast(error.message, "error")));
    $("#btn-upload-browse").addEventListener("click", () => $("#upload-file").click());
    $("#upload-file").addEventListener("change", (event) => {
      const file = event.target.files && event.target.files[0];
      if (file) selectUploadFile(file);
    });
    $("#btn-upload-start").addEventListener("click", startUpload);
    $$('input[name="upload-tier"]').forEach((input) => input.addEventListener("change", renderUploadAdvisor));

    bindDropZone($("#drop-zone"), (file) => {
      openUploadModal();
      selectUploadFile(file);
    });
    bindDropZone($("#upload-drop"), (file) => selectUploadFile(file));

    $("#files-table-body").addEventListener("click", (event) => {
      const button = event.target.closest("[data-file-action], [data-action]");
      if (!button) return;
      const file = state.files.find((item) => item.id === button.dataset.id);
      if (!file) return;
      const action = button.dataset.fileAction || button.dataset.action;
      if (action === "details") openDetails(file);
      if (action === "download") downloadFile(file);
      if (action === "share") openShare(file);
      if (action === "envelope") openEnvelope(file.id);
      if (action === "delete") deleteFile(file);
    });

    $("#btn-close-drawer").addEventListener("click", closeDrawer);
    $("[data-close-drawer]").addEventListener("click", closeDrawer);
    $("#detail-content").addEventListener("click", handleDetailAction);

    $$("[data-close-modal]").forEach((element) => {
      element.addEventListener("click", () => closeModal(element.closest(".modal")));
    });
    $("#btn-confirm-action").addEventListener("click", () => {
      if (state.confirmResolve) {
        const resolve = state.confirmResolve;
        state.confirmResolve = null;
        resolve(true);
      }
      closeModal("confirm-modal");
    });

    $("#btn-add-backend").addEventListener("click", openBackendModal);
    $("#btn-empty-add-backend").addEventListener("click", openBackendModal);
    $("#btn-test-all-backends").addEventListener("click", testAllBackends);
    $("#backend-provider").addEventListener("change", renderBackendFields);
    $("#backend-form").addEventListener("submit", saveBackend);
    $("#backend-grid").addEventListener("click", handleBackendAction);
    $("#backend-grid").addEventListener("change", (event) => {
      const input = event.target.closest("[data-backend-toggle]");
      if (!input) return;
      toggleBackend(input.dataset.backendToggle, input.checked, input);
    });

    $("#btn-refresh-analytics").addEventListener("click", () => loadAnalytics().catch((error) => toast(error.message, "error")));
    $("#btn-run-scrub").addEventListener("click", runScrub);
    $("#btn-save-durability").addEventListener("click", saveDurabilityContract);
    $("#btn-confirm-recovery").addEventListener("click", confirmRecoverySaved);
    $("#durability-preset").addEventListener("change", applyDurabilityPreset);
    ["#durability-required", "#durability-offsite", "#durability-restore-proof"].forEach((selector) => {
      $(selector).addEventListener("change", () => { $("#durability-preset").value = ""; });
    });
    $("#btn-create-snapshot").addEventListener("click", createIndexSnapshot);
    $("#btn-run-drill").addEventListener("click", runRestoreDrill);
    $("#btn-evacuate").addEventListener("click", evacuateAtRisk);
    $("#btn-what-if").addEventListener("click", simulateDomainLoss);
    $("#btn-what-if-reset").addEventListener("click", () => {
      $$("#what-if-domains input[type='checkbox']").forEach((input) => { input.checked = false; });
      resetWhatIfResult();
    });
    $("#btn-add-protection").addEventListener("click", addProtectionSet);
    $("#btn-scan-protection").addEventListener("click", scanAllProtection);
    $("#protection-list").addEventListener("click", handleProtectionAction);
    $("#btn-save-smart").addEventListener("click", saveSmart);

    $("#btn-add-secret").addEventListener("click", openSecretModal);
    $("#btn-refresh-secrets").addEventListener("click", () => loadSecrets().catch((error) => toast(error.message, "error")));
    $("#secret-form").addEventListener("submit", saveSecret);
    $("#secrets-body").addEventListener("click", handleSecretAction);
    $("#btn-reveal-seed").addEventListener("click", openRevealModal);
    $("#reveal-form").addEventListener("submit", revealSeed);
    $("#change-pass-form").addEventListener("submit", changePassphrase);

    $("#recovery-export-form").addEventListener("submit", exportRecoveryKit);
    $("#recovery-restore-form").addEventListener("submit", restoreFromShares);
    $("#recovery-shares-input").addEventListener("input", scheduleSharePreview);
    $("#portable-export-form").addEventListener("submit", exportPortableVault);
    $("#portable-import-form").addEventListener("submit", importPortableVault);
    $("#btn-inspect-vault").addEventListener("click", inspectPortableVault);

    $("#btn-refresh-shares").addEventListener("click", () => loadShares().catch((error) => toast(error.message, "error")));
    $("#shares-body").addEventListener("click", handleShareAction);
    $("#share-passcode-enabled").addEventListener("change", (event) => {
      $("#share-passcode-field").classList.toggle("hidden", !event.target.checked);
    });
    $("#share-form").addEventListener("submit", createShare);
    $("#btn-copy-share").addEventListener("click", () => {
      copyText($("#share-url").value)
        .then(() => toast("Share link copied."))
        .catch((error) => toast(error.message, "error"));
    });

    $("#btn-sync-start").addEventListener("click", startSyncScheduler);
    $("#btn-sync-stop").addEventListener("click", stopSyncScheduler);
    $("#btn-sync-run").addEventListener("click", runSyncNow);
    $("#sync-settings-form").addEventListener("submit", saveSyncSettings);
    $("#btn-sync-add-root").addEventListener("click", addSyncRoot);
    // Enter in the folder input adds the folder instead of submitting the
    // scheduler-settings form.
    $("#sync-root-input").addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        addSyncRoot();
      }
    });
    // Chips re-render on every status load, so remove buttons are delegated.
    $("#sync-roots-list").addEventListener("click", (event) => {
      const button = event.target.closest(".sync-root-remove");
      if (button) removeSyncRoot(Number(button.dataset.rootIndex));
    });
    $("#btn-load-versions").addEventListener("click", loadVersions);
    $("#btn-prune-versions").addEventListener("click", pruneVersions);
    $("#versions-body").addEventListener("click", handleVersionAction);

    $("#btn-run-monitor-drill").addEventListener("click", runMonitorDrill);
    $("#btn-evaluate-alerts").addEventListener("click", evaluateAlerts);
    $("#btn-copy-badge-url").addEventListener("click", copyBadgeUrl);
    $("#alerts-list").addEventListener("click", handleAlertAction);

    $("#envelope-form").addEventListener("submit", createEnvelope);
    $("#btn-copy-envelope-url").addEventListener("click", () => {
      copyText($("#envelope-url").value)
        .then(() => toast("Envelope link copied."))
        .catch((error) => toast(error.message, "error"));
    });
    $("#btn-copy-envelope-passphrase").addEventListener("click", () => {
      copyText($("#envelope-passphrase").value)
        .then(() => toast("Passphrase copied."))
        .catch((error) => toast(error.message, "error"));
    });
    $("#btn-envelope-from-share").addEventListener("click", () => {
      if (state.shareFileId) openEnvelope(state.shareFileId);
    });

    $("#btn-clear-telemetry").addEventListener("click", () => {
      state.telemetryEvents = [];
      state.lastTelemetryMessage = "";
      renderTelemetryFeed();
    });
    $("#btn-empty-trash").addEventListener("click", emptyTrash);
    $("#trash-body").addEventListener("click", handleTrashAction);

    $("#btn-save-settings").addEventListener("click", saveSettings);
    $("#setting-accent").addEventListener("input", (event) => applyAccent(event.target.value));

    // ── New feature bindings ──────────────────────────────────────────
    $("#btn-sync-quick-add").addEventListener("click", quickAddDownloads);

    // Tripwires (canary + mass-change alarm).
    $("#canary-form").addEventListener("submit", addCanary);
    $("#canary-enabled-input").addEventListener("change", saveCanaryEnabled);
    $("#btn-canary-check").addEventListener("click", checkCanariesNow);
    $("#canary-list").addEventListener("click", handleCanaryAction);
    $("#mass-form").addEventListener("submit", saveMassSettings);
    $("#btn-mass-check").addEventListener("click", checkMassNow);

    // Air-gap & waste.
    $("#airgap-form").addEventListener("submit", saveAirgapSettings);
    $("#btn-airgap-export").addEventListener("click", runAirgapExport);
    $("#btn-airgap-verify").addEventListener("click", runAirgapVerify);
    $("#btn-airgap-drill").addEventListener("click", runAirgapDrill);
    $("#btn-waste-refresh").addEventListener("click", loadWaste);

    // Cloud import.
    $("#cloud-connect-form").addEventListener("submit", cloudConnect);
    $("#btn-cloud-refresh").addEventListener("click", loadCloud);
    $("#btn-cloud-list").addEventListener("click", cloudList);
    $("#btn-cloud-import").addEventListener("click", cloudImport);
    $("#cloud-browse-provider").addEventListener("change", () => {
      $("#cloud-files-body").innerHTML = "";
      $("#cloud-empty").classList.remove("hidden");
    });

    // Remote access.
    $("#btn-remote-rescan").addEventListener("click", loadRemote);

    // Weekly health report.
    $("#btn-health-report-run").addEventListener("click", runHealthReportNow);
    $("#btn-health-report-save").addEventListener("click", saveHealthReportSettings);

    // Inheritance switch.
    $("#btn-inheritance-enable").addEventListener("click", enableInheritance);
    $("#btn-inheritance-checkin").addEventListener("click", inheritanceCheckIn);
    $("#btn-inheritance-disable").addEventListener("click", disableInheritance);

    // Content search.
    $("#btn-content-search").addEventListener("click", runContentSearch);
    $("#content-search-input").addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        runContentSearch();
      }
    });

    window.addEventListener("beforeunload", closeTelemetry);
  }

  function bindDropZone(element, onFile) {
    if (!element) return;
    ["dragenter", "dragover"].forEach((name) => {
      element.addEventListener(name, (event) => {
        event.preventDefault();
        element.classList.add("dragover");
      });
    });
    ["dragleave", "drop"].forEach((name) => {
      element.addEventListener(name, (event) => {
        event.preventDefault();
        element.classList.remove("dragover");
      });
    });
    element.addEventListener("drop", (event) => {
      const file = event.dataTransfer && event.dataTransfer.files && event.dataTransfer.files[0];
      if (file) onFile(file);
    });
  }

  function setAuthView(view) {
    const forms = {
      unlock: $("#unlock-form"),
      setup: $("#setup-form"),
      restore: $("#restore-form"),
      seed: $("#seed-view"),
    };
    Object.entries(forms).forEach(([name, form]) => form.classList.toggle("hidden", name !== view));
    if (view === "unlock") {
      window.setTimeout(() => $("#unlock-passphrase").focus(), 80);
    }
    if (view === "setup") {
      window.setTimeout(() => $("#setup-passphrase").focus(), 80);
    }
  }

  async function checkAuth() {
    try {
      const status = await api("/api/auth/status");
      if (status.is_unlocked && status.db_opened) {
        showWorkspace();
        return;
      }
      showAuth(status.keystore_exists ? "unlock" : "setup");
    } catch (error) {
      toast(`Could not reach GhostDrive: ${error.message}`, "error");
    }
  }

  function showAuth(view) {
    state.unlocked = false;
    $("#auth-screen").classList.remove("hidden");
    $("#main-app").classList.add("hidden");
    setAuthView(view || "unlock");
    stopAlertPolling();
    closeTelemetry();
  }

  function showWorkspace() {
    state.unlocked = true;
    $("#auth-screen").classList.add("hidden");
    $("#main-app").classList.remove("hidden");
    state.seedPhrase = "";
    $("#seed-words").innerHTML = "";
    navigate("files");
    loadSettings().catch(() => {});
    connectTelemetry();
    pollAlerts();
  }

  async function handleUnlock(event) {
    event.preventDefault();
    clearError("unlock-error");
    const button = $("#btn-unlock");
    const passphrase = $("#unlock-passphrase").value;
    if (!passphrase) {
      showError("unlock-error", "Enter your master passphrase.");
      return;
    }
    setBusy(button, true, "Unlocking");
    try {
      const result = await api("/api/auth/unlock", {
        method: "POST",
        body: { passphrase },
      });
      if (result.status === "db_error") {
        showError("unlock-error", result.error || "The database could not be decrypted.");
        return;
      }
      $("#unlock-passphrase").value = "";
      showWorkspace();
    } catch (error) {
      showError("unlock-error", error.message);
    } finally {
      setBusy(button, false);
    }
  }

  async function handleSetup(event) {
    event.preventDefault();
    clearError("setup-error");
    const passphrase = $("#setup-passphrase").value;
    const confirmation = $("#setup-confirm").value;
    if (passphrase.length < 8) {
      showError("setup-error", "Use at least 8 characters.");
      return;
    }
    if (passphrase !== confirmation) {
      showError("setup-error", "The passphrases do not match.");
      return;
    }
    const button = $("#btn-create-vault");
    setBusy(button, true, "Creating vault");
    try {
      const result = await api("/api/auth/setup", {
        method: "POST",
        body: { passphrase },
      });
      state.seedPhrase = result.seed_phrase || "";
      $("#seed-words").innerHTML = state.seedPhrase
        .split(/\s+/)
        .filter(Boolean)
        .map((word, index) => `<div class="seed-word"><span>${index + 1}</span>${esc(word)}</div>`)
        .join("");
      $("#setup-passphrase").value = "";
      $("#setup-confirm").value = "";
      setAuthView("seed");
    } catch (error) {
      showError("setup-error", error.message);
    } finally {
      setBusy(button, false);
    }
  }

  async function handleRestore(event) {
    event.preventDefault();
    clearError("restore-error");
    const seedPhrase = $("#restore-seed").value.trim();
    const passphrase = $("#restore-passphrase").value;
    if (!seedPhrase || !passphrase) {
      showError("restore-error", "Enter both the recovery phrase and a new passphrase.");
      return;
    }
    const button = $("#btn-restore");
    setBusy(button, true, "Restoring");
    try {
      await api("/api/auth/restore", {
        method: "POST",
        body: { seed_phrase: seedPhrase, passphrase },
      });
      $("#restore-seed").value = "";
      $("#restore-passphrase").value = "";
      showWorkspace();
      toast("Vault restored and unlocked.");
    } catch (error) {
      showError("restore-error", error.message);
    } finally {
      setBusy(button, false);
    }
  }

  async function handleLock() {
    try {
      await api("/api/auth/lock", { method: "POST" });
      showAuth("unlock");
      toast("Vault locked.");
    } catch (error) {
      toast(error.message, "error");
    }
  }

  function handleSearch(event) {
    state.search = event.target.value.trim();
    window.clearTimeout(state.searchTimer);
    if (!state.unlocked) return;
    if (state.view !== "files") {
      navigate("files");
      return;
    }
    state.searchTimer = window.setTimeout(() => {
      loadFiles().catch((error) => toast(error.message, "error"));
    }, 260);
  }

  function navigate(view) {
    if (!view || !VIEW_META[view]) return;
    state.view = view;
    $$(".nav-item").forEach((button) => button.classList.toggle("active", button.dataset.view === view));
    $$(".view").forEach((section) => section.classList.toggle("active", section.id === `view-${view}`));
    $("#page-eyebrow").textContent = VIEW_META[view][0];
    $("#page-title").textContent = VIEW_META[view][1];
    document.title = `GhostDrive · ${VIEW_META[view][1]}`;
    $(".content").scrollTop = 0;
    closeDrawer();

    const loaders = {
      files: loadFiles,
      shares: loadShares,
      trash: loadTrash,
      backends: loadBackends,
      health: loadHealth,
      sync: loadSync,
      monitoring: loadMonitoring,
      analytics: loadAnalytics,
      smart: loadSmart,
      vault: loadVault,
      recovery: loadRecovery,
      telemetry: async () => connectTelemetry(),
      settings: loadSettings,
      security: loadSecurity,
      airgap: loadAirgap,
      cloud: loadCloud,
      remote: loadRemote,
    };
    const loader = loaders[view];
    if (loader) {
      Promise.resolve(loader()).catch((error) => toast(error.message, "error"));
    }
  }

  async function loadFiles() {
    $("#file-count").textContent = "Loading files.";
    const params = new URLSearchParams({ path: "/", category: state.category });
    if (state.search) params.set("search", state.search);
    const data = await api(`/api/files/list?${params.toString()}`);
    state.files = Array.isArray(data.files) ? data.files : [];
    renderFiles();
  }

  function renderFiles() {
    const body = $("#files-table-body");
    const empty = $("#files-empty");
    const table = body.closest("table");
    const totalBytes = state.files.reduce((sum, file) => sum + (Number(file.size) || 0), 0);
    $("#file-count").textContent = `${state.files.length} file${state.files.length === 1 ? "" : "s"} · ${formatBytes(totalBytes)}`;
    table.classList.toggle("hidden", state.files.length === 0);
    empty.classList.toggle("hidden", state.files.length > 0);

    if (state.files.length === 0) {
      empty.querySelector("h3").textContent = state.search ? "No matching files" : "Your vault is empty";
      empty.querySelector("p").textContent = state.search
        ? "Try a different name, tag, or hash."
        : "Upload a file to encrypt it and distribute it across your backends.";
      body.innerHTML = "";
      return;
    }

    body.innerHTML = state.files
      .map((file) => {
        const [glyphClass, glyphIcon] = fileGlyph(file);
        const tags = (file.tags || "")
          .split(",")
          .map((tag) => tag.trim())
          .filter(Boolean);
        const meta = [file.path || "/", ...tags.map((tag) => `#${tag}`)].join(" · ");
        return `<tr>
          <td>
            <div class="file-cell">
              <span class="file-glyph ${glyphClass}">${icon(glyphIcon)}</span>
              <div>
                <span class="file-name" title="${esc(file.filename || file.name)}">${esc(file.filename || file.name)}</span>
                <span class="file-meta" title="${esc(meta)}">${esc(meta)}</span>
              </div>
            </div>
          </td>
          <td class="hide-sm">${formatBytes(file.size)}</td>
          <td class="hide-sm"><span class="tier-badge tier-${esc(file.tier)}">${esc(file.tier)}</span></td>
          <td class="hide-md">${formatDate(file.modified_at || file.modified)}</td>
          <td>
            <div class="row-actions">
              <button class="row-button" data-file-action="details" data-id="${esc(file.id)}" title="Details" aria-label="File details">${icon("eye")}</button>
              <button class="row-button" data-file-action="download" data-id="${esc(file.id)}" title="Download" aria-label="Download">${icon("download")}</button>
              <button class="row-button" data-file-action="share" data-id="${esc(file.id)}" title="Share" aria-label="Share">${icon("share")}</button>
              <button class="row-button" data-action="envelope" data-id="${esc(file.id)}" title="Zero-knowledge link" aria-label="Zero-knowledge link">${icon("lock")}</button>
              <button class="row-button danger" data-file-action="delete" data-id="${esc(file.id)}" title="Delete" aria-label="Delete">${icon("trash")}</button>
            </div>
          </td>
        </tr>`;
      })
      .join("");
  }

  function findFile(id) {
    return state.files.find((file) => file.id === id) || (state.selectedFile && state.selectedFile.id === id ? state.selectedFile : null);
  }

  function downloadFile(file) {
    const link = document.createElement("a");
    link.href = `/api/files/download/${encodeURIComponent(file.id)}`;
    link.rel = "noopener";
    document.body.appendChild(link);
    link.click();
    link.remove();
    toast(`Preparing ${file.filename || file.name}.`);
  }

  function downloadBlob(filename, content, type) {
    // Trigger a client-side download of an in-memory blob (recovery shares,
    // kit manifest, portable vault) without touching the server again.
    const blob = content instanceof Blob ? content : new Blob([content], { type: type || "text/plain" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 4000);
  }

  async function deleteFile(file) {
    const permanent = file.tier === "DISPOSABLE";
    const confirmed = await confirmAction(
      permanent ? "Delete permanently?" : "Move file to trash?",
      permanent
        ? `“${file.filename || file.name}” is a DISPOSABLE file. This permanently removes every stored copy.`
        : `“${file.filename || file.name}” will be moved to Trash and kept for 30 days.`,
      permanent ? "Delete permanently" : "Move to trash"
    );
    if (!confirmed) return;
    try {
      await api("/api/files/delete", {
        method: "DELETE",
        body: { file_id: file.id, purge: permanent },
      });
      closeDrawer();
      if (state.selectedFile && state.selectedFile.id === file.id) state.selectedFile = null;
      toast(permanent ? "File permanently deleted." : "File moved to Trash.");
      await loadFiles();
      if (state.view === "trash") await loadTrash();
    } catch (error) {
      toast(error.message, "error");
    }
  }

  async function openDetails(file) {
    state.selectedFile = file;
    state.versions = [];
    openDrawer(file.filename || file.name, "File details");
    $("#detail-content").innerHTML = `<div class="empty-state small"><span class="spinner"></span><p>Reading encrypted metadata.</p></div>`;
    try {
      const [metadataResult, versionsResult] = await Promise.allSettled([
        api(`/api/files/metadata/${encodeURIComponent(file.id)}`),
        api(`/api/files/versions/${encodeURIComponent(file.id)}`),
      ]);
      if (metadataResult.status === "rejected") throw metadataResult.reason;
      if (!state.selectedFile || state.selectedFile.id !== file.id) return;
      const metadata = metadataResult.value;
      state.selectedFile = { ...file, ...metadata };
      state.versions = versionsResult.status === "fulfilled" ? versionsResult.value.versions || [] : [];
      renderDetails(metadata);
    } catch (error) {
      $("#detail-content").innerHTML = `<div class="notice">${esc(error.message)}</div>`;
    }
  }

  function renderDetails(metadata) {
    const file = metadata;
    const tags = file.tags || "";
    const hash = file.blake3_hash || (file.chunks && file.chunks[0] ? file.chunks[0].blake3_hash : "");
    const versionRows = state.versions.length
      ? state.versions
          .map(
            (version) => `<div class="version-row">
              <span>v${esc(version.version)} · ${formatBytes(version.size)} · ${formatDate(version.modified_at)}</span>
              <button class="btn btn-secondary btn-sm" data-detail-action="restore-version" data-file-id="${esc(file.id)}" data-version-id="${esc(version.id)}" ${version.id === file.id ? "disabled" : ""}>${version.id === file.id ? "Current" : "Restore"}</button>
            </div>`
          )
          .join("")
      : `<div class="version-row"><span>No other versions.</span></div>`;

    $("#detail-content").innerHTML = `
      <div class="detail-actions">
        <button class="btn btn-primary btn-sm" data-detail-action="download" data-file-id="${esc(file.id)}">${icon("download")} Download</button>
        <button class="btn btn-secondary btn-sm" data-detail-action="share" data-file-id="${esc(file.id)}">${icon("share")} Share</button>
        <button class="btn btn-secondary btn-sm" data-detail-action="verify" data-file-id="${esc(file.id)}">${icon("shield")} Verify</button>
      </div>
      <div class="detail-meta">
        <div><span>Size</span><strong>${formatBytes(file.size)}</strong></div>
        <div><span>Tier</span><strong>${esc(file.tier)}</strong></div>
        <div><span>Redundancy</span><strong>${esc(file.redundancy || "—")}</strong></div>
        <div><span>Version</span><strong>v${esc(file.version || 1)}</strong></div>
        <div><span>Chunks</span><strong>${esc(file.chunk_count ?? (file.chunks ? file.chunks.length : 0))}</strong></div>
        <div><span>Encoding</span><strong>${file.erasure_coded ? "RS 4+2" : "Replicated"}</strong></div>
        <div><span>MIME</span><strong title="${esc(file.mime_type)}">${esc(file.mime_type || "—")}</strong></div>
        <div><span>Modified</span><strong>${formatDate(file.modified_at)}</strong></div>
        <div><span>Created</span><strong>${formatDate(file.created_at)}</strong></div>
        <div><span>Path</span><strong title="${esc(file.path)}">${esc(file.path || "/")}</strong></div>
      </div>
      <div class="detail-section">
        <h3>Tags</h3>
        <label class="field"><span>Comma-separated</span><input id="detail-tags" value="${esc(tags)}" placeholder="finance, personal, archive"></label>
        <button class="btn btn-secondary btn-sm" data-detail-action="save-tags" data-file-id="${esc(file.id)}">Save tags</button>
      </div>
      <div class="detail-section">
        <h3>Integrity</h3>
        <code class="hash">${esc(hash || "Per-chunk hashes stored in the encrypted index.")}</code>
        <div id="verify-result" class="notice hidden" style="margin-top:10px"></div>
      </div>
      <div class="detail-section">
        <h3>Version history</h3>
        ${versionRows}
      </div>`;
  }

  async function handleDetailAction(event) {
    const button = event.target.closest("[data-detail-action]");
    if (!button) return;
    const action = button.dataset.detailAction;
    if (action === "copy-secret") {
      copyText(state.secretPayload)
        .then(() => toast("Secret payload copied."))
        .catch((error) => toast(error.message, "error"));
      return;
    }
    const file = findFile(button.dataset.fileId);
    if (!file) return;
    if (action === "download") downloadFile(file);
    if (action === "share") openShare(file);
    if (action === "verify") await verifyFile(file, button);
    if (action === "save-tags") {
      const tags = $("#detail-tags").value;
      setBusy(button, true, "Saving");
      try {
        const result = await api("/api/files/tags", {
          method: "POST",
          body: { file_id: file.id, tags },
        });
        state.selectedFile = { ...state.selectedFile, ...result.file };
        toast("Tags updated.");
        await loadFiles();
      } catch (error) {
        toast(error.message, "error");
      } finally {
        setBusy(button, false);
      }
    }
    if (action === "restore-version") {
      const version = state.versions.find((item) => item.id === button.dataset.versionId);
      if (!version) return;
      const confirmed = await confirmAction(
        "Restore this version?",
        `Replace the current file with v${version.version} from ${formatDate(version.modified_at)}.`,
        "Restore version"
      );
      if (!confirmed) return;
      try {
        await api(
          `/api/files/versions/${encodeURIComponent(file.id)}/restore/${encodeURIComponent(version.id)}`,
          { method: "POST" }
        );
        toast(`Restored v${version.version}.`);
        await loadFiles();
        const updated = findFile(file.id);
        if (updated) openDetails(updated);
      } catch (error) {
        toast(error.message, "error");
      }
    }
  }

  async function verifyFile(file, button) {
    const resultBox = $("#verify-result");
    setBusy(button, true, "Verifying");
    if (resultBox) {
      resultBox.classList.remove("hidden");
      resultBox.textContent = "Decrypting and hashing every chunk…";
    }
    try {
      const result = await api(`/api/files/verify/${encodeURIComponent(file.id)}`, { method: "POST" });
      if (resultBox) {
        resultBox.classList.remove("hidden");
        resultBox.textContent = result.healthy
          ? `Verified ${result.chunks_checked} chunk${result.chunks_checked === 1 ? "" : "s"}. Every chunk matches its BLAKE3 hash.`
          : `${result.chunks.filter((chunk) => chunk.result !== "ok").length} of ${result.chunks_checked} chunks failed verification.`;
      }
      toast(result.healthy ? "Integrity verified." : "Integrity check found problems.", result.healthy ? "success" : "error");
    } catch (error) {
      if (resultBox) resultBox.textContent = error.message;
      toast(error.message, "error");
    } finally {
      setBusy(button, false);
    }
  }

  function openUploadModal() {
    state.uploadFile = null;
    state.uploadRecommendedTier = "";
    $("#upload-file").value = "";
    $("#upload-file-row").classList.add("hidden");
    $("#upload-advisor").classList.add("hidden");
    $("#upload-progress").classList.add("hidden");
    $("#upload-progress-bar").style.width = "0%";
    $("#upload-progress-label").textContent = "Encrypting…";
    $("#btn-upload-start").disabled = false;
    const important = $('input[name="upload-tier"][value="IMPORTANT"]');
    if (important) important.checked = true;
    openModal("upload-modal");
  }

  async function selectUploadFile(file) {
    state.uploadFile = file;
    $("#upload-file-row").classList.remove("hidden");
    $("#upload-file-row").innerHTML = `
      <span class="file-glyph">${icon("file")}</span>
      <div><strong>${esc(file.name)}</strong><span>${formatBytes(file.size)} · ${esc(file.type || "Unknown type")}</span></div>
      <button type="button" aria-label="Remove selected file">${icon("close")}</button>`;
    $("#upload-file-row").querySelector("button").addEventListener("click", () => {
      state.uploadFile = null;
      $("#upload-file").value = "";
      $("#upload-file-row").classList.add("hidden");
      $("#upload-advisor").classList.add("hidden");
    });
    try {
      const advisor = await api("/api/files/tier-advisor", {
        method: "POST",
        body: {
          filename: file.name,
          file_size: file.size,
          mime_type: file.type || null,
        },
      });
      if (state.uploadFile !== file) return;
      state.uploadRecommendedTier = advisor.recommended_tier;
      const input = $(`input[name="upload-tier"][value="${advisor.recommended_tier}"]`);
      if (input) input.checked = true;
      $("#upload-advisor").classList.remove("hidden");
      $("#upload-advisor").innerHTML = `<strong>Recommended: ${esc(advisor.recommended_tier)}</strong><br>${esc(advisor.rationale)}`;
    } catch (error) {
      $("#upload-advisor").classList.remove("hidden");
      $("#upload-advisor").innerHTML = esc(error.message);
    }
  }

  function renderUploadAdvisor() {
    if (!state.uploadRecommendedTier) return;
    const selected = $('input[name="upload-tier"]:checked');
    const note = $("#upload-advisor");
    if (!selected) return;
    note.classList.remove("hidden");
    note.innerHTML =
      selected.value === state.uploadRecommendedTier
        ? `<strong>${esc(selected.value)}</strong> matches the advisor recommendation for this file.`
        : `Advisor recommends <strong>${esc(state.uploadRecommendedTier)}</strong>. You selected ${esc(selected.value)}.`;
  }

  function startUpload() {
    if (state.uploading) return;
    if (!state.uploadFile) {
      toast("Choose a file to upload.", "warn");
      return;
    }
    const file = state.uploadFile;
    const tier = $('input[name="upload-tier"]:checked');
    if (!tier) {
      toast("Choose a storage tier.", "warn");
      return;
    }
    const button = $("#btn-upload-start");
    const progress = $("#upload-progress");
    const bar = $("#upload-progress-bar");
    const label = $("#upload-progress-label");
    const form = new FormData();
    form.append("file", file);
    form.append("tier", tier.value);
    form.append("destination_path", "/");

    state.uploading = true;
    setBusy(button, true, "Encrypting");
    progress.classList.remove("hidden");
    bar.style.width = "1%";
    label.textContent = "Encrypting and distributing…";

    const request = new XMLHttpRequest();
    request.open("POST", "/api/files/upload");
    request.upload.addEventListener("progress", (event) => {
      if (!event.lengthComputable) return;
      const percent = clamp((event.loaded / event.total) * 100, 1, 99);
      bar.style.width = `${percent}%`;
      label.textContent = `${percent.toFixed(0)}% transferred`;
    });
    request.addEventListener("load", async () => {
      state.uploading = false;
      setBusy(button, false);
      if (request.status >= 200 && request.status < 300) {
        bar.style.width = "100%";
        label.textContent = "Committed.";
        window.setTimeout(() => closeModal("upload-modal"), 450);
        toast(`${file.name} encrypted and uploaded.`);
        await loadFiles().catch((error) => toast(error.message, "error"));
      } else {
        let message = "Upload failed.";
        try {
          const payload = JSON.parse(request.responseText);
          message = payload.detail || message;
        } catch (_) {
          message = request.responseText || message;
        }
        label.textContent = message;
        toast(message, "error");
      }
    });
    request.addEventListener("error", () => {
      state.uploading = false;
      setBusy(button, false);
      label.textContent = "Network error.";
      toast("Upload failed due to a network error.", "error");
    });
    request.send(form);
  }

  function openShare(file) {
    state.shareFileId = file.id;
    $("#share-title").textContent = "Create share link";
    $("#share-file-name").textContent = file.filename || file.name;
    $("#share-form").reset();
    $("#share-passcode-field").classList.add("hidden");
    $("#share-result").classList.add("hidden");
    $("#share-error").classList.add("hidden");
    const button = $("#btn-share-create");
    button.disabled = false;
    button.innerHTML = SHARE_CREATE_LABEL;
    openModal("share-modal");
  }

  async function createShare(event) {
    event.preventDefault();
    clearError("share-error");
    if (!state.shareFileId) return;
    const button = $("#btn-share-create");
    const passcodeEnabled = $("#share-passcode-enabled").checked;
    const passcode = $("#share-passcode").value;
    if (passcodeEnabled && !passcode) {
      showError("share-error", "Enter a passcode or turn off passcode protection.");
      return;
    }
    const maxDownloads = $("#share-max-downloads").value;
    let created = false;
    setBusy(button, true, "Creating");
    try {
      const link = await api("/api/sharing/create", {
        method: "POST",
        body: {
          file_id: state.shareFileId,
          ttl_hours: Number($("#share-ttl").value) || 24,
          require_passcode: passcodeEnabled,
          passcode: passcodeEnabled ? passcode : null,
          max_downloads: maxDownloads ? Number(maxDownloads) : null,
        },
      });
      created = true;
      delete button.dataset.idle;
      $("#share-result").classList.remove("hidden");
      $("#share-url").value = link.url;
      button.disabled = true;
      button.innerHTML = `${icon("check")} Link created`;
      toast("Share link created.");
      if (state.view === "shares") loadShares().catch(() => {});
      copyText(link.url)
        .then(() => toast("Link copied to clipboard."))
        .catch(() => {});
    } catch (error) {
      showError("share-error", error.message);
    } finally {
      if (!created) setBusy(button, false);
    }
  }

  async function loadShares() {
    const data = await api("/api/sharing/links");
    state.shares = Array.isArray(data.shared_links) ? data.shared_links : [];
    renderShares();
  }

  function renderShares() {
    const body = $("#shares-body");
    const table = body.closest("table");
    const empty = $("#shares-empty");
    table.classList.toggle("hidden", state.shares.length === 0);
    empty.classList.toggle("hidden", state.shares.length > 0);
    body.innerHTML = state.shares
      .map((link) => {
        const expiry = link.revoked
          ? "Revoked"
          : parseDate(link.expires_at) && parseDate(link.expires_at) < new Date()
          ? "Expired"
          : formatDate(link.expires_at);
        const downloads = `${formatNumber(link.access_count)}${link.max_downloads ? ` / ${formatNumber(link.max_downloads)}` : ""}`;
        return `<tr>
          <td><span class="file-name">${esc(link.filename)}</span><span class="file-meta">${esc(link.recipient_alias || "public")}</span></td>
          <td class="hide-md">${formatDate(link.created_at)}</td>
          <td>${expiry}</td>
          <td>${downloads}</td>
          <td>
            <div class="row-actions">
              <button class="row-button" data-share-action="copy" data-id="${esc(link.link_id)}" title="Copy link" aria-label="Copy link">${icon("copy")}</button>
              <button class="row-button danger" data-share-action="revoke" data-id="${esc(link.link_id)}" title="Revoke" aria-label="Revoke" ${link.revoked ? "disabled" : ""}>${icon("trash")}</button>
            </div>
          </td>
        </tr>`;
      })
      .join("");
  }

  async function handleShareAction(event) {
    const button = event.target.closest("[data-share-action]");
    if (!button) return;
    const link = state.shares.find((item) => item.link_id === button.dataset.id);
    if (!link) return;
    if (button.dataset.shareAction === "copy") {
      copyText(link.url)
        .then(() => toast("Share link copied."))
        .catch((error) => toast(error.message, "error"));
    }
    if (button.dataset.shareAction === "revoke") {
      const confirmed = await confirmAction(
        "Revoke share link?",
        `The link for “${link.filename}” will stop working immediately.`,
        "Revoke link"
      );
      if (!confirmed) return;
      try {
        await api(`/api/sharing/revoke/${encodeURIComponent(link.link_id)}`, { method: "DELETE" });
        toast("Share link revoked.");
        await loadShares();
      } catch (error) {
        toast(error.message, "error");
      }
    }
  }

  // ── Zero-knowledge envelope share ──────────────────────────────────────

  function openEnvelope(fileId) {
    const file = findFile(fileId);
    state.envelopeFileId = fileId;
    $("#envelope-file-name").textContent = file ? file.filename || file.name : "";
    $("#envelope-form").reset();
    $("#envelope-result").classList.add("hidden");
    $("#envelope-warning").classList.add("hidden");
    clearError("envelope-error");
    const button = $("#btn-envelope-create");
    button.disabled = false;
    button.innerHTML = ENVELOPE_CREATE_LABEL;
    openModal("envelope-modal");
  }

  async function createEnvelope(event) {
    event.preventDefault();
    clearError("envelope-error");
    if (!state.envelopeFileId) return;
    const button = $("#btn-envelope-create");
    const maxDownloads = $("#envelope-max-downloads").value;
    let created = false;
    setBusy(button, true, "Creating");
    try {
      const link = await api("/api/sharing/envelope", {
        method: "POST",
        body: {
          file_id: state.envelopeFileId,
          ttl_hours: Number($("#envelope-ttl").value) || 72,
          max_downloads: maxDownloads ? Number(maxDownloads) : null,
          burn_after_read: $("#envelope-burn").checked,
        },
      });
      created = true;
      delete button.dataset.idle;
      $("#envelope-url").value = link.url || "";
      $("#envelope-passphrase").value = link.passphrase || "";
      $("#envelope-result").classList.remove("hidden");
      $("#envelope-warning").classList.remove("hidden");
      button.disabled = true;
      button.innerHTML = `${icon("check")} Link created`;
      toast("Envelope link created. Passphrase shown once.");
      if (state.view === "shares") loadShares().catch(() => {});
    } catch (error) {
      showError("envelope-error", error.message);
    } finally {
      if (!created) setBusy(button, false);
    }
  }

  // ── Sync & versions ────────────────────────────────────────────────────

  async function loadSync() {
    const [status, files] = await Promise.all([
      api("/api/sync/status"),
      api("/api/files/list?path=/&category=all"),
    ]);
    state.syncStatus = status;
    state.syncFiles = Array.isArray(files.files) ? files.files : [];
    renderSyncStatus();
    renderSyncFileOptions();
  }

  function renderSyncStatus() {
    const status = state.syncStatus;
    if (!status) return;
    const enabled = Boolean(status.enabled);
    const running = Boolean(status.running);
    const roots = Array.isArray(status.roots) ? status.roots : [];
    $("#sync-status-summary").textContent = roots.length
      ? `Auto-vaulting ${formatNumber(roots.length)} folder${roots.length === 1 ? "" : "s"} every ${formatNumber(status.interval_seconds)} seconds.`
      : "Add a folder below to start auto-vaulting local files.";
    $("#sync-root").textContent = roots.length
      ? roots.length === 1
        ? roots[0]
        : `${formatNumber(roots.length)} folders`
      : "Not set";
    $("#sync-interval-input").value = String(Number(status.interval_seconds) || 60);
    $("#sync-enabled-input").checked = enabled;
    $("#sync-enabled-dot").className = `status-dot ${enabled ? "ok" : ""}`;
    $("#sync-enabled-text").textContent = enabled ? "Enabled" : "Disabled";
    $("#sync-running-dot").className = `status-dot ${running ? "warn" : ""}`;
    $("#sync-running-text").textContent = running ? "Scheduler running" : "Scheduler idle";
    $("#sync-interval").textContent = `every ${formatNumber(status.interval_seconds)} s`;
    $("#sync-last-run").textContent = status.last_run_at
      ? `${formatDate(status.last_run_at)} ${formatTime(status.last_run_at)}`
      : "Never";
    const pill = $("#sync-state-pill");
    pill.textContent = running ? "RUNNING" : enabled ? "ARMED" : "OFF";
    pill.className = `pill durability-state ${running ? "state-degraded" : enabled ? "state-protected" : ""}`;
    const result = status.last_result;
    ["scanned", "uploaded", "unchanged", "versioned", "trashed"].forEach((key) => {
      const element = document.getElementById(`sync-${key}`);
      if (element) element.textContent = result ? formatNumber(result[key]) : "—";
    });
    const errors = result && Array.isArray(result.errors) ? result.errors : [];
    $("#sync-errors").textContent = formatNumber(errors.length);
    $("#sync-last-result-note").textContent = result
      ? `Last pass ${formatDate(status.last_run_at)} in ${formatNumber(result.duration_ms || 0)} ms.` +
        (errors.length ? ` First error: ${errors[0]}` : "")
      : "No sync pass has run yet.";
    renderSyncRoots();
  }

  function renderSyncRoots() {
    const list = $("#sync-roots-list");
    if (!list) return;
    const status = state.syncStatus || {};
    const details = Array.isArray(status.root_details) ? status.root_details : [];
    if (!details.length) {
      list.innerHTML = `<p class="muted sync-roots-empty">No folders yet — add one below to start auto-vaulting.</p>`;
      return;
    }
    list.innerHTML = details
      .map(
        (detail, index) => `
      <div class="sync-root-chip" title="${esc(detail.path)}">
        <svg class="icon"><use href="#i-files"/></svg>
        <span class="sync-root-path">${esc(detail.path)}</span>
        <span class="sync-root-count">${formatNumber(detail.tracked || 0)} files</span>
        <button class="icon-button sync-root-remove" type="button" data-root-index="${index}" aria-label="Stop auto-vaulting this folder"><svg class="icon"><use href="#i-close"/></svg></button>
      </div>`
      )
      .join("");
  }

  async function saveSyncRoots(roots, successMessage) {
    // Every folder in the list is re-validated by the server; the response
    // carries the canonical status which re-renders the chips.
    const status = await api("/api/sync/settings", {
      method: "POST",
      body: { roots },
    });
    state.syncStatus = status;
    renderSyncStatus();
    toast(successMessage);
  }

  async function currentSyncRoots() {
    // Never build a replacement list from an unloaded status: it would wipe
    // folders the server already knows about.
    if (!state.syncStatus) {
      state.syncStatus = await api("/api/sync/status");
    }
    const roots = state.syncStatus.roots;
    return Array.isArray(roots) ? roots : [];
  }

  async function addSyncRoot() {
    clearError("sync-settings-error");
    const input = $("#sync-root-input");
    const path = input.value.trim();
    if (!path) {
      showError("sync-settings-error", "Enter a folder path to auto-vault.");
      input.focus();
      return;
    }
    let current;
    try {
      current = await currentSyncRoots();
    } catch (error) {
      showError("sync-settings-error", error.message);
      return;
    }
    const button = $("#btn-sync-add-root");
    setBusy(button, true, "Adding");
    try {
      await saveSyncRoots([...current, path], `Now auto-vaulting ${path}.`);
      input.value = "";
    } catch (error) {
      showError("sync-settings-error", error.message);
    } finally {
      setBusy(button, false);
    }
  }

  async function removeSyncRoot(index) {
    clearError("sync-settings-error");
    let current;
    try {
      current = await currentSyncRoots();
    } catch (error) {
      showError("sync-settings-error", error.message);
      return;
    }
    const target = current[index];
    if (!target) return;
    const confirmed = await confirmAction(
      "Stop auto-vaulting this folder?",
      `${target} will no longer be watched. Its already-vaulted copies stay in the vault (nothing is deleted).`,
      "Stop watching"
    );
    if (!confirmed) return;
    try {
      await saveSyncRoots(current.filter((_, i) => i !== index), `Stopped auto-vaulting ${target}.`);
    } catch (error) {
      showError("sync-settings-error", error.message);
    }
  }

  function renderSyncFileOptions() {
    const select = $("#versions-file");
    const previous = state.syncFileId;
    select.innerHTML =
      `<option value="">Select a file…</option>` +
      state.syncFiles
        .map((file) => `<option value="${esc(file.id)}">${esc(file.filename || file.name)}</option>`)
        .join("");
    if (previous && state.syncFiles.some((file) => file.id === previous)) select.value = previous;
  }

  async function startSyncScheduler() {
    const button = $("#btn-sync-start");
    setBusy(button, true, "Starting");
    try {
      await api("/api/sync/start", { method: "POST" });
      toast("Sync scheduler started.");
      await loadSync();
    } catch (error) {
      toast(error.message, "error");
    } finally {
      setBusy(button, false);
    }
  }

  async function stopSyncScheduler() {
    const button = $("#btn-sync-stop");
    setBusy(button, true, "Stopping");
    try {
      await api("/api/sync/stop", { method: "POST" });
      toast("Sync scheduler stopped.");
      await loadSync();
    } catch (error) {
      toast(error.message, "error");
    } finally {
      setBusy(button, false);
    }
  }

  async function runSyncNow() {
    const button = $("#btn-sync-run");
    setBusy(button, true, "Running");
    try {
      const result = await api("/api/sync/run", { method: "POST", body: {} });
      const errors = Array.isArray(result.errors) ? result.errors : [];
      toast(
        `Sync pass: ${formatNumber(result.scanned)} scanned, ${formatNumber(result.uploaded)} uploaded, ${formatNumber(result.unchanged)} unchanged, ${formatNumber(result.versioned)} versioned, ${formatNumber(result.trashed)} trashed.`,
        errors.length ? "warn" : "success"
      );
      if (errors.length) toast(errors[0], "error");
      await loadSync();
    } catch (error) {
      toast(error.message, "error");
    } finally {
      setBusy(button, false);
    }
  }

  async function saveSyncSettings(event) {
    event.preventDefault();
    clearError("sync-settings-error");
    const button = $("#btn-sync-save");
    setBusy(button, true, "Saving");
    try {
      // Folder membership has its own add/remove controls; this form only
      // persists the scheduler settings.
      await api("/api/sync/settings", {
        method: "POST",
        body: {
          interval_seconds: Number($("#sync-interval-input").value) || 60,
          enabled: $("#sync-enabled-input").checked,
        },
      });
      toast("Sync settings saved.");
      await loadSync();
    } catch (error) {
      showError("sync-settings-error", error.message);
    } finally {
      setBusy(button, false);
    }
  }

  async function loadVersions() {
    clearError("versions-error");
    const fileId = $("#versions-file").value;
    if (!fileId) {
      showError("versions-error", "Choose a file to load its version history.");
      return;
    }
    state.syncFileId = fileId;
    const button = $("#btn-load-versions");
    setBusy(button, true, "Loading");
    try {
      const data = await api(`/api/sync/versions/${encodeURIComponent(fileId)}`);
      state.syncVersions = Array.isArray(data.versions) ? data.versions : [];
      renderVersions();
    } catch (error) {
      showError("versions-error", error.message);
    } finally {
      setBusy(button, false);
    }
  }

  function renderVersions() {
    const body = $("#versions-body");
    const table = body.closest("table");
    const empty = $("#versions-empty");
    const versions = state.syncVersions;
    table.classList.toggle("hidden", versions.length === 0);
    empty.classList.toggle("hidden", versions.length > 0);
    const current = versions.reduce(
      (max, version) => Math.max(max, Number(version.version) || 0),
      0
    );
    body.innerHTML = versions
      .map((version) => {
        const isCurrent = current > 0 && Number(version.version) === current;
        return `<tr>
          <td><span class="file-name">v${esc(version.version)}</span></td>
          <td><span class="tier-badge tier-neutral">${esc(version.reason)}</span></td>
          <td class="hide-sm">${formatBytes(version.size)}</td>
          <td class="hide-md">${formatDate(version.created_at)}</td>
          <td>${isCurrent ? '<span class="pill durability-state state-protected">CURRENT</span>' : '<span class="muted">older</span>'}</td>
          <td>
            <div class="row-actions">
              <button class="btn btn-secondary btn-sm" data-version-action="restore" data-version="${esc(version.version)}" ${isCurrent ? "disabled" : ""}>${isCurrent ? "Current" : "Restore"}</button>
            </div>
          </td>
        </tr>`;
      })
      .join("");
  }

  async function handleVersionAction(event) {
    const button = event.target.closest("[data-version-action]");
    if (!button || button.disabled) return;
    if (button.dataset.versionAction !== "restore") return;
    const fileId = state.syncFileId;
    const version = Number(button.dataset.version);
    if (!fileId || !version) return;
    const confirmed = await confirmAction(
      "Restore this version?",
      `Version ${version} becomes the live file and a restore version is appended to the history.`,
      "Restore version"
    );
    if (!confirmed) return;
    setBusy(button, true, "Restoring");
    try {
      const result = await api(
        `/api/sync/versions/${encodeURIComponent(fileId)}/restore`,
        { method: "POST", body: { version } }
      );
      toast(`Restored version ${result.restored_version}; new version ${result.new_version} recorded.`);
      await loadVersions();
    } catch (error) {
      toast(error.message, "error");
    } finally {
      setBusy(button, false);
    }
  }

  async function pruneVersions() {
    clearError("versions-error");
    const fileId = state.syncFileId;
    if (!fileId) {
      showError("versions-error", "Load a file's version history first.");
      return;
    }
    const keep = Number($("#versions-keep").value) || 0;
    if (keep < 1) {
      showError("versions-error", "Keep at least one version.");
      return;
    }
    const confirmed = await confirmAction(
      "Prune version history?",
      `Keep the newest ${keep} version${keep === 1 ? "" : "s"} for this file. Older versions are removed permanently.`,
      "Prune versions"
    );
    if (!confirmed) return;
    const button = $("#btn-prune-versions");
    setBusy(button, true, "Pruning");
    try {
      const result = await api(`/api/sync/versions/${encodeURIComponent(fileId)}/prune`, {
        method: "POST",
        body: { keep },
      });
      toast(
        `Pruned ${formatNumber(result.removed)} version${Number(result.removed) === 1 ? "" : "s"}; ${formatNumber(result.keep)} kept.`
      );
      await loadVersions();
    } catch (error) {
      toast(error.message, "error");
    } finally {
      setBusy(button, false);
    }
  }

  // ── Monitoring: badge, drills, alerts ─────────────────────────────────

  async function loadMonitoring() {
    const [badge, summary, drills, alerts, scheduler, healthReport] = await Promise.all([
      api("/api/monitoring/badge"),
      api("/api/monitoring/drills/summary"),
      api("/api/monitoring/drills"),
      api("/api/monitoring/alerts"),
      api("/api/monitoring/scheduler"),
      api("/api/health/report").catch(() => null),
    ]);
    state.monitorAlerts = Array.isArray(alerts.alerts) ? alerts.alerts : [];
    renderMonitorBadge(badge);
    renderDrillSummary(summary);
    renderDrillHistory(Array.isArray(drills) ? drills : []);
    renderAlerts(state.monitorAlerts);
    renderScheduler(scheduler);
    renderNavAlertBadge(alerts.active_count);
    if (healthReport) {
      state.healthReport = healthReport.report || null;
      renderHealthReport(healthReport.last_run, healthReport.report);
    }
  }

  function renderMonitorBadge(badge) {
    const overall = ["green", "amber", "red"].includes(badge.overall) ? badge.overall : "green";
    const pill = $("#monitor-badge-pill");
    pill.textContent = overall.toUpperCase();
    pill.className = `pill badge-verdict badge-${overall}`;
    $("#monitor-badge-label").textContent = badge.label || "—";
    $("#monitor-active-alerts").textContent = formatNumber(badge.active_alerts);
    const contract = badge.contract || {};
    $("#monitor-contract").textContent =
      contract.summary ||
      (contract.meets ? "Meets durability contract" : "Below durability contract");
    $("#badge-checked-at").textContent = badge.checked_at
      ? `Checked ${formatDate(badge.checked_at)} at ${formatTime(badge.checked_at)}.`
      : "Waiting for the first check.";
    const image = $("#monitor-badge-img");
    if (image) image.src = `/api/monitoring/badge.svg?t=${Date.now()}`;
  }

  async function copyBadgeUrl() {
    try {
      await copyText(`${window.location.origin}/api/monitoring/badge.svg`);
      toast("Badge URL copied.");
    } catch (error) {
      toast(error.message, "error");
    }
  }

  function renderDrillSummary(summary) {
    $("#drill-total").textContent = formatNumber(summary.total);
    $("#drill-passed").textContent = formatNumber(summary.passed);
    $("#drill-failed").textContent = formatNumber(summary.failed);
    $("#drill-consecutive").textContent = formatNumber(summary.consecutive_failures);
    const stale = Boolean(summary.stale);
    $("#drill-stale").textContent = stale ? "Yes" : "No";
    const stalePill = $("#drill-stale-pill");
    stalePill.textContent = stale ? "STALE" : "FRESH";
    stalePill.className = `pill badge-verdict ${stale ? "badge-red" : "badge-green"}`;
    const last = summary.last;
    $("#drill-summary-line").textContent =
      last && last.result
        ? `Last drill ${last.result} ${formatDate(last.completed_at || last.started_at)} · last success ${summary.last_success_at ? formatDate(summary.last_success_at) : "never"}.`
        : "No restore drills recorded yet.";
  }

  function renderDrillHistory(drills) {
    const body = $("#drills-body");
    const table = body.closest("table");
    const empty = $("#drills-empty");
    table.classList.toggle("hidden", drills.length === 0);
    empty.classList.toggle("hidden", drills.length > 0);
    body.innerHTML = drills
      .map((drill) => {
        const detail = String(drill.detail || "");
        const short = detail.length > 90 ? `${detail.slice(0, 90)}…` : detail;
        const tone =
          drill.result === "passed"
            ? "badge-green"
            : drill.result === "failed"
            ? "badge-red"
            : "badge-amber";
        return `<tr>
          <td>${formatDate(drill.started_at)} ${formatTime(drill.started_at)}</td>
          <td><span class="pill badge-verdict ${tone}">${esc(drill.result)}</span></td>
          <td class="hide-sm">${formatBytes(drill.bytes_restored)}</td>
          <td class="hide-md">${formatNumber(drill.duration_ms)} ms</td>
          <td><span class="muted" title="${esc(detail)}">${esc(short || "—")}</span></td>
        </tr>`;
      })
      .join("");
  }

  function renderAlerts(alerts) {
    const list = $("#alerts-list");
    const active = alerts.filter((alert) => !alert.dismissed);
    if (!active.length) {
      list.innerHTML = `<div class="empty-state small"><p>No active alerts — everything looks healthy.</p></div>`;
      return;
    }
    list.innerHTML = active
      .map((alert) => {
        const severity = String(alert.severity || "info").toLowerCase();
        const tone =
          severity === "critical"
            ? "severity-critical"
            : severity === "warning"
            ? "severity-warning"
            : "severity-info";
        return `<div class="alert-row ${tone}">
          <span class="severity-chip">${esc(severity)}</span>
          <div class="alert-main"><strong>${esc(alert.title)}</strong><span>${esc(alert.detail)}</span></div>
          <time>${alert.first_seen_at ? formatDate(alert.first_seen_at) : "just now"}</time>
          <button class="btn btn-secondary btn-sm" data-alert-action="dismiss" data-id="${esc(alert.id)}" type="button">Dismiss</button>
        </div>`;
      })
      .join("");
  }

  async function handleAlertAction(event) {
    const button = event.target.closest("[data-alert-action]");
    if (!button) return;
    if (button.dataset.alertAction !== "dismiss") return;
    setBusy(button, true, "Dismissing");
    try {
      await api(`/api/monitoring/alerts/${encodeURIComponent(button.dataset.id)}`, {
        method: "DELETE",
      });
      toast("Alert dismissed.");
      await loadMonitoring();
    } catch (error) {
      toast(error.message, "error");
    } finally {
      setBusy(button, false);
    }
  }

  async function evaluateAlerts() {
    const button = $("#btn-evaluate-alerts");
    setBusy(button, true, "Evaluating");
    try {
      const result = await api("/api/monitoring/alerts/evaluate", { method: "POST", body: {} });
      const count = Number(result.new_alerts) || 0;
      toast(
        count ? `${count} new alert${count === 1 ? "" : "s"} raised.` : "No new alerts raised.",
        count ? "warn" : "success"
      );
      await loadMonitoring();
    } catch (error) {
      toast(error.message, "error");
    } finally {
      setBusy(button, false);
    }
  }

  async function runMonitorDrill() {
    const button = $("#btn-run-monitor-drill");
    setBusy(button, true, "Drilling");
    try {
      const result = await api("/api/monitoring/drills/run", {
        method: "POST",
        body: { deep: false },
      });
      const tone =
        result.result === "passed" ? "success" : result.result === "failed" ? "error" : "warn";
      toast(`Restore drill ${result.result}: ${result.detail}`, tone);
      await loadMonitoring();
    } catch (error) {
      toast(error.message, "error");
    } finally {
      setBusy(button, false);
    }
  }

  function renderScheduler(scheduler) {
    const drills = scheduler.drills || {};
    const alerts = scheduler.alerts || {};
    $("#monitor-drill-scheduler").textContent =
      `every ${formatNumber(drills.interval_hours)} h · ${drills.running ? "running" : "idle"} · ${drills.enabled ? "enabled" : "paused"}`;
    $("#monitor-alert-scheduler").textContent =
      `every ${formatNumber(alerts.interval_minutes)} min · ${alerts.running ? "running" : "idle"}`;
  }

  // ── Global alert toasts + nav badge ────────────────────────────────────

  function renderNavAlertBadge(count) {
    const badge = $("#nav-alert-badge");
    if (!badge) return;
    const total = Number(count) || 0;
    badge.textContent = total > 9 ? "9+" : String(total);
    badge.classList.toggle("hidden", total === 0);
  }

  function stopAlertPolling() {
    window.clearTimeout(state.alertTimer);
    state.alertTimer = null;
  }

  async function pollAlerts() {
    if (!state.unlocked) return;
    try {
      const data = await api("/api/monitoring/alerts");
      const alerts = Array.isArray(data.alerts) ? data.alerts : [];
      const active = alerts.filter((alert) => !alert.dismissed);
      active.forEach((alert) => {
        const id = String(alert.id || "");
        if (!id || state.alertToasted.has(id)) return;
        state.alertToasted.add(id);
        const severity = String(alert.severity || "info");
        const type = severity === "critical" ? "error" : severity === "warning" ? "warn" : "success";
        toast(`${severity.toUpperCase()}: ${alert.title} — ${alert.detail}`, type);
      });
      renderNavAlertBadge(data.active_count || active.length);
      if (state.view === "monitoring") {
        state.monitorAlerts = alerts;
        renderAlerts(alerts);
      }
    } catch (_) {
      // Background poll: an unreachable API stays quiet, the next tick retries.
    }
    if (state.unlocked) {
      window.clearTimeout(state.alertTimer);
      state.alertTimer = window.setTimeout(pollAlerts, ALERT_POLL_MS);
    }
  }

  async function loadBackends() {
    const data = await api("/api/backends/list");
    state.backends = Array.isArray(data.configured_backends) ? data.configured_backends : [];
    renderBackends();
  }

  function renderBackends() {
    const backends = state.backends;
    const totalStored = backends.reduce((sum, item) => sum + (Number(item.used_bytes) || 0), 0);
    const healthy = backends.filter((item) => String(item.status).toUpperCase() === "ONLINE" || String(item.status).toUpperCase() === "HEALTHY").length;
    $("#backend-count").textContent = formatNumber(backends.length);
    $("#backend-healthy").textContent = formatNumber(healthy);
    $("#backend-storage").textContent = formatBytes(totalStored);
    $("#backend-grid").innerHTML = backends.map(renderBackendCard).join("");
    $("#backend-grid").classList.toggle("hidden", backends.length === 0);
    $("#backends-empty").classList.toggle("hidden", backends.length > 0);
  }

  function backendIcon(providerKey) {
    if (providerKey === "nas") return "server";
    if (providerKey === "external_drive") return "drive";
    if (providerKey === "telegram" || providerKey === "discord") return "wifi";
    return "database";
  }

  function renderBackendCard(backend) {
    const used = Number(backend.used_bytes) || 0;
    const cap = Number(backend.quota_cap_bytes) || 0;
    const percent = cap > 0 ? clamp((used / cap) * 100, 0, 100) : 0;
    const online = String(backend.status).toUpperCase() === "ONLINE" || String(backend.status).toUpperCase() === "HEALTHY";
    const capacityLabel = cap > 0 && cap < 4e18 ? `${formatBytes(used)} of ${formatBytes(cap)}` : `${formatBytes(used)} · no cap`;
    return `<article class="backend-card">
      <div class="backend-head">
        <span class="backend-icon">${icon(backendIcon(backend.provider_key))}</span>
        <div class="backend-title"><strong title="${esc(backend.name)}">${esc(backend.name)}</strong><span>${esc(backend.provider)}${backend.append_only ? " · WORM" : ""}</span></div>
        <label class="switch" title="Enable or disable backend">
          <input type="checkbox" data-backend-toggle="${esc(backend.id)}" ${backend.enabled ? "checked" : ""}>
          <i></i>
        </label>
      </div>
      <div class="backend-capacity">
        <div><span>${capacityLabel}</span><strong>${cap > 0 ? formatPercent(percent) : "—"}</strong></div>
        <div class="progress"><span style="width:${percent}%"></span></div>
      </div>
      <div class="backend-foot">
        <span class="backend-status"><span class="status-dot ${online ? "ok" : "warn"}"></span>${esc(backend.status)}${backend.latency_ms ? ` · ${Number(backend.latency_ms).toFixed(0)} ms` : ""}</span>
        <div class="backend-actions">
          <button class="row-button" data-backend-action="worm" data-id="${esc(backend.id)}" title="${backend.append_only ? "Disable WORM (append-only)" : "Enable WORM (append-only)"}">${icon("lock")}</button>
          <button class="row-button" data-backend-action="test" data-id="${esc(backend.id)}" title="Test connection">${icon("activity")}</button>
          <button class="row-button danger" data-backend-action="remove" data-id="${esc(backend.id)}" title="Remove backend">${icon("trash")}</button>
        </div>
      </div>
    </article>`;
  }

  async function openBackendModal() {
    $("#backend-form").reset();
    clearError("backend-error");
    $("#backend-provider").value = "local";
    $("#backend-quota").value = "0";
    await renderBackendFields();
    openModal("backend-modal");
  }

  async function renderBackendFields() {
    const provider = $("#backend-provider").value;
    const container = $("#backend-fields");
    const token = ++state.backendFieldsToken;
    if (provider === "local") {
      container.innerHTML = `<label class="field"><span>Folder path</span><input id="bf-path" placeholder="C:\\Users\\You\\GhostDriveLocker" required></label>`;
    } else if (provider === "external") {
      container.innerHTML = `<label class="field"><span>Detected drive</span><select id="bf-drive"><option value="">Scanning drives…</option></select></label>`;
      try {
        const data = await api("/api/backends/drives");
        if (token !== state.backendFieldsToken) return;
        const drives = data.drives || [];
        container.innerHTML = `<label class="field"><span>Detected drive</span><select id="bf-drive">${
          drives.length
            ? drives
                .map(
                  (drive) =>
                    `<option value="${esc(drive.drive_uuid)}" data-capacity="${esc(drive.capacity_bytes)}" data-mount="${esc(drive.mountpoint)}" data-serial="${esc(drive.drive_serial || "")}" data-type="${esc(drive.drive_type || "unknown")}">${esc(drive.mountpoint)} · ${formatBytes(drive.capacity_bytes)} · ${esc(drive.drive_type || "drive")}</option>`
                )
                .join("")
            : `<option value="">No external drives detected</option>`
        }</select></label>`;
      } catch (error) {
        if (token === state.backendFieldsToken) {
          container.innerHTML = `<div class="form-error">${esc(error.message)}</div>`;
        }
      }
    } else if (provider === "nas") {
      container.innerHTML = `
        <div class="field-grid">
          <label class="field"><span>Protocol</span><select id="bf-protocol"><option value="sftp">SFTP</option><option value="smb">SMB</option></select></label>
          <label class="field"><span>Host</span><input id="bf-host" placeholder="192.168.1.20" required></label>
        </div>
        <div class="field-grid">
          <label class="field"><span>Port</span><input id="bf-port" type="number" placeholder="22"></label>
          <label class="field"><span>Username</span><input id="bf-username" required></label>
        </div>
        <label class="field"><span>Password</span><input id="bf-password" type="password" autocomplete="new-password"></label>
        <div class="field-grid">
          <label class="field"><span>Share</span><input id="bf-share" placeholder="optional"></label>
          <label class="field"><span>Remote directory</span><input id="bf-remote-dir" value="GhostDriveData"></label>
        </div>`;
    } else if (provider === "telegram") {
      container.innerHTML = `
        <div class="field-grid">
          <label class="field"><span>API ID</span><input id="bf-api-id" required></label>
          <label class="field"><span>Phone</span><input id="bf-phone" placeholder="+1..." required></label>
        </div>
        <label class="field"><span>API hash</span><input id="bf-api-hash" required></label>`;
    } else if (provider === "discord") {
      container.innerHTML = `
        <label class="field"><span>Bot token</span><input id="bf-bot-token" type="password" autocomplete="new-password" required></label>
        <label class="field"><span>Channel ID</span><input id="bf-channel-id" required></label>`;
    }
  }

  function fieldValue(id) {
    const element = document.getElementById(id);
    return element ? element.value.trim() : "";
  }

  async function saveBackend(event) {
    event.preventDefault();
    clearError("backend-error");
    const provider = $("#backend-provider").value;
    let credentials = {};
    if (provider === "local") {
      credentials = { path: fieldValue("bf-path") };
      if (!credentials.path) return showError("backend-error", "Enter a folder path.");
    } else if (provider === "external") {
      const select = $("#bf-drive");
      const option = select && select.selectedOptions[0];
      if (!select || !select.value) return showError("backend-error", "Select a detected external drive.");
      credentials = {
        drive_uuid: select.value,
        capacity_bytes: Number(option.dataset.capacity) || 0,
        mount_hint: option.dataset.mount || "",
        drive_serial: option.dataset.serial || "",
        drive_type: option.dataset.type || "unknown",
      };
    } else if (provider === "nas") {
      credentials = {
        protocol: fieldValue("bf-protocol"),
        host: fieldValue("bf-host"),
        port: Number(fieldValue("bf-port")) || null,
        username: fieldValue("bf-username"),
        password: fieldValue("bf-password"),
        share: fieldValue("bf-share"),
        remote_dir: fieldValue("bf-remote-dir") || "GhostDriveData",
      };
      if (!credentials.host || !credentials.username) {
        return showError("backend-error", "NAS requires a host and username.");
      }
    } else if (provider === "telegram") {
      credentials = {
        api_id: fieldValue("bf-api-id"),
        api_hash: fieldValue("bf-api-hash"),
        phone: fieldValue("bf-phone"),
      };
      if (!credentials.api_id || !credentials.api_hash || !credentials.phone) {
        return showError("backend-error", "Telegram requires API ID, API hash, and phone.");
      }
    } else if (provider === "discord") {
      credentials = {
        bot_token: fieldValue("bf-bot-token"),
        channel_id: fieldValue("bf-channel-id"),
      };
      if (!credentials.bot_token || !credentials.channel_id) {
        return showError("backend-error", "Discord requires a bot token and channel ID.");
      }
    }
    const tier = provider === "telegram" ? "REMOTE_PRIMARY" : provider === "discord" ? "REMOTE_SECONDARY" : "LOCAL_LOCKER";
    const button = $("#btn-backend-save");
    setBusy(button, true, "Adding");
    try {
      await api("/api/backends/save", {
        method: "POST",
        body: {
          provider,
          name: $("#backend-name").value.trim() || provider,
          tier,
          enabled: true,
          credentials,
          quota_cap_gb: Number($("#backend-quota").value) || 0,
          append_only: $("#backend-worm").checked,
        },
      });
      closeModal("backend-modal");
      toast("Backend added.");
      await loadBackends();
    } catch (error) {
      showError("backend-error", error.message);
    } finally {
      setBusy(button, false);
    }
  }

  async function handleBackendAction(event) {
    const button = event.target.closest("[data-backend-action]");
    if (!button) return;
    const backend = state.backends.find((item) => item.id === button.dataset.id);
    if (!backend) return;
    if (button.dataset.backendAction === "test") {
      setBusy(button, true);
      try {
        const result = await api("/api/backends/test", {
          method: "POST",
          body: { provider: backend.provider_key, credentials: {}, backend_id: backend.id },
        });
        toast(result.message, result.success ? "success" : "error");
        await loadBackends();
      } catch (error) {
        toast(error.message, "error");
      } finally {
        setBusy(button, false);
      }
    }
    if (button.dataset.backendAction === "worm") {
      const enabling = !backend.append_only;
      const confirmed = await confirmAction(
        enabling ? "Enable WORM mode?" : "Disable WORM mode?",
        enabling
          ? `“${backend.name}” will refuse to overwrite or delete anything, even on request. Chunks already on it are retained through purge.`
          : `“${backend.name}” will allow deletes again. Bytes retained under WORM are not restored automatically.`,
        enabling ? "Enable WORM" : "Disable WORM"
      );
      if (!confirmed) return;
      try {
        await api(`/api/backends/${encodeURIComponent(backend.id)}/worm`, {
          method: "POST",
          body: { enabled: enabling },
        });
        toast(enabling ? "WORM enabled — this backend is now append-only." : "WORM disabled.");
        await loadBackends();
      } catch (error) {
        toast(error.message, "error");
      }
      return;
    }
    if (button.dataset.backendAction === "remove") {
      const confirmed = await confirmAction(
        "Remove backend?",
        `“${backend.name}” will no longer receive new data. Existing chunks must remain available until repaired.`,
        "Remove backend"
      );
      if (!confirmed) return;
      try {
        await api(`/api/backends/remove/${encodeURIComponent(backend.id)}`, { method: "DELETE" });
        toast("Backend removed.");
        await loadBackends();
      } catch (error) {
        toast(error.message, "error");
      }
    }
  }

  async function toggleBackend(id, enabled, input) {
    input.disabled = true;
    try {
      await api(`/api/backends/toggle?backend_id=${encodeURIComponent(id)}&enabled=${enabled}`, { method: "POST" });
      toast(`Backend ${enabled ? "enabled" : "disabled"}.`);
      await loadBackends();
    } catch (error) {
      toast(error.message, "error");
      input.checked = !enabled;
    } finally {
      input.disabled = false;
    }
  }

  async function testAllBackends() {
    const button = $("#btn-test-all-backends");
    setBusy(button, true, "Testing");
    try {
      const data = await api("/api/backends/health", { method: "POST" });
      const results = data.results || [];
      const reachable = results.filter((result) => result.reachable).length;
      toast(`${reachable} of ${results.length} backends reachable.`, reachable === results.length ? "success" : "warn");
      await loadBackends();
    } catch (error) {
      toast(error.message, "error");
    } finally {
      setBusy(button, false);
    }
  }

  async function loadAnalytics() {
    const data = await api("/api/analytics/metrics");
    const summary = data.summary || {};
    $("#stat-logical").textContent = formatBytes(summary.total_logical_bytes);
    $("#stat-physical").textContent = formatBytes(summary.total_physical_bytes);
    $("#stat-files").textContent = formatNumber(summary.total_files);
    $("#stat-dedup").textContent = `${Number(summary.dedup_ratio || 1).toFixed(2)}×`;
    renderTierAnalytics(data.tier_distribution || []);
    renderBackendUsage(data.backend_usage || []);
    renderUploadHistory(data.upload_history || []);
  }

  function renderTierAnalytics(tiers) {
    const total = tiers.reduce((sum, tier) => sum + (Number(tier.bytes) || 0), 0);
    $("#donut-total").textContent = formatBytes(total);
    const donut = $("#storage-donut");
    if (total === 0) {
      donut.style.background = "var(--line)";
    } else {
      let cursor = 0;
      const segments = tiers
        .filter((tier) => Number(tier.bytes) > 0)
        .map((tier) => {
          const start = cursor;
          cursor += (Number(tier.bytes) / total) * 360;
          return `${TIER_COLORS[tier.tier] || "var(--accent)"} ${start}deg ${cursor}deg`;
        });
      donut.style.background = `conic-gradient(${segments.join(", ")})`;
    }
    $("#tier-bars").innerHTML = tiers
      .map((tier) => {
        const bytes = Number(tier.bytes) || 0;
        const percent = total > 0 ? (bytes / total) * 100 : 0;
        return `<div class="bar-item">
          <div class="bar-item-head"><span><i class="swatch" style="background:${TIER_COLORS[tier.tier] || "var(--accent)"}"></i>${esc(tier.tier)} · ${esc(tier.redundancy)}</span><strong>${formatBytes(bytes)}</strong></div>
          <div class="progress"><span style="width:${percent}%;background:${TIER_COLORS[tier.tier] || "var(--accent)"}"></span></div>
          <div class="bar-item-head"><span>${formatNumber(tier.files)} file${Number(tier.files) === 1 ? "" : "s"}</span><span>${formatPercent(percent)}</span></div>
        </div>`;
      })
      .join("");
  }

  function renderBackendUsage(backends) {
    if (!backends.length) {
      $("#backend-usage").innerHTML = `<div class="empty-state small"><p>No backend usage recorded.</p></div>`;
      return;
    }
    $("#backend-usage").innerHTML = backends
      .map((backend) => {
        const share = Number(backend.share_percent) || 0;
        return `<div class="bar-item">
          <div class="bar-item-head"><span>${esc(backend.provider)}</span><strong>${formatBytes(backend.stored_bytes)}</strong></div>
          <div class="progress"><span style="width:${clamp(share, 0, 100)}%"></span></div>
          <div class="bar-item-head"><span>${formatPercent(share)} of stored data</span><span>${backend.quota_bytes ? `cap ${formatBytes(backend.quota_bytes)}` : "no cap"}</span></div>
        </div>`;
      })
      .join("");
  }

  function renderUploadHistory(history) {
    const body = $("#upload-history-body");
    const table = body.closest("table");
    const empty = $("#history-empty");
    table.classList.toggle("hidden", history.length === 0);
    empty.classList.toggle("hidden", history.length > 0);
    body.innerHTML = history
      .map(
        (entry) => `<tr>
          <td>${esc(entry.month || "—")}</td>
          <td>${formatBytes(entry.total_bytes)}</td>
          <td><span class="tier-badge tier-IMPORTANT">Successful</span></td>
        </tr>`
      )
      .join("");
  }

  async function loadHealth() {
    const data = await api("/api/resilience/status");
    state.healthRunning = Boolean(data.scrub_running);
    const score = Number(data.health_score_percent) || 0;
    const total = Number(data.total_chunks_scanned) || 0;
    $("#health-score").textContent = `${score.toFixed(1)}%`;
    $("#health-chunks").textContent = formatNumber(total);
    $("#health-verified").textContent = formatNumber(data.verified_chunks);
    $("#health-corrupted").textContent = formatNumber(data.corrupted_chunks);
    $("#health-missing").textContent = formatNumber(data.missing_mirrors);
    const ring = $("#health-ring");
    ring.style.setProperty("--value", `${clamp(score, 0, 100) * 3.6}deg`);
    ring.style.setProperty("--ring-color", score >= 95 ? "var(--accent)" : score >= 75 ? "var(--warn)" : "var(--danger)");
    $("#health-label").textContent =
      total === 0 ? "No chunks indexed" : score >= 95 ? "Fully replicated" : score >= 75 ? "Degraded redundancy" : "Attention required";
    const scrubDot = $("#scrub-dot");
    scrubDot.className = `status-dot ${state.healthRunning ? "warn" : data.last_scrub_timestamp ? "ok" : ""}`;
    $("#scrub-status").textContent = state.healthRunning ? "Scrub running" : "Idle";
    $("#last-scrub").textContent = data.last_scrub_timestamp
      ? `Last completed ${formatDate(data.last_scrub_timestamp)} at ${formatTime(data.last_scrub_timestamp)}.`
      : "No scrub has run yet.";
    $("#scrub-log").textContent = (data.recent_scrub_logs || []).join("\n") || "No scrub log entries.";
    renderIntegrityEvents(data.recent_integrity_events || []);
    renderDurability(data.worst_case || {});
    loadProtection().catch((error) => toast(error.message, "error"));
  }

  function renderDurability(worstCase) {
    const stateName = String(worstCase.state || "UNKNOWN").toUpperCase();
    const badge = $("#durability-state");
    badge.textContent = stateName;
    badge.className = `pill durability-state state-${stateName.toLowerCase()}`;
    $("#durability-summary").textContent = worstCase.summary || "Worst-case readiness is unknown.";

    const domainCount = Number(worstCase.failure_domain_count) || 0;
    const required = Number(worstCase.contract?.required_domain_losses) || 0;
    const survivable = worstCase.minimum_survivable_domain_losses === null
      || worstCase.minimum_survivable_domain_losses === undefined
      ? null
      : Number(worstCase.minimum_survivable_domain_losses);
    $("#durability-domains").textContent = formatNumber(domainCount);
    $("#durability-protected").textContent = formatNumber(worstCase.protected_chunks || 0);
    $("#durability-at-risk").textContent = formatNumber(
      (Number(worstCase.at_risk_chunks) || 0) + (Number(worstCase.unprotected_chunks) || 0)
    );
    $("#durability-survivable").textContent = survivable === null
      ? "-"
      : `${formatNumber(survivable)} / ${formatNumber(required)}`;

    const findings = Array.isArray(worstCase.findings) ? worstCase.findings : [];
    $("#durability-findings").innerHTML = findings
      .map((finding) => `<li>${esc(finding)}</li>`)
      .join("") || "<li>No findings.</li>";

    const metadata = worstCase.metadata || {};
    const metadataLabel = metadata.status === "ok"
      ? `fresh (${formatNumber(metadata.snapshot_count || 0)} snapshot${Number(metadata.snapshot_count) === 1 ? "" : "s"})`
      : metadata.status === "stale" ? "stale" : "missing";
    const proof = worstCase.restore_proof || {};
    const proofLabel = proof.ok
      ? `passed ${proof.completed_at ? formatDate(proof.completed_at) : ""}`.trim()
      : proof.result === "failed" ? "failed" : "missing";
    const recoveryLabel = worstCase.recovery?.ok ? "confirmed" : "not confirmed";
    const offsiteLabel = worstCase.offsite_ok ? "present" : "not configured";
    $("#durability-meta").textContent =
      `Metadata backup: ${metadataLabel} (${formatNumber(metadata.copy_count || 0)} remote cop${Number(metadata.copy_count) === 1 ? "y" : "ies"}, ${formatNumber(metadata.copy_failure_domains || 0)} domain${Number(metadata.copy_failure_domains) === 1 ? "" : "s"}). Restore proof: ${proofLabel}. Recovery phrase: ${recoveryLabel}. Offsite provider: ${offsiteLabel}.`;

    $("#durability-required").value = String(Math.min(2, Math.max(0, required)));
    $("#durability-offsite").checked = Boolean(worstCase.contract?.requires_offsite);
    $("#durability-restore-proof").checked = Boolean(worstCase.contract?.requires_restore_proof);
    const preset = worstCase.contract?.preset || "";
    $("#durability-preset").value = ["basic", "safe", "paranoid"].includes(preset) ? preset : "";
    renderWhatIfDomains(worstCase);
    const recoveryButton = $("#btn-confirm-recovery");
    recoveryButton.disabled = Boolean(worstCase.recovery?.ok);
    recoveryButton.textContent = worstCase.recovery?.ok ? "Recovery phrase confirmed" : "Recovery phrase saved";
  }

  async function saveDurabilityContract() {
    const button = $("#btn-save-durability");
    setBusy(button, true, "Saving");
    try {
      await api("/api/resilience/contract", {
        method: "POST",
        body: {
          required_domain_losses: Number($("#durability-required").value) || 0,
          requires_offsite: $("#durability-offsite").checked,
          requires_restore_proof: $("#durability-restore-proof").checked,
          preset: $("#durability-preset").value || null,
        },
      });
      toast("Durability contract updated.");
      await loadHealth();
    } catch (error) {
      toast(error.message, "error");
    } finally {
      setBusy(button, false);
    }
  }

  async function confirmRecoverySaved() {
    try {
      await api("/api/resilience/recovery/confirm", { method: "POST" });
      toast("Recovery phrase confirmation recorded.");
      await loadHealth();
    } catch (error) {
      toast(error.message, "error");
    }
  }

  function applyDurabilityPreset() {
    const preset = $("#durability-preset").value;
    if (!preset) return;
    const values = {
      basic: { losses: 1, offsite: false, proof: false },
      safe: { losses: 2, offsite: false, proof: false },
      paranoid: { losses: 2, offsite: true, proof: true },
    }[preset];
    if (!values) return;
    $("#durability-required").value = String(values.losses);
    $("#durability-offsite").checked = values.offsite;
    $("#durability-restore-proof").checked = values.proof;
  }

  function renderWhatIfDomains(worstCase) {
    const container = $("#what-if-domains");
    if (!container) return;
    const domains = Array.isArray(worstCase.configured_failure_domains)
      ? worstCase.configured_failure_domains
      : [];
    const checked = new Set(
      $$("#what-if-domains input[type='checkbox']:checked").map((input) => input.value)
    );
    if (!domains.length) {
      container.innerHTML = `<p class="what-if-empty">Configure a storage backend to simulate failure domains.</p>`;
      return;
    }
    const counts = worstCase.domain_shard_counts || {};
    container.innerHTML = domains.map((domain) => {
      const count = Number(counts[domain.id] || 0);
      return `<label class="domain-toggle">
        <input type="checkbox" value="${esc(domain.id)}"${checked.has(domain.id) ? " checked" : ""}>
        <span><strong>${esc(domain.label || domain.id)}</strong><small>${esc(domain.kind || "domain")} &middot; ${formatNumber(count)} shard${count === 1 ? "" : "s"}</small></span>
      </label>`;
    }).join("");
  }

  function resetWhatIfResult() {
    const badge = $("#what-if-state");
    badge.textContent = "IDLE";
    badge.className = "pill durability-state";
    $("#what-if-result").textContent = "Choose one or more independent domains to see which chunks survive.";
  }

  async function simulateDomainLoss() {
    const selected = $$("#what-if-domains input[type='checkbox']:checked").map((input) => input.value);
    if (!selected.length) {
      toast("Select at least one failure domain.", "error");
      return;
    }
    const button = $("#btn-what-if");
    setBusy(button, true, "Simulating");
    try {
      const result = await api("/api/resilience/what-if", {
        method: "POST",
        body: { lost_domain_ids: selected },
      });
      const badge = $("#what-if-state");
      badge.textContent = String(result.state || "UNKNOWN").toUpperCase();
      badge.className = `pill durability-state state-${String(result.state || "unknown").toLowerCase()}`;
      $("#what-if-result").textContent =
        `${result.summary} Affected files: ${formatNumber(result.affected_files)} (${formatBytes(result.affected_bytes)}). ` +
        `Unreadable chunks: ${formatNumber(result.unreadable_chunks)}; below contract: ${formatNumber(result.below_contract_chunks)}; unaffected: ${formatNumber(result.unaffected_chunks)}.`;
    } catch (error) {
      toast(error.message, "error");
    } finally {
      setBusy(button, false);
    }
  }

  async function createIndexSnapshot() {
    const button = $("#btn-create-snapshot");
    setBusy(button, true, "Snapshotting");
    try {
      const result = await api("/api/resilience/snapshots", { method: "POST", body: {} });
      toast(`Index snapshot written to ${result.confirmed_copies} cop${result.confirmed_copies === 1 ? "y" : "ies"} across ${result.failure_domains} domain${result.failure_domains === 1 ? "" : "s"}.`);
      await loadHealth();
    } catch (error) {
      toast(error.message, "error");
    } finally {
      setBusy(button, false);
    }
  }

  async function runRestoreDrill() {
    const button = $("#btn-run-drill");
    setBusy(button, true, "Restoring");
    try {
      const result = await api("/api/resilience/drill", { method: "POST" });
      toast(
        result.result === "passed"
          ? `Restore drill passed: ${result.detail}`
          : `Restore drill failed: ${result.detail}`,
        result.result === "passed" ? "success" : "error"
      );
      await loadHealth();
    } catch (error) {
      toast(error.message, "error");
    } finally {
      setBusy(button, false);
    }
  }

  async function evacuateAtRisk() {
    const button = $("#btn-evacuate");
    setBusy(button, true, "Evacuating");
    try {
      const result = await api("/api/resilience/evacuate", { method: "POST" });
      toast(
        `Evacuation examined ${result.examined} chunk${result.examined === 1 ? "" : "s"} and repaired ${result.repaired_chunks} (${result.repaired_shards} shards, ${result.failures} failures).`,
        result.failures ? "warn" : "success"
      );
      await loadHealth();
    } catch (error) {
      toast(error.message, "error");
    } finally {
      setBusy(button, false);
    }
  }

  async function loadProtection() {
    const data = await api("/api/protection/sets");
    const summary = data.summary || {};
    $("#protection-summary").textContent =
      `${formatNumber(summary.count || 0)} set${Number(summary.count) === 1 ? "" : "s"}, ` +
      `${formatNumber(summary.enabled || 0)} enabled, ${formatNumber(summary.files || 0)} mirrored files ` +
      `(${formatBytes(summary.bytes || 0)}).`;
    const sets = Array.isArray(data.sets) ? data.sets : [];
    const list = $("#protection-list");
    if (!sets.length) {
      list.innerHTML = `<p class="protection-empty">No protection sets yet. Add a local folder below to mirror it on every scan.</p>`;
      return;
    }
    list.innerHTML = sets.map((item) => {
      const paused = !item.enabled;
      const status = item.last_error
        ? `<span class="bad">${esc(item.last_error)}</span>`
        : item.last_sync_at ? `Synced ${formatDate(item.last_sync_at)}` : "Not synced yet";
      return `<div class="protection-card${paused ? " paused" : ""}">
        <div class="protection-card-main">
          <div class="protection-card-head">
            <strong>${esc(item.name)}</strong>
            <span class="pill">${esc(item.tier)}</span>
            ${paused ? '<span class="pill">PAUSED</span>' : ""}
          </div>
          <code title="${esc(item.source_path)}">${esc(item.source_path)} &rarr; ${esc(item.destination_path)}</code>
          <div class="protection-card-meta">
            <span>${formatNumber(item.file_count || 0)} files</span>
            <span>${formatBytes(item.total_bytes || 0)}</span>
            <span>${status}</span>
          </div>
        </div>
        <div class="protection-card-actions">
          <button class="btn btn-secondary btn-sm" data-protection-action="scan" data-id="${esc(item.id)}" type="button">Scan</button>
          <button class="btn btn-ghost btn-sm" data-protection-action="toggle" data-id="${esc(item.id)}" data-enabled="${item.enabled ? "0" : "1"}" type="button">${paused ? "Resume" : "Pause"}</button>
          <button class="btn btn-ghost btn-sm" data-protection-action="delete" data-id="${esc(item.id)}" type="button">Delete</button>
        </div>
      </div>`;
    }).join("");
  }

  async function addProtectionSet() {
    const source = $("#protection-source").value.trim();
    if (!source) {
      toast("Enter a local folder path.", "error");
      return;
    }
    const button = $("#btn-add-protection");
    setBusy(button, true, "Adding");
    try {
      const created = await api("/api/protection/sets", {
        method: "POST",
        body: {
          name: $("#protection-name").value.trim(),
          source_path: source,
          destination_path: $("#protection-destination").value.trim() || "/",
          tier: $("#protection-tier").value,
        },
      });
      $("#protection-name").value = "";
      $("#protection-source").value = "";
      toast("Protection set added. Scanning now.");
      await loadProtection();
      await api(`/api/protection/sets/${encodeURIComponent(created.set.id)}/scan`, {
        method: "POST",
        body: { max_files: 200 },
      });
      toast("Protection set mirrored.");
      await loadHealth();
    } catch (error) {
      toast(error.message, "error");
    } finally {
      setBusy(button, false);
    }
  }

  async function scanAllProtection() {
    const button = $("#btn-scan-protection");
    setBusy(button, true, "Scanning");
    try {
      const result = await api("/api/protection/scan-all", {
        method: "POST",
        body: { max_files: 200 },
      });
      toast(
        `Protection scan: ${result.uploaded} uploaded, ${result.failed} failed across ${result.sets} set${result.sets === 1 ? "" : "s"}.`,
        result.failed ? "warn" : "success"
      );
      await loadHealth();
    } catch (error) {
      toast(error.message, "error");
    } finally {
      setBusy(button, false);
    }
  }

  async function handleProtectionAction(event) {
    const button = event.target.closest("[data-protection-action]");
    if (!button) return;
    const set_id = button.dataset.id;
    const action = button.dataset.protectionAction;
    if (action === "delete") {
      const confirmed = await confirmAction(
        "Delete protection set?",
        "The watch entry is removed. Files already mirrored into the vault stay until you delete them.",
        "Delete set"
      );
      if (!confirmed) return;
      try {
        await api(`/api/protection/sets/${encodeURIComponent(set_id)}`, { method: "DELETE" });
        toast("Protection set deleted.");
        await loadProtection();
      } catch (error) {
        toast(error.message, "error");
      }
      return;
    }
    setBusy(button, true, action === "scan" ? "Scanning" : "Saving");
    try {
      if (action === "scan") {
        const result = await api(`/api/protection/sets/${encodeURIComponent(set_id)}/scan`, {
          method: "POST",
          body: { max_files: 200 },
        });
        toast(`Scanned: ${result.uploaded} uploaded, ${result.unchanged} unchanged, ${result.failed} failed.`, result.failed ? "warn" : "success");
        await loadHealth();
      } else if (action === "toggle") {
        const enabled = button.dataset.enabled === "1";
        await api(`/api/protection/sets/${encodeURIComponent(set_id)}`, {
          method: "PUT",
          body: { enabled },
        });
        toast(enabled ? "Protection set resumed." : "Protection set paused.");
        await loadProtection();
      }
    } catch (error) {
      toast(error.message, "error");
    } finally {
      setBusy(button, false);
    }
  }

  function renderIntegrityEvents(events) {
    if (!events.length) {
      $("#integrity-events").innerHTML = `<div class="event-row"><span>No integrity events yet.</span><time>—</time></div>`;
      return;
    }
    $("#integrity-events").innerHTML = events
      .map(
        (event) => `<div class="event-row">
          <span title="${esc(event.chunk_id)}"><span class="${event.result === "ok" ? "ok" : "bad"}">${esc(event.result)}</span> · ${esc(event.filename || event.chunk_id)}</span>
          <time>${formatDate(event.checked_at)}</time>
        </div>`
      )
      .join("");
  }

  async function runScrub() {
    const button = $("#btn-run-scrub");
    setBusy(button, true, "Starting");
    try {
      const result = await api("/api/resilience/scrub/start", {
        method: "POST",
        body: { tier: "ALL", auto_repair: true },
      });
      toast(result.message, result.status === "running" ? "warn" : "success");
      $("#scrub-status").textContent = "Scrub running";
      $("#scrub-dot").className = "status-dot warn";
      window.clearTimeout(state.scrubTimer);
      state.scrubTimer = window.setTimeout(pollScrub, 1500);
    } catch (error) {
      toast(error.message, "error");
    } finally {
      setBusy(button, false);
    }
  }

  async function pollScrub() {
    try {
      const data = await api("/api/resilience/status");
      if (data.scrub_running && state.unlocked) {
        state.scrubTimer = window.setTimeout(pollScrub, 2200);
        if (state.view === "health") {
          $("#scrub-status").textContent = "Scrub running";
          $("#scrub-dot").className = "status-dot warn";
        }
      } else {
        await loadHealth();
        toast("Integrity scrub finished.");
      }
    } catch (error) {
      toast(error.message, "error");
    }
  }

  async function loadSmart() {
    const data = await api("/api/smart/config");
    state.smart = data;
    $("#smart-background-sync").checked = Boolean(data.background_sync);
    $("#smart-auto-tier").checked = Boolean(data.auto_tiering_enabled);
    $("#smart-tier-days").value = data.auto_tiering_days_unused;
    $("#smart-thermal").checked = Boolean(data.thermal_throttling_enabled);
    $("#smart-cpu-cap").value = data.max_cpu_percent_cap;
    $("#smart-bandwidth").value = data.bandwidth_limit_kbps;
    $("#smart-battery").checked = Boolean(data.battery_saver_pause);
    renderThermal(data.thermal_state || {});
  }

  function renderThermal(thermal) {
    const cpu = Number(thermal.cpu_usage_percent) || 0;
    const temperature = thermal.temperature_available ? Number(thermal.cpu_temp_celsius) : null;
    $("#thermal-cpu").textContent = `${cpu.toFixed(1)}%`;
    $("#thermal-temp").textContent = temperature === null ? "Unavailable" : `${temperature.toFixed(1)} °C`;
    $("#thermal-state").textContent = thermal.throttling_active ? "Throttling" : "Nominal";
    $("#thermal-backpressure").textContent = `${Number(thermal.current_backpressure_factor || 1).toFixed(2)}×`;
    const notice = $("#thermal-notice");
    if (thermal.throttling_active) {
      notice.textContent = "Thermal backpressure is active. Transfers are being slowed to protect the machine.";
    } else if (thermal.battery_paused) {
      notice.textContent = "Battery saver is limiting background activity.";
    } else {
      notice.textContent = "No thermal or battery pressure detected. Transfers run at full speed.";
    }
  }

  async function saveSmart() {
    const button = $("#btn-save-smart");
    setBusy(button, true, "Saving");
    try {
      const result = await api("/api/smart/config", {
        method: "POST",
        body: {
          background_sync: $("#smart-background-sync").checked,
          auto_tiering_enabled: $("#smart-auto-tier").checked,
          auto_tiering_days_unused: Number($("#smart-tier-days").value) || 30,
          thermal_throttling_enabled: $("#smart-thermal").checked,
          max_cpu_percent_cap: Number($("#smart-cpu-cap").value) || 80,
          bandwidth_limit_kbps: Number($("#smart-bandwidth").value) || 0,
          battery_saver_pause: $("#smart-battery").checked,
        },
      });
      state.smart = result.config;
      renderThermal(result.thermal_state || {});
      toast(result.message || "Smart engine updated.");
    } catch (error) {
      toast(error.message, "error");
    } finally {
      setBusy(button, false);
    }
  }

  async function loadVault() {
    await Promise.all([loadSecrets(), loadPostQuantum()]);
  }

  async function loadSecrets() {
    const data = await api("/api/secrets/vault");
    state.secrets = Array.isArray(data.secrets) ? data.secrets : [];
    renderSecrets();
  }

  function renderSecrets() {
    const body = $("#secrets-body");
    const table = body.closest("table");
    const empty = $("#secrets-empty");
    table.classList.toggle("hidden", state.secrets.length === 0);
    empty.classList.toggle("hidden", state.secrets.length > 0);
    body.innerHTML = state.secrets
      .map(
        (secret) => `<tr>
          <td><span class="file-name">${esc(secret.label)}</span><span class="file-meta">${esc(secret.id)}</span></td>
          <td><span class="tier-badge tier-neutral">${esc(kindLabel(secret.kind))}</span></td>
          <td class="hide-sm">${formatDate(secret.created_at)}</td>
          <td>
            <div class="row-actions">
              <button class="row-button" data-secret-action="reveal" data-id="${esc(secret.id)}" title="Reveal payload" aria-label="Reveal payload">${icon("eye")}</button>
              <button class="row-button danger" data-secret-action="delete" data-id="${esc(secret.id)}" title="Delete secret" aria-label="Delete secret">${icon("trash")}</button>
            </div>
          </td>
        </tr>`
      )
      .join("");
  }

  function openSecretModal() {
    $("#secret-form").reset();
    $("#secret-payload").value = "";
    clearError("secret-error");
    openModal("secret-modal");
  }

  async function saveSecret(event) {
    event.preventDefault();
    clearError("secret-error");
    const label = $("#secret-label").value.trim();
    if (!label) return showError("secret-error", "Enter a label.");
    let payload = {};
    const raw = $("#secret-payload").value.trim();
    if (raw) {
      try {
        payload = JSON.parse(raw);
      } catch (_) {
        return showError("secret-error", "Payload must be valid JSON.");
      }
      if (typeof payload !== "object" || Array.isArray(payload) || payload === null) {
        return showError("secret-error", "Payload must be a JSON object.");
      }
    }
    const button = $("#btn-secret-save");
    setBusy(button, true, "Encrypting");
    try {
      await api("/api/secrets/vault", {
        method: "POST",
        body: { label, kind: $("#secret-kind").value, payload },
      });
      closeModal("secret-modal");
      toast("Secret encrypted and stored.");
      await loadSecrets();
    } catch (error) {
      showError("secret-error", error.message);
    } finally {
      setBusy(button, false);
    }
  }

  async function handleSecretAction(event) {
    const button = event.target.closest("[data-secret-action]");
    if (!button) return;
    const secret = state.secrets.find((item) => item.id === button.dataset.id);
    if (!secret) return;
    if (button.dataset.secretAction === "reveal") {
      try {
        const detail = await api(`/api/secrets/vault/${encodeURIComponent(secret.id)}`);
        state.secretPayload = JSON.stringify(detail.payload || {}, null, 2);
        openDrawer(secret.label, "Encrypted vault");
        $("#detail-content").innerHTML = `
          <div class="detail-meta">
            <div><span>Kind</span><strong>${esc(kindLabel(detail.kind))}</strong></div>
            <div><span>Created</span><strong>${formatDate(detail.created_at)}</strong></div>
          </div>
          <div class="detail-section">
            <h3>Decrypted payload</h3>
            <pre class="hash">${esc(state.secretPayload)}</pre>
            <button class="btn btn-secondary btn-sm" data-detail-action="copy-secret" data-file-id="${esc(secret.id)}" style="margin-top:10px">${icon("copy")} Copy payload</button>
          </div>`;
      } catch (error) {
        toast(error.message, "error");
      }
    }
    if (button.dataset.secretAction === "delete") {
      const confirmed = await confirmAction("Delete secret?", `“${secret.label}” will be removed from the encrypted vault.`, "Delete secret");
      if (!confirmed) return;
      try {
        await api(`/api/secrets/vault/${encodeURIComponent(secret.id)}`, { method: "DELETE" });
        toast("Secret deleted.");
        await loadSecrets();
      } catch (error) {
        toast(error.message, "error");
      }
    }
  }

  function openRevealModal() {
    $("#reveal-form").reset();
    $("#reveal-result").classList.add("hidden");
    $("#reveal-words").innerHTML = "";
    clearError("reveal-error");
    openModal("reveal-modal");
  }

  async function revealSeed(event) {
    event.preventDefault();
    clearError("reveal-error");
    const button = $("#btn-reveal");
    setBusy(button, true, "Decrypting");
    try {
      const data = await api("/api/secrets/reveal-seed", {
        method: "POST",
        body: { passphrase: $("#reveal-passphrase").value },
      });
      const words = String(data.seed_phrase || "").split(/\s+/).filter(Boolean);
      $("#reveal-words").innerHTML = words
        .map((word, index) => `<div class="seed-word"><span>${index + 1}</span>${esc(word)}</div>`)
        .join("");
      $("#reveal-result").classList.remove("hidden");
      $("#reveal-passphrase").value = "";
    } catch (error) {
      showError("reveal-error", error.message);
    } finally {
      setBusy(button, false);
    }
  }

  async function changePassphrase(event) {
    event.preventDefault();
    const current = $("#change-pass-current").value;
    const next = $("#change-pass-new").value;
    if (!current || !next) {
      toast("Enter the current and new passphrase.", "warn");
      return;
    }
    const button = $("#btn-change-pass");
    setBusy(button, true, "Updating");
    try {
      await api("/api/secrets/change-passphrase", {
        method: "POST",
        body: { current_passphrase: current, new_passphrase: next },
      });
      $("#change-pass-current").value = "";
      $("#change-pass-new").value = "";
      toast("Master passphrase updated.");
    } catch (error) {
      toast(error.message, "error");
    } finally {
      setBusy(button, false);
    }
  }

  async function loadPostQuantum() {
    try {
      const data = await api("/api/secrets/post-quantum-status");
      $("#pq-mode").textContent = data.mode;
      const dot = $("#pq-status-dot");
      dot.className = `status-dot ${data.post_quantum_shield_active ? "ok" : "warn"}`;
      $("#pq-status-text").textContent = data.post_quantum_shield_active ? "Shield active" : "Classical mode";
    } catch (error) {
      $("#pq-mode").textContent = "Unavailable";
      $("#pq-status-dot").className = "status-dot error";
      $("#pq-status-text").textContent = "Check failed";
    }
  }

  async function loadRecovery() {
    const [recovery, portable, inheritance] = await Promise.all([
      api("/api/recovery/status"),
      api("/api/portable/status"),
      api("/api/inheritance/status").catch(() => null),
    ]);
    state.recoveryStatus = recovery;
    state.portableStatus = portable;
    state.inheritanceStatus = inheritance;
    renderRecoveryStatus();
    if (inheritance) renderInheritance(inheritance);
  }

  function renderRecoveryStatus() {
    const recovery = state.recoveryStatus;
    const portable = state.portableStatus;
    if (recovery) {
      const unlocked = Boolean(recovery.unlocked);
      $("#recovery-ratio").textContent = `${recovery.threshold}-of-${recovery.total}`;
      $("#recovery-threshold-summary").textContent = `Any ${recovery.threshold} of ${recovery.total} shares`;
      $("#recovery-kit-pill").textContent = unlocked ? "UNLOCKED" : "LOCKED";
      $("#recovery-lock-dot").className = `status-dot ${unlocked ? "ok" : "warn"}`;
      $("#recovery-lock-text").textContent = unlocked ? "Unlocked" : "Locked";
      $("#btn-export-kit").disabled = !unlocked;
      $("#recovery-export-note").textContent = unlocked
        ? "Downloads one .gdshare file per share plus a manifest."
        : "Unlock the vault to export a recovery kit.";
      if (recovery.offline_tool) $("#recovery-offline-tool").textContent = recovery.offline_tool;
    }
    if (portable) {
      const unlocked = Boolean(portable.unlocked);
      $("#portable-pill").textContent = unlocked ? "UNLOCKED" : "LOCKED";
      $("#portable-format").textContent = `${portable.format} · ${portable.extension}`;
      $("#btn-export-vault").disabled = !unlocked;
      $("#portable-export-note").textContent = unlocked
        ? "The archive is sealed with the passphrase you enter."
        : "Unlock the vault to export a portable archive.";
    }
  }

  async function exportRecoveryKit(event) {
    event.preventDefault();
    const threshold = Number($("#recovery-threshold").value) || 3;
    const total = Number($("#recovery-total").value) || 5;
    const label = $("#recovery-kit-label").value.trim();
    const button = $("#btn-export-kit");
    setBusy(button, true, "Exporting");
    try {
      const data = await api("/api/recovery/kit/export", {
        method: "POST",
        body: { threshold, total, label },
      });
      const files = (data.shares || []).map((text, index) => ({
        name: (data.filenames || [])[index] || `ghostdrive-share-${index + 1}-of-${total}.gdshare`,
        content: text,
        type: "text/plain",
      }));
      files.push({
        name: "ghostdrive-recovery-kit.json",
        content: JSON.stringify({ manifest: data.manifest, download_hint: data.download_hint }, null, 2),
        type: "application/json",
      });
      // Stagger the downloads — browsers block rapid multiple automatic ones.
      files.forEach((file, index) => {
        window.setTimeout(() => downloadBlob(file.name, file.content, file.type), index * 350);
      });
      toast(data.download_hint || "Recovery kit exported.");
    } catch (error) {
      toast(error.message, "error");
    } finally {
      setBusy(button, false);
      renderRecoveryStatus();
    }
  }

  function parseShares(raw) {
    // Split pasted text at every GDSHARE1: prefix; each part is one share
    // (the decoder tolerates line wrapping inside a share).
    return String(raw || "")
      .split(/(?=GDSHARE1:)/)
      .map((part) => part.trim())
      .filter((part) => part.startsWith("GDSHARE1:"));
  }

  function scheduleSharePreview() {
    window.clearTimeout(state.recoveryPreviewTimer);
    state.recoveryPreviewTimer = window.setTimeout(previewShares, 300);
  }

  async function previewShares() {
    const shares = parseShares($("#recovery-shares-input").value);
    const status = $("#recovery-preview-status");
    if (!shares.length) {
      status.className = "muted recovery-preview";
      status.textContent = "Paste shares to validate them.";
      return;
    }
    try {
      const data = await api("/api/recovery/kit/preview", { method: "POST", body: { shares } });
      const summary = data.summary || {};
      const provided = summary.provided || 0;
      const threshold = summary.threshold || "?";
      const errors = data.errors || [];
      if (data.ready) {
        status.className = "recovery-preview ready";
        status.textContent = `${provided} of ${threshold} shares valid — ready to restore.`;
      } else if (errors.length) {
        status.className = "recovery-preview bad";
        status.textContent = `${provided} valid, ${errors.length} rejected — ${errors[0]}`;
      } else {
        status.className = "recovery-preview warn";
        status.textContent = `${provided} of ${threshold} shares valid — ${data.missing} more needed.`;
      }
    } catch (error) {
      status.className = "recovery-preview bad";
      status.textContent = error.message;
    }
  }

  async function restoreFromShares(event) {
    event.preventDefault();
    clearError("recovery-restore-error");
    const shares = parseShares($("#recovery-shares-input").value);
    if (!shares.length) {
      showError("recovery-restore-error", "Paste at least one key share.");
      return;
    }
    const passphrase = $("#recovery-restore-passphrase").value;
    if (!passphrase) {
      showError("recovery-restore-error", "Enter a new passphrase for the restored vault.");
      return;
    }
    const button = $("#btn-restore-kit");
    setBusy(button, true, "Restoring");
    try {
      // Raw fetch so the 409 (already unlocked) path can be special-cased.
      const response = await fetch("/api/recovery/kit/combine", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ shares, passphrase }),
      });
      const payload = await response.json().catch(() => null);
      if (response.status === 409) {
        showError(
          "recovery-restore-error",
          `${(payload && payload.detail) || "Vault is already unlocked."} Use Lock vault in the sidebar, then restore again.`
        );
        return;
      }
      if (!response.ok) {
        throw new Error((payload && payload.detail) || `Restore failed (${response.status}).`);
      }
      $("#recovery-shares-input").value = "";
      $("#recovery-restore-passphrase").value = "";
      toast((payload && payload.message) || "Vault restored from key shares and unlocked.");
      await loadRecovery();
    } catch (error) {
      showError("recovery-restore-error", error.message);
    } finally {
      setBusy(button, false);
    }
  }

  async function exportPortableVault(event) {
    event.preventDefault();
    const passphrase = $("#portable-export-passphrase").value;
    if (!passphrase) {
      toast("Enter an archive passphrase.", "warn");
      return;
    }
    const button = $("#btn-export-vault");
    setBusy(button, true, "Packaging");
    try {
      const response = await fetch("/api/portable/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          passphrase,
          include_index: $("#portable-include-index").checked,
          label: "",
        }),
      });
      if (!response.ok) {
        let payload = null;
        try {
          payload = await response.json();
        } catch (_) {}
        throw new Error((payload && payload.detail) || `Export failed (${response.status}).`);
      }
      const blob = await response.blob();
      downloadBlob("ghostdrive-vault.gdvault", blob);
      $("#portable-export-passphrase").value = "";
      toast("Portable vault exported.");
    } catch (error) {
      toast(error.message, "error");
    } finally {
      setBusy(button, false);
      renderRecoveryStatus();
    }
  }

  async function inspectPortableVault() {
    clearError("portable-import-error");
    const result = $("#portable-inspect-result");
    result.classList.add("hidden");
    const file = $("#portable-import-file").files && $("#portable-import-file").files[0];
    if (!file) {
      showError("portable-import-error", "Choose a .gdvault file to check.");
      return;
    }
    const passphrase = $("#portable-import-passphrase").value;
    if (!passphrase) {
      showError("portable-import-error", "Enter the archive passphrase.");
      return;
    }
    const form = new FormData();
    form.append("file", file);
    const params = new URLSearchParams({ passphrase });
    const button = $("#btn-inspect-vault");
    setBusy(button, true, "Checking");
    try {
      const data = await api(`/api/portable/inspect?${params}`, { method: "POST", body: form });
      const created = data.created_at ? formatDate(data.created_at) : "unknown date";
      const members = Array.isArray(data.members) ? data.members.length : 0;
      result.textContent = `${file.name} — created ${created}${data.label ? `, label “${data.label}”` : ""}, ${members} member${members === 1 ? "" : "s"}${data.has_snapshot ? ", index snapshot included" : ""}.`;
      result.classList.remove("hidden");
    } catch (error) {
      showError("portable-import-error", error.message);
    } finally {
      setBusy(button, false);
    }
  }

  async function importPortableVault(event) {
    event.preventDefault();
    clearError("portable-import-error");
    const file = $("#portable-import-file").files && $("#portable-import-file").files[0];
    if (!file) {
      showError("portable-import-error", "Choose a .gdvault file to import.");
      return;
    }
    const passphrase = $("#portable-import-passphrase").value;
    if (!passphrase) {
      showError("portable-import-error", "Enter the archive passphrase.");
      return;
    }
    const form = new FormData();
    form.append("file", file);
    const params = new URLSearchParams({
      passphrase,
      restore_index: $("#portable-restore-index").checked ? "true" : "false",
    });
    const button = $("#btn-import-vault");
    setBusy(button, true, "Importing");
    try {
      const data = await api(`/api/portable/import?${params}`, { method: "POST", body: form });
      $("#portable-import-file").value = "";
      $("#portable-import-passphrase").value = "";
      toast(data.message || "Portable vault imported.");
      await loadRecovery();
    } catch (error) {
      showError("portable-import-error", error.message);
    } finally {
      setBusy(button, false);
    }
  }

  async function loadTrash() {
    const data = await api("/api/files/trash");
    state.trash = Array.isArray(data.files) ? data.files : [];
    $("#trash-subtitle").textContent = state.trash.length
      ? `${state.trash.length} item${state.trash.length === 1 ? "" : "s"} · retained for 30 days`
      : "Deleted files stay here until purged.";
    renderTrash();
  }

  function renderTrash() {
    const body = $("#trash-body");
    const table = body.closest("table");
    const empty = $("#trash-empty");
    table.classList.toggle("hidden", state.trash.length === 0);
    empty.classList.toggle("hidden", state.trash.length > 0);
    body.innerHTML = state.trash
      .map(
        (file) => `<tr>
          <td><span class="file-name">${esc(file.filename || file.name)}</span><span class="file-meta">${esc(file.path || "/")}</span></td>
          <td class="hide-sm"><span class="tier-badge tier-${esc(file.tier)}">${esc(file.tier)}</span></td>
          <td class="hide-md">${formatDate(file.deleted_at || file.modified_at)}</td>
          <td class="hide-sm">${formatBytes(file.size)}</td>
          <td>
            <div class="row-actions">
              <button class="row-button" data-trash-action="restore" data-id="${esc(file.id)}" title="Restore" aria-label="Restore">${icon("refresh")}</button>
              <button class="row-button danger" data-trash-action="purge" data-id="${esc(file.id)}" title="Delete permanently" aria-label="Delete permanently">${icon("trash")}</button>
            </div>
          </td>
        </tr>`
      )
      .join("");
  }

  async function handleTrashAction(event) {
    const button = event.target.closest("[data-trash-action]");
    if (!button) return;
    const file = state.trash.find((item) => item.id === button.dataset.id);
    if (!file) return;
    if (button.dataset.trashAction === "restore") {
      try {
        await api("/api/files/restore", { method: "POST", body: { file_id: file.id } });
        toast("File restored.");
        await loadTrash();
        await loadFiles();
      } catch (error) {
        toast(error.message, "error");
      }
    }
    if (button.dataset.trashAction === "purge") {
      const confirmed = await confirmAction(
        "Delete permanently?",
        `“${file.filename || file.name}” will be destroyed and cannot be recovered.`,
        "Delete permanently"
      );
      if (!confirmed) return;
      try {
        await api("/api/files/delete", {
          method: "DELETE",
          body: { file_id: file.id, purge: true },
        });
        toast("File permanently deleted.");
        await loadTrash();
      } catch (error) {
        toast(error.message, "error");
      }
    }
  }

  async function emptyTrash() {
    if (!state.trash.length) {
      toast("Trash is already empty.", "warn");
      return;
    }
    const confirmed = await confirmAction(
      "Empty trash?",
      `Permanently delete all ${state.trash.length} item${state.trash.length === 1 ? "" : "s"} in Trash.`,
      "Empty trash"
    );
    if (!confirmed) return;
    const button = $("#btn-empty-trash");
    setBusy(button, true, "Emptying");
    try {
      const result = await api("/api/files/trash/empty", { method: "DELETE" });
      toast(`${result.purged} item${result.purged === 1 ? "" : "s"} purged.`);
      await loadTrash();
    } catch (error) {
      toast(error.message, "error");
    } finally {
      setBusy(button, false);
    }
  }

  async function loadSettings() {
    const settings = await api("/api/settings/");
    state.settings = settings;
    $("#setting-theme").value = settings.theme || "dark";
    $("#setting-autostart").checked = Boolean(settings.autostart);
    $("#setting-notifications").checked = Boolean(settings.desktop_notifications);
    $("#setting-log-level").value = settings.log_level || "INFO";
    $("#setting-proxy-type").value = settings.proxy_type || "none";
    $("#setting-proxy-host").value = settings.proxy_host || "";
    $("#setting-proxy-port").value = settings.proxy_port || "";
    applyTheme(settings.theme || "dark");
    applyAccent(settings.accent_color || "#c4f56a");
  }

  function applyTheme(theme) {
    state.themePreference = ["dark", "light", "system"].includes(theme) ? theme : "dark";
    const resolved =
      state.themePreference === "system"
        ? window.matchMedia("(prefers-color-scheme: dark)").matches
          ? "dark"
          : "light"
        : state.themePreference;
    document.documentElement.dataset.theme = resolved;
  }

  function applyAccent(color) {
    const safe = /^#[0-9a-f]{6}$/i.test(String(color || "")) ? String(color) : "#c4f56a";
    document.documentElement.style.setProperty("--accent", safe);
    const input = $("#setting-accent");
    if (input) input.value = safe;
    const label = $("#accent-value");
    if (label) label.textContent = safe.toUpperCase();
  }

  async function saveSettings() {
    const button = $("#btn-save-settings");
    setBusy(button, true, "Saving");
    try {
      const result = await api("/api/settings/", {
        method: "POST",
        body: {
          theme: $("#setting-theme").value,
          accent_color: $("#setting-accent").value,
          autostart: $("#setting-autostart").checked,
          desktop_notifications: $("#setting-notifications").checked,
          log_level: $("#setting-log-level").value,
          proxy_type: $("#setting-proxy-type").value,
          proxy_host: $("#setting-proxy-host").value.trim(),
          proxy_port: Number($("#setting-proxy-port").value) || 0,
        },
      });
      state.settings = result.settings;
      applyTheme(result.settings.theme);
      applyAccent(result.settings.accent_color);
      toast(result.message || "Settings saved.");
    } catch (error) {
      toast(error.message, "error");
    } finally {
      setBusy(button, false);
    }
  }

  async function connectTelemetry() {
    if (!state.unlocked) return;
    if (state.telemetrySocket && state.telemetrySocket.readyState <= 1) return;
    window.clearTimeout(state.telemetryReconnect);
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const socket = new WebSocket(`${protocol}//${window.location.host}/api/telemetry/ws`);
    state.telemetrySocket = socket;
    socket.addEventListener("open", () => {
      $("#telemetry-live").className = "status-dot ok";
      $("#telemetry-live").title = "Telemetry connected";
    });
    socket.addEventListener("message", (event) => {
      try {
        const payload = JSON.parse(event.data);
        handleTelemetry(payload);
      } catch (_) {}
    });
    socket.addEventListener("close", () => {
      state.telemetrySocket = null;
      $("#telemetry-live").className = "status-dot warn";
      $("#telemetry-live").title = "Telemetry disconnected";
      if (state.unlocked) {
        window.clearTimeout(state.telemetryReconnect);
        state.telemetryReconnect = window.setTimeout(connectTelemetry, 4000);
      }
    });
    socket.addEventListener("error", () => socket.close());
  }

  function handleTelemetry(payload) {
    $("#tel-upload").textContent = formatSpeed(payload.upload_speed_kbps);
    $("#tel-download").textContent = formatSpeed(payload.download_speed_kbps);
    $("#tel-threads").textContent = formatNumber(payload.active_threads);
    $("#tel-resources").textContent = `${Number(payload.ram_usage_mb || 0).toFixed(0)} MB / ${Number(payload.cpu_usage_percent || 0).toFixed(0)}%`;
    if (payload.log_message && payload.log_message !== state.lastTelemetryMessage) {
      state.lastTelemetryMessage = payload.log_message;
      state.telemetryEvents.unshift({ time: new Date().toISOString(), message: payload.log_message });
      state.telemetryEvents = state.telemetryEvents.slice(0, 80);
      renderTelemetryFeed();
    }
  }

  function renderTelemetryFeed() {
    const feed = $("#telemetry-feed");
    if (!state.telemetryEvents.length) {
      feed.innerHTML = `<div class="empty-state small"><p>Listening for pipeline events.</p></div>`;
      return;
    }
    feed.innerHTML = state.telemetryEvents
      .map(
        (event) => `<div class="feed-row"><time>${formatTime(event.time)}</time><span>${esc(event.message)}</span><em>pipeline</em></div>`
      )
      .join("");
  }

  function closeTelemetry() {
    window.clearTimeout(state.telemetryReconnect);
    state.telemetryReconnect = null;
    if (state.telemetrySocket) {
      const socket = state.telemetrySocket;
      state.telemetrySocket = null;
      socket.close();
    }
  }

  function setReadiness(level, text) {
    const dot = $("#system-dot");
    const sidebarDot = $("#sidebar-dot");
    if (dot) dot.className = `status-dot ${level}`;
    if (sidebarDot) sidebarDot.className = `status-dot ${level}`;
    $("#system-text").textContent = text;
    const sidebarText = $("#sidebar-status");
    if (sidebarText) sidebarText.textContent = text;
  }

  async function openDiagnostics() {
    openModal("diagnostics-modal");
    await runDiagnostics(true);
  }

  async function runDiagnostics(openResult) {
    try {
      const data = await api("/api/preflight/run");
      renderDiagnostics(data);
      if (openResult && !$("#diagnostics-modal").classList.contains("open")) {
        openModal("diagnostics-modal");
      }
    } catch (error) {
      setReadiness("error", "Diagnostics unavailable");
      if (openResult) toast(error.message, "error");
    }
  }

  function renderDiagnostics(data) {
    const checks = [
      ["Keyring access", data.keyring_ok, data.keyring_msg, "error"],
      ["Database write access", data.database_ok, data.database_msg, "error"],
      ["Internet reachability", data.network_ok, data.network_msg, "warn"],
      ["Long path support", data.long_paths_ok, data.long_paths_msg, "warn"],
      ["File watcher limits", data.inotify_ok, data.inotify_msg, "warn"],
    ];
    $("#diagnostics-list").innerHTML = checks
      .map(([label, passed, message, failLevel]) => {
        const level = passed ? "ok" : failLevel;
        const display = passed ? "Available" : failLevel === "warn" ? "Unavailable" : "Action needed";
        return `<div class="diagnostic-row">
          <span class="status-dot ${level}"></span>
          <div><strong>${esc(label)} · ${display}</strong><span>${esc(message || "No details reported.")}</span></div>
        </div>`;
      })
      .join("");
    const critical = Boolean(data.keyring_ok && data.database_ok);
    if (critical && data.network_ok) {
      setReadiness("ok", "System ready");
    } else if (critical) {
      setReadiness("warn", "Local-only mode");
    } else {
      setReadiness("error", "Attention needed");
    }
  }

  // ── Tripwires: canary files + mass-change alarm ─────────────────────

  async function loadSecurity() {
    const [canaries, mass] = await Promise.all([
      api("/api/security/canaries"),
      api("/api/security/mass-change"),
    ]);
    renderCanaries(canaries);
    renderMassStatus(mass);
  }

  function renderCanaries(data) {
    const pill = $("#canary-pill");
    pill.textContent = data.enabled ? "ARMED" : "OFF";
    pill.className = `pill durability-state ${data.enabled ? "state-degraded" : ""}`;
    $("#canary-count").textContent = formatNumber((data.canaries || []).length);
    $("#canary-interval").textContent = `every ${formatNumber(data.interval_seconds)} s`;
    $("#canary-enabled-input").checked = Boolean(data.enabled);
    const list = $("#canary-list");
    const canaries = Array.isArray(data.canaries) ? data.canaries : [];
    const missing = canaries.filter((item) => item.missing).length;
    $("#canary-missing").textContent = formatNumber(missing);
    if (!canaries.length) {
      list.innerHTML = `<p class="muted sync-roots-empty">No canaries planted yet.</p>`;
      return;
    }
    list.innerHTML = canaries
      .map(
        (item, index) => `<div class="sync-root-chip">
          <div><strong title="${esc(item.path)}">${esc(item.path.split(/[\\/]/).pop() || item.path)}</strong><span>${esc(item.path)} · gen ${Number(item.generation) || 0}${item.missing ? " · MISSING" : ""}</span></div>
          <button class="row-button danger sync-root-remove" data-canary-index="${index}" data-canary-path="${esc(item.path)}" title="Remove canary">${icon("trash")}</button>
        </div>`
      )
      .join("");
  }

  async function addCanary(event) {
    event.preventDefault();
    clearError("canary-error");
    const path = $("#canary-path-input").value.trim();
    if (!path) return showError("canary-error", "Enter a full file path for the canary.");
    const button = $("#btn-canary-add");
    setBusy(button, true, "Planting");
    try {
      const result = await api("/api/security/canary/add", { method: "POST", body: { path, plant: true } });
      $("#canary-path-input").value = "";
      toast("Canary planted. Any change to it will fire a critical alert.");
      renderCanaries(result);
    } catch (error) {
      showError("canary-error", error.message);
    } finally {
      setBusy(button, false);
    }
  }

  async function saveCanaryEnabled() {
    try {
      const result = await api("/api/security/canary/settings", {
        method: "POST",
        body: { enabled: $("#canary-enabled-input").checked },
      });
      renderCanaries(result);
      toast(result.enabled ? "Canary watching enabled." : "Canary watching disabled.");
    } catch (error) {
      toast(error.message, "error");
    }
  }

  async function checkCanariesNow() {
    const button = $("#btn-canary-check");
    setBusy(button, true, "Checking");
    try {
      const result = await api("/api/security/canary/check", { method: "POST" });
      toast(
        result.triggers
          ? `${formatNumber(result.triggers)} canar${result.triggers === 1 ? "y" : "ies"} tampered — critical alert raised.`
          : `Checked ${formatNumber(result.checked)} canar${result.checked === 1 ? "y" : "ies"} — all clean.`,
        result.triggers ? "error" : "success"
      );
      await loadSecurity();
    } catch (error) {
      toast(error.message, "error");
    } finally {
      setBusy(button, false);
    }
  }

  async function handleCanaryAction(event) {
    const button = event.target.closest("[data-canary-path]");
    if (!button) return;
    const path = button.dataset.canaryPath;
    const confirmed = await confirmAction("Remove canary?", `Stop watching “${path}”. The decoy file is deleted too.`, "Remove canary");
    if (!confirmed) return;
    try {
      const result = await api(`/api/security/canary?path=${encodeURIComponent(path)}&delete_file=true`, { method: "DELETE" });
      toast("Canary removed.");
      renderCanaries(result);
    } catch (error) {
      toast(error.message, "error");
    }
  }

  function renderMassStatus(data) {
    const pill = $("#mass-pill");
    pill.textContent = data.enabled ? "ARMED" : "OFF";
    pill.className = `pill durability-state ${data.enabled ? "state-degraded" : ""}`;
    $("#mass-threshold").textContent = `${formatNumber(data.threshold)} files`;
    $("#mass-window").textContent = `${formatNumber(data.window_minutes)} min`;
    $("#mass-threshold-input").value = String(Number(data.threshold) || 50);
    $("#mass-window-input").value = String(Number(data.window_minutes) || 5);
    $("#mass-enabled-input").checked = Boolean(data.enabled);
    const last = data.last;
    $("#mass-last").textContent = last && last.at ? `${formatDate(last.at)} ${formatTime(last.at)}` : "Never";
    $("#mass-count").textContent = last && last.count !== undefined ? formatNumber(last.count) : "—";
  }

  async function saveMassSettings(event) {
    event.preventDefault();
    clearError("mass-error");
    try {
      const result = await api("/api/security/mass-change/settings", {
        method: "POST",
        body: {
          enabled: $("#mass-enabled-input").checked,
          threshold: Number($("#mass-threshold-input").value) || 50,
          window_minutes: Number($("#mass-window-input").value) || 5,
        },
      });
      renderMassStatus(result);
      toast("Mass-change alarm settings saved.");
    } catch (error) {
      showError("mass-error", error.message);
    }
  }

  async function checkMassNow() {
    const button = $("#btn-mass-check");
    setBusy(button, true, "Scanning");
    try {
      const result = await api("/api/security/mass-change/check", { method: "POST" });
      toast(
        result.triggered
          ? `${formatNumber(result.count)} files changed — critical alert raised.`
          : `${formatNumber(result.count)} changes in the window — below threshold.`,
        result.triggered ? "error" : "success"
      );
      await loadSecurity();
    } catch (error) {
      toast(error.message, "error");
    } finally {
      setBusy(button, false);
    }
  }

  // ── Air-gap export & waste report ───────────────────────────────────

  async function loadAirgap() {
    const [status] = await Promise.all([api("/api/airgap/status"), loadWaste()]);
    renderAirgap(status);
  }

  function renderAirgap(status) {
    const pill = $("#airgap-pill");
    pill.textContent = status.enabled ? "ARMED" : "OFF";
    pill.className = `pill durability-state ${status.enabled ? "state-protected" : ""}`;
    $("#airgap-target").textContent = status.target_dir || "Not set";
    if (!status.target_exists && status.target_dir) $("#airgap-target").textContent = `${status.target_dir} (missing)`;
    $("#airgap-interval").textContent = `every ${formatNumber(status.interval_hours)} h`;
    $("#airgap-target-input").value = status.target_dir || "";
    $("#airgap-interval-input").value = String(Number(status.interval_hours) || 168);
    $("#airgap-enabled-input").checked = Boolean(status.enabled);
    const last = status.last;
    $("#airgap-last").textContent = last
      ? `${last.ok ? "OK" : "FAILED"} · ${formatDate(last.at)} · ${formatBytes(last.bytes || 0)}`
      : "Never";
    const drill = status.last_drill;
    $("#airgap-drill").textContent = drill
      ? `${drill.ok ? "PASSED" : "FAILED"} · ${formatDate(drill.at || drill.checked_at)}`
      : "Never";
  }

  async function saveAirgapSettings(event) {
    event.preventDefault();
    clearError("airgap-error");
    try {
      await api("/api/airgap/settings", {
        method: "POST",
        body: {
          enabled: $("#airgap-enabled-input").checked,
          target_dir: $("#airgap-target-input").value.trim(),
          interval_hours: Number($("#airgap-interval-input").value) || 168,
        },
      });
      toast("Air-gap settings saved.");
      await loadAirgap();
    } catch (error) {
      showError("airgap-error", error.message);
    }
  }

  async function runAirgapExport() {
    const button = $("#btn-airgap-export");
    setBusy(button, true, "Exporting");
    try {
      const result = await api("/api/airgap/export", { method: "POST" });
      toast(result.ok ? `Exported ${formatNumber(result.file_count)} files (${formatBytes(result.bytes)}) to the air-gap drive.` : `Export failed: ${result.error}`, result.ok ? "success" : "error");
      await loadAirgap();
    } catch (error) {
      toast(error.message, "error");
    } finally {
      setBusy(button, false);
    }
  }

  async function runAirgapVerify() {
    const button = $("#btn-airgap-verify");
    setBusy(button, true, "Verifying");
    try {
      const result = await api("/api/airgap/verify", { method: "POST" });
      toast(
        result.ok
          ? `Export verified — ${formatNumber(result.checked_chunks)} chunks checked.`
          : `Verification failed: ${result.error || `${result.missing} missing, ${result.corrupt} corrupt`}`,
        result.ok ? "success" : "error"
      );
    } catch (error) {
      toast(error.message, "error");
    } finally {
      setBusy(button, false);
    }
  }

  async function runAirgapDrill() {
    const button = $("#btn-airgap-drill");
    setBusy(button, true, "Drilling");
    try {
      const result = await api("/api/airgap/drill", { method: "POST" });
      toast(result.ok ? `Restore drill passed — “${result.file}” verified from the export.` : `Restore drill FAILED: ${result.error}`, result.ok ? "success" : "error");
      await loadAirgap();
    } catch (error) {
      toast(error.message, "error");
    } finally {
      setBusy(button, false);
    }
  }

  async function loadWaste() {
    try {
      const data = await api("/api/waste/report");
      renderWaste(data);
    } catch (error) {
      $("#waste-note").textContent = `Waste report unavailable: ${error.message}`;
    }
  }

  function renderWaste(data) {
    $("#waste-reclaimable").textContent = formatBytes(data.total_reclaimable_bytes);
    const dedup = data.dedup || {};
    $("#waste-dedup").textContent = formatBytes(dedup.wasted_bytes || dedup.potential_reclaim_bytes || 0);
    const trash = data.trash || {};
    $("#waste-trash").textContent = formatBytes(trash.bytes || 0);
    const versions = data.versions || {};
    $("#waste-versions").textContent = versions.bytes != null ? formatBytes(versions.bytes) : formatNumber(versions.count || 0);
    const top = Array.isArray(data.top_duplicates) ? data.top_duplicates : [];
    const container = $("#waste-duplicates");
    if (!top.length) {
      container.innerHTML = `<p class="muted">No duplicated content detected.</p>`;
      return;
    }
    const max = Math.max(...top.map((item) => Number(item.size) * Number(item.copies)), 1);
    container.innerHTML = top
      .map(
        (item) => `<div class="bar-row">
          <div><strong>${formatBytes(item.size)} × ${formatNumber(item.copies)}</strong><span>${esc((item.sample_paths || []).join(" · ") || "identical chunks")}</span></div>
          <div class="bar-track"><span style="width:${clamp(((Number(item.size) * Number(item.copies)) / max) * 100, 2, 100)}%"></span></div>
        </div>`
      )
      .join("");
  }

  // ── Cloud import ────────────────────────────────────────────────────

  const CLOUD_PROVIDER_LABELS = { dropbox: "Dropbox", gdrive: "Google Drive", onedrive: "OneDrive" };

  async function loadCloud() {
    const [status, history] = await Promise.all([
      api("/api/cloud/status"),
      api("/api/cloud/history").catch(() => ({ history: [] })),
    ]);
    renderCloudConnections(status);
    renderCloudHistory(history.history || history.imports || []);
  }

  function renderCloudConnections(status) {
    const container = $("#cloud-connections");
    const browse = $("#cloud-browse-provider");
    const entries = Object.entries(status || {});
    if (!entries.length) {
      container.innerHTML = `<p class="muted">No providers available.</p>`;
      return;
    }
    container.innerHTML = entries
      .map(
        ([provider, info]) => `<div class="sync-root-chip">
          <div><strong>${esc(CLOUD_PROVIDER_LABELS[provider] || provider)}</strong><span>${info.connected ? `Connected · token …${esc(info.token_hint || "")}` : "Not connected"}</span></div>
          ${
            info.connected
              ? `<button class="row-button" data-cloud-disconnect="${esc(provider)}" title="Disconnect">${icon("close")}</button>`
              : ""
          }
        </div>`
      )
      .join("");
    container.querySelectorAll("[data-cloud-disconnect]").forEach((button) => {
      button.addEventListener("click", async () => {
        try {
          await api("/api/cloud/disconnect", { method: "POST", body: { provider: button.dataset.cloudDisconnect } });
          toast("Provider disconnected.");
          await loadCloud();
        } catch (error) {
          toast(error.message, "error");
        }
      });
    });
    // Rebuild the browse dropdown from connected providers only.
    const connected = entries.filter(([, info]) => info.connected).map(([provider]) => provider);
    browse.innerHTML = connected.length
      ? connected.map((provider) => `<option value="${esc(provider)}">${esc(CLOUD_PROVIDER_LABELS[provider] || provider)}</option>`).join("")
      : `<option value="">Not connected</option>`;
  }

  function renderCloudHistory(history) {
    const container = $("#cloud-history");
    if (!history.length) {
      container.innerHTML = `<p class="muted">No imports yet.</p>`;
      return;
    }
    container.innerHTML = history
      .slice(0, 10)
      .map(
        (item) => `<div class="event-row">
          <span class="status-dot ${item.failed ? "warn" : "ok"}"></span>
          <div><strong>${esc(CLOUD_PROVIDER_LABELS[item.provider] || item.provider || "?")} · ${formatNumber(item.imported || 0)} imported${item.failed ? `, ${formatNumber(item.failed)} failed` : ""}</strong><span>${formatBytes(item.bytes || 0)} · ${esc(item.at || "")}</span></div>
        </div>`
      )
      .join("");
  }

  async function cloudConnect(event) {
    event.preventDefault();
    clearError("cloud-error");
    const provider = $("#cloud-provider-input").value;
    const token = $("#cloud-token-input").value.trim();
    if (!token) return showError("cloud-error", "Paste an access token.");
    const button = $("#btn-cloud-connect");
    setBusy(button, true, "Validating");
    try {
      await api("/api/cloud/connect", { method: "POST", body: { provider, token } });
      $("#cloud-token-input").value = "";
      toast(`${CLOUD_PROVIDER_LABELS[provider] || provider} connected.`);
      await loadCloud();
    } catch (error) {
      showError("cloud-error", error.message);
    } finally {
      setBusy(button, false);
    }
  }

  async function cloudList() {
    const provider = $("#cloud-browse-provider").value;
    const errorBox = $("#cloud-error-list");
    errorBox.classList.add("hidden");
    if (!provider) return showError("cloud-error-list", "Connect a provider first.");
    const button = $("#btn-cloud-list");
    setBusy(button, true, "Listing");
    try {
      const data = await api(`/api/cloud/list?provider=${encodeURIComponent(provider)}`);
      state.cloudFiles = Array.isArray(data.files) ? data.files : [];
      renderCloudFiles();
    } catch (error) {
      showError("cloud-error-list", error.message);
    } finally {
      setBusy(button, false);
    }
  }

  function renderCloudFiles() {
    const body = $("#cloud-files-body");
    const table = body.closest("table");
    const empty = $("#cloud-empty");
    const files = state.cloudFiles || [];
    table.classList.toggle("hidden", files.length === 0);
    empty.classList.toggle("hidden", files.length > 0);
    $("#cloud-list-note").textContent = files.length
      ? `${formatNumber(files.length)} files — select and import.`
      : "Select a connected provider to browse its files.";
    body.innerHTML = files
      .map(
        (file, index) => `<tr>
          <td><input type="checkbox" data-cloud-file="${index}"></td>
          <td><span class="file-name" title="${esc(file.path)}">${esc(file.name)}</span></td>
          <td class="hide-sm">${formatBytes(file.size)}</td>
          <td class="hide-md">${file.modified_at ? esc(formatDate(file.modified_at)) : "—"}</td>
        </tr>`
      )
      .join("");
  }

  async function cloudImport() {
    const provider = $("#cloud-browse-provider").value;
    const errorBox = $("#cloud-error-list");
    errorBox.classList.add("hidden");
    if (!provider) return showError("cloud-error-list", "Connect a provider first.");
    const selected = [...document.querySelectorAll("[data-cloud-file]:checked")]
      .map((checkbox) => state.cloudFiles[Number(checkbox.dataset.cloudFile)])
      .filter(Boolean);
    if (!selected.length) return showError("cloud-error-list", "Select files to import.");
    const button = $("#btn-cloud-import");
    setBusy(button, true, "Importing");
    try {
      const result = await api("/api/cloud/import", {
        method: "POST",
        body: { provider, paths: selected.map((file) => file.path) },
      });
      toast(
        result.failed
          ? `Imported ${formatNumber(result.imported)}, failed ${formatNumber(result.failed)}.`
          : `Imported ${formatNumber(result.imported)} files (${formatBytes(result.bytes)}) — encrypted on arrival.`,
        result.failed ? "error" : "success"
      );
      await loadCloud();
    } catch (error) {
      showError("cloud-error-list", error.message);
    } finally {
      setBusy(button, false);
    }
  }

  // ── Remote access & pairing ─────────────────────────────────────────

  async function loadRemote() {
    const status = await api("/api/remote/status");
    const pill = $("#remote-pill");
    const ready = Boolean(status.ready_for_phone);
    pill.textContent = ready ? "READY" : "LOCAL ONLY";
    pill.className = `pill durability-state ${ready ? "state-protected" : ""}`;
    const ts = status.tailscale || {};
    const urls = [...(status.remote_urls || []), ...(status.local_urls || [])];
    $("#remote-urls").textContent = urls.length ? urls.join("  ·  ") : "No URLs detected.";
    // Re-point the QR at the best URL whenever the status changes.
    const qr = $("#remote-qr");
    if (urls.length) qr.src = `/api/pairing/qr.png?url=${encodeURIComponent(urls[0])}&v=${Date.now()}`;
    $("#remote-note").textContent = ready
      ? `Tailscale is up (${ts.ip}). Scan the QR from your phone on the same tailnet.`
      : "Install and start Tailscale on this machine, then rescan — the app never opens a public port.";
    const steps = Array.isArray(status.steps) ? status.steps : [];
    $("#remote-steps").innerHTML = steps.length
      ? steps
          .map(
            (step) => `<div><span>${esc(step.label)}</span><strong class="inline-status"><span class="status-dot ${step.done ? "ok" : ""}"></span>${step.done ? "Done" : "Pending"}</strong></div>`
          )
          .join("")
      : `<p class="muted">No steps reported.</p>`;
    const safety = Array.isArray(status.safety) ? status.safety : [];
    $("#remote-safety").innerHTML = safety.length
      ? safety.map((line) => `<div><span>${esc(line)}</span></div>`).join("")
      : `<p class="muted">No safety notes reported.</p>`;
  }

  // ── Weekly health report ────────────────────────────────────────────

  function renderHealthReport(lastRun, report) {
    const pill = $("#health-report-pill");
    pill.textContent = report ? "READY" : "…";
    pill.className = `pill durability-state ${report ? "state-protected" : ""}`;
    $("#health-report-last").textContent = lastRun ? `${formatDate(lastRun)} ${formatTime(lastRun)}` : "Never";
    if (!report) return;
    const badge = report.badge || {};
    $("#health-report-badge").textContent = badge.label || badge.overall || "—";
    const alerts = report.alerts || {};
    $("#health-report-alerts").textContent = formatNumber(alerts.active_count || 0);
    const waste = report.waste;
    $("#health-report-waste").textContent =
      waste && waste.total_reclaimable_bytes != null ? formatBytes(waste.total_reclaimable_bytes) : "—";
    const drills = report.drills || {};
    $("#health-report-note").textContent = drills.last
      ? `Last drill: ${drills.last.result || "?"} · ${formatNumber(drills.passed || 0)} passed, ${formatNumber(drills.failed || 0)} failed.`
      : "Drills, badge, alerts, and space — one summary on a schedule.";
  }

  async function runHealthReportNow() {
    const button = $("#btn-health-report-run");
    setBusy(button, true, "Running");
    try {
      const result = await api("/api/health/run", { method: "POST" });
      renderHealthReport(result.report && result.report.generated_at, result.report);
      toast(result.delivered ? "Report built and delivered." : "Report built.");
    } catch (error) {
      toast(error.message, "error");
    } finally {
      setBusy(button, false);
    }
  }

  async function saveHealthReportSettings() {
    try {
      const result = await api("/api/health/settings", {
        method: "POST",
        body: {
          enabled: $("#health-report-enabled-input").checked,
          interval_hours: Number($("#health-report-interval-input").value) || 168,
          webhook_url: $("#health-report-webhook-input").value.trim() || null,
        },
      });
      $("#health-report-enabled-input").checked = Boolean(result.enabled);
      $("#health-report-interval-input").value = String(Number(result.interval_hours) || 168);
      $("#health-report-webhook").textContent = result.webhook_configured ? "Configured" : "Not set";
      toast("Health report settings saved.");
    } catch (error) {
      toast(error.message, "error");
    }
  }

  // ── Inheritance (dead man's switch) ─────────────────────────────────

  function renderInheritance(status) {
    const pill = $("#inheritance-pill");
    pill.textContent = status.enabled ? (status.overdue ? "OVERDUE" : "ARMED") : "OFF";
    pill.className = `pill durability-state ${status.overdue ? "state-unprotected" : status.enabled ? "state-degraded" : ""}`;
    $("#inheritance-interval").textContent = status.enabled ? `${formatNumber(status.interval_days)} days` : "—";
    $("#inheritance-last-checkin").textContent = status.last_check_in ? `${formatDate(status.last_check_in)} ${formatTime(status.last_check_in)}` : "Never";
    $("#inheritance-due").textContent = status.due_at ? formatDate(status.due_at) : "—";
    const remaining = status.days_remaining;
    $("#inheritance-remaining").textContent =
      remaining == null ? "—" : remaining < 0 ? `${formatNumber(-remaining)} days OVERDUE` : `${formatNumber(remaining)} days`;
    $("#inheritance-package").textContent = status.package_sealed ? "Sealed" : "Not sealed";
    $("#inheritance-days-input").value = String(Number(status.interval_days) || 90);
    // Keep contacts textarea in sync only when empty so typing is not clobbered.
    if (!$("#inheritance-contacts-input").value && Array.isArray(status.contacts) && status.contacts.length) {
      $("#inheritance-contacts-input").value = status.contacts
        .map((contact) => `${contact.name} | ${contact.webhook_url}`)
        .join("\n");
    }
  }

  function parseInheritanceContacts() {
    return $("#inheritance-contacts-input")
      .value.split("\n")
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => {
        const [name, ...rest] = line.split("|");
        return { name: (name || "").trim(), webhook_url: rest.join("|").trim() };
      });
  }

  async function enableInheritance() {
    clearError("inheritance-error");
    const contacts = parseInheritanceContacts();
    if (!contacts.length) return showError("inheritance-error", "Add at least one contact (Name | URL).");
    const button = $("#btn-inheritance-enable");
    setBusy(button, true, "Sealing");
    try {
      const status = await api("/api/inheritance/enable", {
        method: "POST",
        body: {
          interval_days: Number($("#inheritance-days-input").value) || 90,
          release_passphrase: $("#inheritance-passphrase-input").value,
          contacts,
        },
      });
      $("#inheritance-passphrase-input").value = "";
      renderInheritance(status);
      toast("Inheritance switch armed. The release passphrase is never stored — share it with your contacts out-of-band.");
    } catch (error) {
      showError("inheritance-error", error.message);
    } finally {
      setBusy(button, false);
    }
  }

  async function inheritanceCheckIn() {
    try {
      const status = await api("/api/inheritance/check-in", { method: "POST" });
      renderInheritance(status);
      toast("Checked in — the release timer is reset.");
    } catch (error) {
      toast(error.message, "error");
    }
  }

  async function disableInheritance() {
    const confirmed = await confirmAction(
      "Disable the inheritance switch?",
      "The sealed package is destroyed. Contacts will never receive it. You can re-arm later (re-sealed from the current master key).",
      "Disable switch"
    );
    if (!confirmed) return;
    try {
      const status = await api("/api/inheritance/disable", { method: "POST", body: {} });
      renderInheritance(status);
      toast("Inheritance switch disabled.");
    } catch (error) {
      toast(error.message, "error");
    }
  }

  // ── Content search (decrypt-at-query-time) ──────────────────────────

  async function runContentSearch() {
    const query = $("#content-search-input").value.trim();
    const errorBox = $("#content-search-error");
    errorBox.classList.add("hidden");
    if (!query) return showError("content-search-error", "Type something to search inside your files.");
    const button = $("#btn-content-search");
    setBusy(button, true, "Searching");
    try {
      const result = await api("/api/search/content", { method: "POST", body: { query } });
      renderContentSearch(result);
    } catch (error) {
      showError("content-search-error", error.message);
    } finally {
      setBusy(button, false);
    }
  }

  function renderContentSearch(result) {
    const container = $("#content-search-results");
    const empty = $("#content-search-empty");
    const results = Array.isArray(result.results) ? result.results : [];
    empty.classList.toggle("hidden", results.length > 0);
    if (!results.length) {
      container.innerHTML = "";
      empty.querySelector("p").textContent = `No files matched “${result.query}” (${formatNumber(result.scanned)} scanned in ${formatNumber(result.duration_ms)} ms).`;
      return;
    }
    container.innerHTML = results
      .map(
        (item) => `<div class="event-row">
          <span class="status-dot ok"></span>
          <div>
            <strong>${esc(item.name)}</strong>
            <span>${esc(item.path || "/")}${item.truncated ? " · searched first part only" : ""}</span>
            ${(item.snippets || [])
              .map((snippet) => `<span class="content-snippet">…${esc(snippet)}…</span>`)
              .join("")}
          </div>
        </div>`
      )
      .join("");
  }

  // ── Downloads quick-add ─────────────────────────────────────────────

  async function quickAddDownloads() {
    const button = $("#btn-sync-quick-add");
    setBusy(button, true, "Adding");
    try {
      const result = await api("/api/sync/quick-add", { method: "POST", body: {} });
      toast(
        result.added
          ? `Downloads folder added and sync started: ${result.root}`
          : "Downloads folder was already a sync root.",
        "success"
      );
      await loadSync();
    } catch (error) {
      toast(error.message, "error");
    } finally {
      setBusy(button, false);
    }
  }
})();
