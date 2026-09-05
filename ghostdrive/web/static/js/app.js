/**
 * GhostDrive Web Single-Page Application (SPA) Controller
 */

document.addEventListener("DOMContentLoaded", () => {
  // Global State
  const state = {
    currentPath: "/",
    currentCategory: "all",
    searchQuery: "",
    webSocket: null,
  };

  // DOM Elements
  const preflightModal = document.getElementById("preflight-modal");
  const btnRetestDiag = document.getElementById("btn-retest-diag");
  const btnProceedDiag = document.getElementById("btn-proceed-diag");

  const authScreen = document.getElementById("auth-screen");
  const unlockForm = document.getElementById("unlock-form");
  const setupForm = document.getElementById("setup-form");
  const seedDisplayView = document.getElementById("seed-display-view");
  const mainApp = document.getElementById("main-app");

  // Run Preflight Diagnostics on Initial Load
  runPreflightChecks();

  function runPreflightChecks() {
    fetch("/api/preflight/run")
      .then(res => res.json())
      .then(data => {
        updateCheckItem("check-keyring", data.keyring_ok, data.keyring_msg);
        updateCheckItem("check-db", data.database_ok, data.database_msg);
        updateCheckItem("check-net", data.network_ok, data.network_msg);
        updateCheckItem("check-sys", data.long_paths_ok && data.inotify_ok, `${data.long_paths_msg} | ${data.inotify_msg}`);

        document.getElementById("preflight-progress").style.width = "100%";
        btnRetestDiag.disabled = false;
        btnProceedDiag.disabled = false;

        if (data.all_passed) {
          setTimeout(() => proceedFromPreflight(), 1000);
        }
      })
      .catch(err => {
        console.error("Preflight error:", err);
        btnRetestDiag.disabled = false;
        btnProceedDiag.disabled = false;
      });
  }

  function updateCheckItem(id, passed, msg) {
    const el = document.getElementById(id);
    if (!el) return;
    const statusSpan = el.querySelector(".status");
    if (passed) {
      statusSpan.innerHTML = `<span style="color: var(--success);">✅ Passed (${msg})</span>`;
    } else {
      statusSpan.innerHTML = `<span style="color: var(--warning);">⚠️ ${msg}</span>`;
    }
  }

  btnRetestDiag.addEventListener("click", () => {
    document.getElementById("preflight-progress").style.width = "20%";
    runPreflightChecks();
  });

  btnProceedDiag.addEventListener("click", proceedFromPreflight);

  function proceedFromPreflight() {
    preflightModal.classList.remove("active");
    checkAuthStatus();
  }

  // Auth Status Check
  function checkAuthStatus() {
    fetch("/api/auth/status")
      .then(res => res.json())
      .then(data => {
        if (data.is_unlocked && data.db_opened) {
          showMainApp();
        } else {
          authScreen.classList.remove("hidden");
          if (!data.keystore_exists) {
            unlockForm.classList.add("hidden");
            setupForm.classList.remove("hidden");
          } else {
            setupForm.classList.add("hidden");
            unlockForm.classList.remove("hidden");
          }
        }
      });
  }

  // Unlock Handler
  document.getElementById("btn-unlock").addEventListener("click", () => {
    const passphrase = document.getElementById("unlock-passphrase").value;
    const errEl = document.getElementById("unlock-error");
    errEl.classList.add("hidden");

    fetch("/api/auth/unlock", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ passphrase })
    })
    .then(res => res.json())
    .then(data => {
      if (data.status === "success") {
        showMainApp();
      } else {
        errEl.innerText = data.detail || data.error || "Unlock failed.";
        errEl.classList.remove("hidden");
      }
    });
  });

  // Setup Handler
  document.getElementById("btn-create-vault").addEventListener("click", () => {
    const pass = document.getElementById("setup-passphrase").value;
    const confirm = document.getElementById("setup-confirm").value;

    if (!pass || pass !== confirm) {
      alert("Passphrases do not match or are empty!");
      return;
    }

    fetch("/api/auth/setup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ passphrase: pass })
    })
    .then(res => res.json())
    .then(data => {
      if (data.seed_phrase) {
        setupForm.classList.add("hidden");
        seedDisplayView.classList.remove("hidden");
        renderSeedWords(data.seed_phrase);
      }
    });
  });

  function renderSeedWords(phrase) {
    const container = document.getElementById("seed-words-container");
    container.innerHTML = "";
    phrase.split(" ").forEach((word, idx) => {
      const div = document.createElement("div");
      div.className = "seed-word";
      div.innerText = `${idx + 1}. ${word}`;
      container.appendChild(div);
    });
  }

  document.getElementById("btn-confirm-seed").addEventListener("click", () => {
    showMainApp();
  });

  document.getElementById("btn-lock-vault").addEventListener("click", () => {
    fetch("/api/auth/lock", { method: "POST" }).then(() => {
      mainApp.classList.add("hidden");
      authScreen.classList.remove("hidden");
      unlockForm.classList.remove("hidden");
    });
  });

  function showMainApp() {
    authScreen.classList.add("hidden");
    mainApp.classList.remove("hidden");
    loadFileList();
    loadBackends();
    loadAnalytics();
    loadResilience();
    loadSharedLinks();
    connectWebSocketTelemetry();
  }

  // Navigation Tabs
  const navBtns = document.querySelectorAll(".nav-btn");
  const viewPanels = document.querySelectorAll(".view-panel");

  navBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      navBtns.forEach(b => b.classList.remove("active"));
      viewPanels.forEach(p => p.classList.remove("active"));

      btn.classList.add("active");
      const targetId = btn.getAttribute("data-target");
      document.getElementById(targetId).classList.add("active");
    });
  });

  // Files Manager
  function loadFileList() {
    const url = `/api/files/list?path=${encodeURIComponent(state.currentPath)}&category=${state.currentCategory}&search=${encodeURIComponent(state.searchQuery)}`;
    fetch(url)
      .then(res => res.json())
      .then(data => {
        const tbody = document.getElementById("files-table-body");
        tbody.innerHTML = "";
        if (!data.files || data.files.length === 0) {
          tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No files found in directory.</td></tr>`;
          return;
        }

        data.files.forEach(f => {
          const tr = document.createElement("tr");
          const sizeKb = (f.size / 1024).toFixed(1);
          let tierBadge = `<span class="badge badge-important">IMPORTANT 3x</span>`;
          if (f.tier === "CRITICAL") tierBadge = `<span class="badge badge-critical">CRITICAL 4x</span>`;
          if (f.tier === "DISPOSABLE") tierBadge = `<span class="badge badge-disposable">DISPOSABLE 2x</span>`;

          tr.innerHTML = `
            <td>📄 <strong>${f.filename}</strong></td>
            <td>${sizeKb} KB</td>
            <td>${tierBadge}</td>
            <td>${f.modified}</td>
            <td>
              <button class="btn btn-sm btn-secondary" onclick="downloadFile('${f.id}')">⬇️</button>
              <button class="btn btn-sm btn-secondary" onclick="deleteFile('${f.id}')">🗑️</button>
            </td>
          `;
          tbody.appendChild(tr);
        });
      });
  }

  // Filter Buttons
  document.querySelectorAll(".filter-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      state.currentCategory = btn.getAttribute("data-cat");
      loadFileList();
    });
  });

  // Search Input
  document.getElementById("global-search").addEventListener("input", (e) => {
    state.searchQuery = e.target.value;
    loadFileList();
  });

  // Upload Modal & Tier Advisor
  const uploadModal = document.getElementById("upload-modal");
  const modalFileInput = document.getElementById("modal-file-input");
  const advisorBanner = document.getElementById("tier-advisor-banner");
  const advisorRec = document.getElementById("advisor-recommendation");
  const modalTierSelect = document.getElementById("modal-tier-select");

  document.getElementById("btn-quick-upload").addEventListener("click", () => {
    uploadModal.classList.add("active");
  });

  document.getElementById("btn-cancel-upload").addEventListener("click", () => {
    uploadModal.classList.remove("active");
  });

  modalFileInput.addEventListener("change", (e) => {
    const file = e.target.files[0];
    if (!file) return;

    fetch("/api/files/tier-advisor", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ filename: file.name, file_size: file.size, mime_type: file.type })
    })
    .then(res => res.json())
    .then(data => {
      advisorRec.innerText = `${data.recommended_tier} Tier: ${data.rationale}`;
      advisorBanner.classList.remove("hidden");
      modalTierSelect.value = data.recommended_tier;
    });
  });

  document.getElementById("btn-confirm-upload").addEventListener("click", () => {
    const file = modalFileInput.files[0];
    if (!file) {
      alert("Select a file first.");
      return;
    }

    const formData = new FormData();
    formData.append("file", file);
    formData.append("tier", modalTierSelect.value);
    formData.append("destination_path", state.currentPath);

    fetch("/api/files/upload", {
      method: "POST",
      body: formData
    })
    .then(res => res.json())
    .then(data => {
      uploadModal.classList.remove("active");
      showToast(`Uploaded ${file.name} to ${modalTierSelect.value} tier.`);
      loadFileList();
    });
  });

  // Backends Renderer
  function loadBackends() {
    fetch("/api/backends/list")
      .then(res => res.json())
      .then(data => {
        const container = document.getElementById("backend-cards-container");
        container.innerHTML = "";
        data.configured_backends.forEach(b => {
          const card = document.createElement("div");
          card.className = "glass-card stat-card";
          card.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <strong>${b.name}</strong>
              <span class="badge badge-important">${b.tier}</span>
            </div>
            <p class="muted" style="margin: 8px 0; font-size: 11px;">Provider: ${b.provider}</p>
            <div style="font-size: 12px;">Latency: ${b.latency_ms} ms</div>
            <button class="btn btn-sm btn-secondary mt-16" onclick="testBackend('${b.provider}', '${b.tier}')">Test Reachability</button>
          `;
          container.appendChild(card);
        });
      });
  }

  window.testBackend = (provider, tier) => {
    fetch("/api/backends/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ provider, tier, credentials: {} })
    })
    .then(res => res.json())
    .then(data => {
      showToast(`${provider}: ${data.message}`);
    });
  };

  // Analytics Renderer
  function loadAnalytics() {
    fetch("/api/analytics/metrics")
      .then(res => res.json())
      .then(data => {
        const tierBars = document.getElementById("tier-bars");
        tierBars.innerHTML = "";
        data.tier_distribution.forEach(t => {
          const div = document.createElement("div");
          div.style.marginBottom = "10px";
          div.innerHTML = `
            <div style="display: flex; justify-content: space-between; font-size: 12px; margin-bottom: 4px;">
              <span>${t.tier} Tier (${t.redundancy})</span>
              <span>${t.files} files</span>
            </div>
            <div class="progress-bar-container" style="margin: 0;">
              <div class="progress-bar" style="width: ${(t.files / 128 * 100).toFixed(0)}%;"></div>
            </div>
          `;
          tierBars.appendChild(div);
        });
      });
  }

  // Resilience & Scrubbing
  function loadResilience() {
    fetch("/api/resilience/status")
      .then(res => res.json())
      .then(data => {
        document.getElementById("health-score-val").innerText = `${data.health_score_percent}%`;
        const logFeed = document.getElementById("scrub-log-console");
        logFeed.innerText = data.recent_scrub_logs.join("\n");
      });
  }

  document.getElementById("btn-trigger-scrub").addEventListener("click", () => {
    fetch("/api/resilience/scrub/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tier: "ALL", auto_repair: true })
    })
    .then(res => res.json())
    .then(data => {
      showToast(data.message);
      loadResilience();
    });
  });

  // Shared Links
  function loadSharedLinks() {
    fetch("/api/sharing/links")
      .then(res => res.json())
      .then(data => {
        const tbody = document.getElementById("shared-links-body");
        tbody.innerHTML = "";
        data.shared_links.forEach(l => {
          const tr = document.createElement("tr");
          tr.innerHTML = `
            <td><code>${l.link_id}</code></td>
            <td>${l.filename}</td>
            <td>${l.created_at}</td>
            <td>${l.expires_at}</td>
            <td>${l.access_count}</td>
            <td><button class="btn btn-sm btn-secondary" onclick="revokeLink('${l.link_id}')">Revoke</button></td>
          `;
          tbody.appendChild(tr);
        });
      });
  }

  window.revokeLink = (id) => {
    fetch(`/api/sharing/revoke/${id}`, { method: "DELETE" })
      .then(res => res.json())
      .then(data => {
        showToast(data.message);
        loadSharedLinks();
      });
  };

  // WebSocket Live Telemetry
  function connectWebSocketTelemetry() {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/api/telemetry/ws`;
    state.webSocket = new WebSocket(wsUrl);

    state.webSocket.onmessage = (event) => {
      const data = JSON.parse(event.data);
      document.getElementById("tel-upload").innerText = `${data.upload_speed_kbps} KB/s`;
      document.getElementById("tel-download").innerText = `${data.download_speed_kbps} KB/s`;
      document.getElementById("tel-threads").innerText = `${data.active_threads} Threads`;
      document.getElementById("tel-resources").innerText = `${data.ram_usage_mb} MB / ${data.cpu_usage_percent}%`;

      const feed = document.getElementById("telemetry-log-feed");
      const timestamp = new Date().toLocaleTimeString();
      feed.innerText += `\n[${timestamp}] ${data.log_message} (UL: ${data.upload_speed_kbps} KB/s)`;
      feed.scrollTop = feed.scrollHeight;
    };
  }

  // Toast Helper
  function showToast(msg) {
    const container = document.getElementById("toast-container");
    const toast = document.createElement("div");
    toast.className = "glass-card";
    toast.style.padding = "10px 16px";
    toast.style.marginBottom = "8px";
    toast.style.fontSize = "12px";
    toast.innerText = msg;
    container.appendChild(toast);
    setTimeout(() => toast.remove(), 4000);
  }

  window.downloadFile = (id) => {
    window.open(`/api/files/download/${id}`, "_blank");
  };

  window.deleteFile = (id) => {
    fetch("/api/files/delete", {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ file_id: id, purge: false })
    })
    .then(res => res.json())
    .then(data => {
      showToast(data.message);
      loadFileList();
    });
  };
});
