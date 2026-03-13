// Depends on: app-core.js (postJSON, showToast, saveFormState, loadFormState)

// -----------------------------
// Hints panels (collapsible + click-to-copy)
// -----------------------------
function initHintsPanel(panelId, toggleId) {
  const panel = document.getElementById(panelId);
  const toggle = document.getElementById(toggleId);

  if (!panel || !toggle) return;

  // Start collapsed by default
  panel.classList.add("collapsed");

  toggle.addEventListener("click", () => {
    panel.classList.toggle("collapsed");
  });
}

// Initialize all hints panels
initHintsPanel("snmpv3-hints-panel", "snmpv3-hints-toggle");
initHintsPanel("ntp-hints-panel", "ntp-hints-toggle");
initHintsPanel("aaa-hints-panel", "aaa-hints-toggle");
initHintsPanel("golden-hints-panel", "golden-hints-toggle");
initHintsPanel("iperf-hints-panel", "iperf-hints-toggle");
initHintsPanel("subnet-hints-panel", "subnet-hints-toggle");

// Click-to-copy for hints code blocks
document.querySelectorAll(".hints-code").forEach((codeEl) => {
  codeEl.addEventListener("click", () => {
    const text = codeEl.textContent;

    // Copy to clipboard
    navigator.clipboard.writeText(text).then(() => {
      codeEl.classList.add("copied");
      const original = codeEl.textContent;
      codeEl.textContent = "Copied!";

      setTimeout(() => {
        codeEl.textContent = original;
        codeEl.classList.remove("copied");
      }, 1000);
    }).catch(() => {
      // Fallback for older browsers
      const textarea = document.createElement("textarea");
      textarea.value = text;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand("copy");
      document.body.removeChild(textarea);

      codeEl.classList.add("copied");
      const original = codeEl.textContent;
      codeEl.textContent = "Copied!";

      setTimeout(() => {
        codeEl.textContent = original;
        codeEl.classList.remove("copied");
      }, 1000);
    });
  });
});

// -----------------------------
// Command Tooltips (hover)
// -----------------------------
(function() {
  // Create tooltip element
  const tooltip = document.createElement("div");
  tooltip.className = "command-tooltip";
  document.body.appendChild(tooltip);

  // Add hover listeners to hints-code elements with data-tooltip
  document.querySelectorAll(".hints-code[data-tooltip]").forEach((codeEl) => {
    codeEl.addEventListener("mouseenter", (e) => {
      const text = codeEl.dataset.tooltip;
      if (!text) return;

      tooltip.textContent = text;

      // Get element position
      const rect = codeEl.getBoundingClientRect();
      const tooltipHeight = 120; // Approximate height

      // Position above or below based on available space
      let top;
      if (rect.top > tooltipHeight + 20) {
        // Show above
        top = rect.top - tooltipHeight - 10;
      } else {
        // Show below
        top = rect.bottom + 10;
      }

      // Keep within viewport horizontally
      let left = rect.left;
      const tooltipWidth = 320;
      if (left + tooltipWidth > window.innerWidth - 20) {
        left = window.innerWidth - tooltipWidth - 20;
      }

      tooltip.style.top = top + "px";
      tooltip.style.left = left + "px";
      tooltip.classList.add("visible");
    });

    codeEl.addEventListener("mouseleave", () => {
      tooltip.classList.remove("visible");
    });
  });
})();

// -----------------------------
// Golden Config: Go to generator buttons
// -----------------------------
document.querySelectorAll(".golden-goto-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    const targetTab = btn.dataset.gotoTab;
    if (!targetTab) return;

    // Find and click the corresponding tab button
    const tabBtn = document.querySelector(`.tab-button[data-tab="${targetTab}"]`);
    if (tabBtn) {
      tabBtn.click();
      showToast("Switched to", `${targetTab.toUpperCase()} Generator`);
    }
  });
});

// -----------------------------
// Golden Config: Insert from generator buttons
// -----------------------------
document.querySelectorAll(".golden-insert-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    const sourceKey = btn.dataset.insertSource;
    const targetId = btn.dataset.insertTarget;

    if (!sourceKey || !targetId) return;

    const storedConfig = localStorage.getItem(sourceKey);
    const targetTextarea = document.getElementById(targetId);

    if (!targetTextarea) return;

    if (!storedConfig) {
      // No config generated yet
      const generatorName = sourceKey.replace("lastGenerated", "").toUpperCase();
      showToast("No config found", `Generate a ${generatorName} config first`);
      return;
    }

    // Insert the config
    targetTextarea.value = storedConfig;

    // Trigger input event to update hints
    targetTextarea.dispatchEvent(new Event("input"));

    // Visual feedback
    const configType = sourceKey.replace("lastGenerated", "");
    showToast("Config inserted", `${configType} config added`);
  });
});

// -----------------------------
// Golden Config: Hide hints when textarea has content
// -----------------------------
function updateGoldenConfigHints() {
  const configs = [
    { textarea: "golden-snmpv3-config", hint: "golden-snmp-hint" },
    { textarea: "golden-ntp-config", hint: "golden-ntp-hint" },
    { textarea: "golden-aaa-config", hint: "golden-aaa-hint" },
  ];

  configs.forEach(({ textarea, hint }) => {
    const textareaEl = document.getElementById(textarea);
    const hintEl = document.getElementById(hint);
    if (!textareaEl || !hintEl) return;

    if (textareaEl.value.trim()) {
      hintEl.classList.add("hidden");
    } else {
      hintEl.classList.remove("hidden");
    }
  });
}

// Listen for input changes on Golden Config textareas
["golden-snmpv3-config", "golden-ntp-config", "golden-aaa-config"].forEach((id) => {
  const el = document.getElementById(id);
  if (el) {
    el.addEventListener("input", updateGoldenConfigHints);
  }
});

// Initial check
updateGoldenConfigHints();

// -----------------------------
// SNMPv3 Multi-Host Generator (v3)
// -----------------------------
const snmpMultiForm = document.getElementById("snmp-multi-form");
const snmpMultiOutput = document.getElementById("snmp-multi-output");
const snmpMultiHostsContainer = document.getElementById("snmp-multi-hosts-container");
const snmpMultiAddHostBtn = document.getElementById("snmp-multi-add-host");

let snmpMultiHostCounter = 0;

function createSnmpHostCard(hostId, hostData = null) {
  const card = document.createElement("div");
  card.className = "snmp-host-card";
  card.dataset.hostId = hostId;

  const defaults = hostData || {
    name: "",
    ip_address: "",
    user_name: "",
    access_mode: "read-only",
    auth_algorithm: "sha-2 256",
    priv_algorithm: "aes 256",
    auth_password: "",
    priv_password: "",
  };

  card.innerHTML = `
    <div class="snmp-host-header">
      <span class="snmp-host-title">Host #${hostId + 1}</span>
      <button type="button" class="btn-remove-host" data-host-id="${hostId}">× Remove</button>
    </div>
    <div class="snmp-host-fields">
      <div class="snmp-host-row">
        <div class="snmp-host-field">
          <label>Name (remark/group)</label>
          <input type="text" name="host_${hostId}_name" value="${defaults.name}" placeholder="PRIME, WUG, SPLUNK..." />
        </div>
        <div class="snmp-host-field">
          <label>IP Address</label>
          <input type="text" name="host_${hostId}_ip" value="${defaults.ip_address}" placeholder="10.0.0.1" />
        </div>
        <div class="snmp-host-field">
          <label>User Name</label>
          <input type="text" name="host_${hostId}_user" value="${defaults.user_name}" placeholder="auto: {name}-user" />
        </div>
      </div>
      <div class="snmp-host-row">
        <div class="snmp-host-field">
          <label>Access Mode</label>
          <select name="host_${hostId}_access">
            <option value="read-only" ${defaults.access_mode === "read-only" ? "selected" : ""}>Read-Only</option>
            <option value="read-write" ${defaults.access_mode === "read-write" ? "selected" : ""}>Read-Write</option>
          </select>
        </div>
        <div class="snmp-host-field">
          <label>Auth Algorithm</label>
          <select name="host_${hostId}_auth_algo">
            <option value="sha-2 256" ${defaults.auth_algorithm === "sha-2 256" ? "selected" : ""}>SHA-2 256</option>
            <option value="sha-2 384" ${defaults.auth_algorithm === "sha-2 384" ? "selected" : ""}>SHA-2 384</option>
            <option value="sha-2 512" ${defaults.auth_algorithm === "sha-2 512" ? "selected" : ""}>SHA-2 512</option>
            <option value="sha" ${defaults.auth_algorithm === "sha" ? "selected" : ""}>SHA (legacy)</option>
            <option value="md5" ${defaults.auth_algorithm === "md5" ? "selected" : ""}>MD5 (legacy)</option>
          </select>
        </div>
        <div class="snmp-host-field">
          <label>Priv Algorithm</label>
          <select name="host_${hostId}_priv_algo">
            <option value="aes 256" ${defaults.priv_algorithm === "aes 256" ? "selected" : ""}>AES-256</option>
            <option value="aes 192" ${defaults.priv_algorithm === "aes 192" ? "selected" : ""}>AES-192</option>
            <option value="aes 128" ${defaults.priv_algorithm === "aes 128" ? "selected" : ""}>AES-128</option>
            <option value="3des" ${defaults.priv_algorithm === "3des" ? "selected" : ""}>3DES</option>
            <option value="des" ${defaults.priv_algorithm === "des" ? "selected" : ""}>DES (legacy)</option>
          </select>
        </div>
      </div>
      <div class="snmp-host-row">
        <div class="snmp-host-field">
          <label>Auth Password</label>
          <input type="password" name="host_${hostId}_auth_pass" value="${defaults.auth_password}" placeholder="Min 8 chars" />
        </div>
        <div class="snmp-host-field">
          <label>Priv Password</label>
          <input type="password" name="host_${hostId}_priv_pass" value="${defaults.priv_password}" placeholder="Min 8 chars" />
        </div>
      </div>
    </div>
  `;

  // Wire up remove button
  const removeBtn = card.querySelector(".btn-remove-host");
  removeBtn.addEventListener("click", () => {
    card.remove();
    updateHostCardTitles();
  });

  return card;
}

function updateHostCardTitles() {
  const cards = snmpMultiHostsContainer.querySelectorAll(".snmp-host-card");
  cards.forEach((card, index) => {
    const title = card.querySelector(".snmp-host-title");
    if (title) title.textContent = `Host #${index + 1}`;
  });
}

function addSnmpHost(hostData = null) {
  const card = createSnmpHostCard(snmpMultiHostCounter, hostData);
  snmpMultiHostsContainer.appendChild(card);
  snmpMultiHostCounter++;
}

function getSnmpMultiHosts() {
  const hosts = [];
  const cards = snmpMultiHostsContainer.querySelectorAll(".snmp-host-card");

  cards.forEach((card) => {
    const hostId = card.dataset.hostId;
    const getName = (suffix) => card.querySelector(`[name="host_${hostId}_${suffix}"]`)?.value || "";

    const host = {
      name: getName("name"),
      ip_address: getName("ip"),
      user_name: getName("user") || null,  // null = auto-generate as {name}-user
      access_mode: getName("access"),
      auth_algorithm: getName("auth_algo"),
      priv_algorithm: getName("priv_algo"),
      auth_password: getName("auth_pass"),
      priv_password: getName("priv_pass"),
    };

    // Only include hosts with at least name and IP
    if (host.name && host.ip_address) {
      hosts.push(host);
    }
  });

  return hosts;
}

function saveSnmpMultiState() {
  if (!snmpMultiForm) return;

  const formData = new FormData(snmpMultiForm);
  const state = {
    acl_name: formData.get("acl_name"),
    view_name: formData.get("view_name"),
    device: formData.get("device"),
    contact: formData.get("contact"),
    location: formData.get("location"),
    source_interface: formData.get("source_interface"),
    output_format: formData.get("output_format"),
    hosts: getSnmpMultiHosts(),
  };

  localStorage.setItem("snmp-multi-form", JSON.stringify(state));
}

function loadSnmpMultiState() {
  const raw = localStorage.getItem("snmp-multi-form");
  if (!raw) {
    // Add one empty host by default
    addSnmpHost();
    return;
  }

  try {
    const state = JSON.parse(raw);

    // Set form fields
    const setField = (name, value) => {
      const field = snmpMultiForm.querySelector(`[name="${name}"]`);
      if (field && value) field.value = value;
    };

    setField("acl_name", state.acl_name);
    setField("view_name", state.view_name);
    setField("device", state.device);
    setField("contact", state.contact);
    setField("location", state.location);
    setField("source_interface", state.source_interface);
    setField("output_format", state.output_format);

    // Restore hosts
    if (state.hosts && state.hosts.length > 0) {
      state.hosts.forEach((hostData) => addSnmpHost(hostData));
    } else {
      addSnmpHost();
    }
  } catch (_) {
    addSnmpHost();
  }
}

// Toggle visibility of Logging Level field (Multi SNMP)
const snmpMultiLoggingEnabled = document.getElementById("snmp-multi-logging-enabled");

function updateSnmpMultiLoggingFieldsVisibility() {
  const show = snmpMultiLoggingEnabled && snmpMultiLoggingEnabled.value === "true";
  document.querySelectorAll(".snmp-multi-logging-field").forEach((el) => {
    if (show) el.classList.add("visible");
    else el.classList.remove("visible");
  });
}

if (snmpMultiLoggingEnabled) {
  snmpMultiLoggingEnabled.addEventListener("change", updateSnmpMultiLoggingFieldsVisibility);
  updateSnmpMultiLoggingFieldsVisibility(); // initial state
}

// Initialize
if (snmpMultiHostsContainer) {
  loadSnmpMultiState();
}

if (snmpMultiAddHostBtn) {
  snmpMultiAddHostBtn.addEventListener("click", () => {
    addSnmpHost();
  });
}

if (snmpMultiForm && snmpMultiOutput) {
  snmpMultiForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    snmpMultiOutput.value = "Generating SNMPv3 Multi-Host config...";

    const formData = new FormData(snmpMultiForm);
    const hosts = getSnmpMultiHosts();

    if (hosts.length === 0) {
      snmpMultiOutput.value = "Error: Add at least one host with name and IP address.";
      return;
    }

    const packetsizeVal = formData.get("packetsize");

    // Collect selected traps (checkboxes)
    const selectedTraps = [];
    snmpMultiForm.querySelectorAll('input[name="traps"]:checked').forEach((cb) => {
      selectedTraps.push(cb.value);
    });

    // Logging settings
    const loggingEnabled = formData.get("logging_enabled") === "true";

    const payload = {
      acl_name: formData.get("acl_name") || "SNMP-POLLERS",
      view_name: formData.get("view_name") || "SECUREVIEW",
      device: formData.get("device") || "Cisco IOS XE",
      contact: formData.get("contact") || null,
      location: formData.get("location") || null,
      source_interface: formData.get("source_interface") || null,
      packetsize: packetsizeVal ? parseInt(packetsizeVal, 10) : null,
      traps: selectedTraps.length > 0 ? selectedTraps : null,
      logging_enabled: loggingEnabled,
      logging_level: loggingEnabled ? formData.get("logging_level") : "informational",
      output_format: formData.get("output_format") || "cli",
      hosts: hosts,
    };

    saveSnmpMultiState();

    try {
      const data = await postJSON("/generate/snmpv3/multi", payload);
      snmpMultiOutput.value = data.config || "";
      showToast("Config generated", `${hosts.length} host(s)`);

      // Store payload for Golden Config integration
      if (data.config) {
        localStorage.setItem("lastGeneratedSnmpv3Multi", data.config);
        const payloadForGolden = { ...payload };
        delete payloadForGolden.output_format;
        localStorage.setItem("lastPayloadSnmpv3Multi", JSON.stringify(payloadForGolden));
        // Update Golden Config status
        if (typeof updateGoldenSnmpStatus === "function") {
          updateGoldenSnmpStatus();
        }
      }
    } catch (err) {
      snmpMultiOutput.value = `Error: ${err.message}`;
    }
  });
}
