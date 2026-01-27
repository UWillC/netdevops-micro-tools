// Change this if your API runs on a different host/port
const API_BASE_URL = "http://127.0.0.1:8000";

// -----------------------------
// Tabs
// -----------------------------
const tabButtons = document.querySelectorAll(".tab-button");
const tabContents = document.querySelectorAll(".tab-content");

tabButtons.forEach((btn) => {
  btn.addEventListener("click", () => {
    const tab = btn.dataset.tab;

    tabButtons.forEach((b) => b.classList.remove("active"));
    tabContents.forEach((c) => c.classList.remove("active"));

    btn.classList.add("active");
    const section = document.getElementById(`tab-${tab}`);
    if (section) section.classList.add("active");

    // Update Golden Config payload status when switching to that tab
    if (tab === "golden-config" && typeof updateGoldenPayloadStatus === "function") {
      updateGoldenPayloadStatus();
    }
  });
});

// -----------------------------
// Copy to clipboard buttons
// -----------------------------
document
  .querySelectorAll(".btn-secondary[data-copy-target]")
  .forEach((btn) => {
    btn.addEventListener("click", () => {
      const targetId = btn.dataset.copyTarget;
      const textarea = document.getElementById(targetId);
      if (!textarea) return;

      textarea.select();
      textarea.setSelectionRange(0, 99999);
      document.execCommand("copy");

      const original = btn.textContent;
      btn.textContent = "Copied!";
      setTimeout(() => {
        btn.textContent = original;
      }, 1200);
    });
  });

// -----------------------------
// Download buttons (.txt files)
// -----------------------------
document
  .querySelectorAll(".btn-secondary[data-download-target]")
  .forEach((btn) => {
    btn.addEventListener("click", () => {
      const targetId = btn.dataset.downloadTarget;
      const filename = btn.dataset.filename || "config.txt";
      const textarea = document.getElementById(targetId);
      if (!textarea) return;

      const blob = new Blob([textarea.value || ""], {
        type: "text/plain;charset=utf-8",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    });
  });

// -----------------------------
// Helper: generic POST JSON
// -----------------------------
async function postJSON(path, payload) {
  const res = await fetch(`${API_BASE_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Request failed (${res.status}): ${text || res.statusText}`);
  }

  return res.json();
}

// -----------------------------
// LocalStorage helpers
// -----------------------------
function saveFormState(key, formElement) {
  const data = {};
  const formData = new FormData(formElement);
  formData.forEach((value, name) => {
    data[name] = value;
  });
  localStorage.setItem(key, JSON.stringify(data));
}

function loadFormState(key, formElement) {
  const raw = localStorage.getItem(key);
  if (!raw) return;
  try {
    const data = JSON.parse(raw);
    Object.entries(data).forEach(([name, value]) => {
      const field = formElement.querySelector(`[name="${name}"]`);
      if (!field || value === undefined || value === null) return;
      if (
        field.tagName === "SELECT" ||
        field.tagName === "INPUT" ||
        field.tagName === "TEXTAREA"
      ) {
        field.value = value;
      }
    });
  } catch (_) {
    // ignore
  }
}

// -----------------------------
// Toast helper (UX polish)
// -----------------------------
function showToast(title, message) {
  const existing = document.getElementById("toast");
  if (existing) existing.remove();

  const div = document.createElement("div");
  div.id = "toast";
  div.className = "toast";
  div.innerHTML = `
    <div class="toast-title">${title}</div>
    <div>${message}</div>
  `;
  document.body.appendChild(div);

  setTimeout(() => {
    const el = document.getElementById("toast");
    if (el) el.remove();
  }, 2200);
}

// -----------------------------
// Quick profiles (legacy presets)
// -----------------------------
const profilesPresets = {
  "lab-router": {
    snmp: {
      host: "10.0.0.10",
      user: "lab-monitor",
      group: "lab_grp",
      auth_password: "LabSnmpAuth123",
      priv_password: "LabSnmpPriv123",
    },
    ntp: {
      primary_server: "0.pool.ntp.org",
      secondary_server: "1.pool.ntp.org",
      timezone: "UTC",
    },
    aaa: {
      enable_secret: "LabEnable123",
      tacacs1_name: "lab-tacacs",
      tacacs1_ip: "10.0.0.20",
      tacacs1_key: "LabTacacsKey123",
    },
  },
  "branch-router": {
    snmp: {
      host: "192.168.10.10",
      user: "branch-monitor",
      group: "branch_grp",
      auth_password: "BranchAuth123",
      priv_password: "BranchPriv123",
    },
    ntp: {
      primary_server: "192.168.0.1",
      secondary_server: "0.pool.ntp.org",
      timezone: "UTC",
    },
    aaa: {
      enable_secret: "BranchEnable123",
      tacacs1_name: "branch-tacacs",
      tacacs1_ip: "172.16.0.10",
      tacacs1_key: "BranchTacacsKey123",
    },
  },
  "dc-router": {
    snmp: {
      host: "10.1.1.10",
      user: "dc-monitor",
      group: "dc_grp",
      auth_password: "DcAuth123",
      priv_password: "DcPriv123",
    },
    ntp: {
      primary_server: "time.google.com",
      secondary_server: "1.pool.ntp.org",
      timezone: "UTC",
    },
    aaa: {
      enable_secret: "DcEnable123",
      tacacs1_name: "dc-tacacs",
      tacacs1_ip: "10.1.1.20",
      tacacs1_key: "DcTacacsKey123",
    },
  },
};

function applyPresetProfile(profileKey) {
  const profile = profilesPresets[profileKey];
  if (!profile) return;

  const snmpForm = document.getElementById("snmpv3-form");
  const ntpForm = document.getElementById("ntp-form");
  const aaaForm = document.getElementById("aaa-form");

  const setField = (form, name, val) => {
    if (!form) return;
    const field = form.querySelector(`[name="${name}"]`);
    if (!field) return;
    if (val === undefined || val === null || val === "") return;
    field.value = val;
  };

  if (snmpForm && profile.snmp) {
    setField(snmpForm, "host", profile.snmp.host);
    setField(snmpForm, "user", profile.snmp.user);
    setField(snmpForm, "group", profile.snmp.group);
    setField(snmpForm, "auth_password", profile.snmp.auth_password);
    setField(snmpForm, "priv_password", profile.snmp.priv_password);
    saveFormState("snmpv3-form", snmpForm);
  }

  if (ntpForm && profile.ntp) {
    setField(ntpForm, "primary_server", profile.ntp.primary_server);
    setField(ntpForm, "secondary_server", profile.ntp.secondary_server);
    setField(ntpForm, "timezone", profile.ntp.timezone);
    saveFormState("ntp-form", ntpForm);
  }

  if (aaaForm && profile.aaa) {
    setField(aaaForm, "enable_secret", profile.aaa.enable_secret);
    setField(aaaForm, "tacacs1_name", profile.aaa.tacacs1_name);
    setField(aaaForm, "tacacs1_ip", profile.aaa.tacacs1_ip);
    setField(aaaForm, "tacacs1_key", profile.aaa.tacacs1_key);
    saveFormState("aaa-form", aaaForm);
  }
}

const globalProfileSelect = document.getElementById("global-profile");
const applyProfileBtn = document.getElementById("apply-profile");

if (applyProfileBtn && globalProfileSelect) {
  applyProfileBtn.addEventListener("click", () => {
    const key = globalProfileSelect.value;
    if (!key) return;
    applyPresetProfile(key);
    showToast("Profile applied", key);
  });
}

// -----------------------------
// SNMPv3 form (v2 - with ACL support)
// -----------------------------
const snmpForm = document.getElementById("snmpv3-form");
const snmpOutput = document.getElementById("snmpv3-output");
const snmpUseAcl = document.getElementById("snmp-use-acl");

// Toggle visibility of ACL fields
function updateSnmpAclFieldsVisibility() {
  const show = snmpUseAcl && snmpUseAcl.value === "true";
  document.querySelectorAll(".snmp-acl-field").forEach((el) => {
    if (show) el.classList.add("visible");
    else el.classList.remove("visible");
  });
}

if (snmpUseAcl) {
  snmpUseAcl.addEventListener("change", updateSnmpAclFieldsVisibility);
  updateSnmpAclFieldsVisibility(); // initial state
}

// Toggle visibility of Logging Level field (Single SNMP)
const snmpLoggingEnabled = document.getElementById("snmp-logging-enabled");

function updateSnmpLoggingFieldsVisibility() {
  const show = snmpLoggingEnabled && snmpLoggingEnabled.value === "true";
  document.querySelectorAll(".snmp-logging-field").forEach((el) => {
    if (show) el.classList.add("visible");
    else el.classList.remove("visible");
  });
}

if (snmpLoggingEnabled) {
  snmpLoggingEnabled.addEventListener("change", updateSnmpLoggingFieldsVisibility);
  updateSnmpLoggingFieldsVisibility(); // initial state
}

if (snmpForm && snmpOutput) {
  loadFormState("snmpv3-form", snmpForm);
  // Re-apply visibility after loading state
  updateSnmpAclFieldsVisibility();
  updateSnmpLoggingFieldsVisibility();

  snmpForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    snmpOutput.value = "Generating SNMPv3 config (Cisco Best Practices)...";

    const formData = new FormData(snmpForm);
    const useAcl = formData.get("use_acl") === "true";

    const packetsizeVal = formData.get("packetsize");

    // Collect selected traps (checkboxes)
    const selectedTraps = [];
    snmpForm.querySelectorAll('input[name="traps"]:checked').forEach((cb) => {
      selectedTraps.push(cb.value);
    });

    // Logging settings
    const loggingEnabled = formData.get("logging_enabled") === "true";

    const payload = {
      mode: formData.get("mode"),
      access_mode: formData.get("access_mode"),
      device: formData.get("device"),
      host: formData.get("host"),
      user: formData.get("user"),
      group: formData.get("group"),
      auth_password: formData.get("auth_password"),
      priv_password: formData.get("priv_password"),
      use_acl: useAcl,
      acl_hosts: useAcl ? formData.get("acl_hosts") || null : null,
      source_interface: formData.get("source_interface") || null,
      packetsize: packetsizeVal ? parseInt(packetsizeVal, 10) : null,
      contact: formData.get("contact") || null,
      location: formData.get("location") || null,
      traps: selectedTraps.length > 0 ? selectedTraps : null,
      logging_enabled: loggingEnabled,
      logging_level: loggingEnabled ? formData.get("logging_level") : "informational",
      output_format: formData.get("output_format"),
    };

    saveFormState("snmpv3-form", snmpForm);

    try {
      const data = await postJSON("/generate/snmpv3", payload);
      snmpOutput.value = data.config || "";
      // Store last generated config for Golden Config integration
      if (data.config) {
        localStorage.setItem("lastGeneratedSnmpv3", data.config);
        // Store payload (without output_format) for Golden Config refactor
        const payloadForGolden = { ...payload };
        delete payloadForGolden.output_format;
        localStorage.setItem("lastPayloadSnmpv3", JSON.stringify(payloadForGolden));
        // Update Golden Config status indicators
        if (typeof updateGoldenPayloadStatus === "function") {
          updateGoldenPayloadStatus();
        }
      }
    } catch (err) {
      snmpOutput.value = `Error: ${err.message}`;
    }
  });
}

// -----------------------------
// NTP form (v2 - Cisco Best Practices)
// -----------------------------
const ntpForm = document.getElementById("ntp-form");
const ntpOutput = document.getElementById("ntp-output");
const ntpUseAuth = document.getElementById("ntp-use-auth");
const ntpUseAcl = document.getElementById("ntp-use-acl");

// Toggle visibility of auth fields
function updateNtpAuthFieldsVisibility() {
  const show = ntpUseAuth && ntpUseAuth.value === "true";
  document.querySelectorAll(".ntp-auth-field").forEach((el) => {
    if (show) el.classList.add("visible");
    else el.classList.remove("visible");
  });
}

// Toggle visibility of ACL fields
function updateNtpAclFieldsVisibility() {
  const show = ntpUseAcl && ntpUseAcl.value === "true";
  document.querySelectorAll(".ntp-acl-field").forEach((el) => {
    if (show) el.classList.add("visible");
    else el.classList.remove("visible");
  });
}

// NTP Tier configuration - labels and placeholders per tier
const ntpTierConfig = {
  CORE: {
    title: "NTP Sources (External)",
    primary: { label: "GPS / Stratum 1 Source (prefer)", placeholder: "time.nist.gov or GPS receiver IP" },
    secondary: { label: "Alternate Stratum 1", placeholder: "time.google.com" },
    tertiary: { label: "Backup Stratum 1 (optional)", placeholder: "time.cloudflare.com" },
    showCoreFields: true,
  },
  DISTRIBUTION: {
    title: "NTP Sources (CORE Routers)",
    primary: { label: "Primary CORE Router (prefer)", placeholder: "10.0.0.1 (core-rtr01)" },
    secondary: { label: "Secondary CORE Router", placeholder: "10.0.0.2 (core-rtr02)" },
    tertiary: { label: "Backup CORE (optional)", placeholder: "10.0.0.3 or external NTP" },
    showCoreFields: false,
  },
  ACCESS: {
    title: "NTP Sources (Upstream)",
    primary: { label: "Primary Upstream (prefer)", placeholder: "10.0.0.1 (dist/core)" },
    secondary: { label: "Secondary Upstream", placeholder: "10.0.0.2" },
    tertiary: { label: "Tertiary Upstream (optional)", placeholder: "10.0.0.3" },
    showCoreFields: false,
  },
};

const ntpNetworkTier = document.getElementById("ntp-network-tier");
const ntpUseMaster = document.getElementById("ntp-use-master");

// Update NTP form based on selected tier
function updateNtpTierFields() {
  if (!ntpNetworkTier) return;

  const tier = ntpNetworkTier.value;
  const config = ntpTierConfig[tier] || ntpTierConfig.ACCESS;

  // Update title
  const titleEl = document.getElementById("ntp-servers-title");
  if (titleEl) titleEl.textContent = config.title;

  // Update labels and placeholders
  const primaryLabel = document.getElementById("ntp-primary-label");
  const primaryInput = document.getElementById("ntp-primary-input");
  const secondaryLabel = document.getElementById("ntp-secondary-label");
  const secondaryInput = document.getElementById("ntp-secondary-input");
  const tertiaryLabel = document.getElementById("ntp-tertiary-label");
  const tertiaryInput = document.getElementById("ntp-tertiary-input");

  if (primaryLabel) primaryLabel.textContent = config.primary.label;
  if (primaryInput) primaryInput.placeholder = config.primary.placeholder;
  if (secondaryLabel) secondaryLabel.textContent = config.secondary.label;
  if (secondaryInput) secondaryInput.placeholder = config.secondary.placeholder;
  if (tertiaryLabel) tertiaryLabel.textContent = config.tertiary.label;
  if (tertiaryInput) tertiaryInput.placeholder = config.tertiary.placeholder;

  // Show/hide CORE-only fields
  document.querySelectorAll(".ntp-core-field").forEach((el) => {
    if (config.showCoreFields) el.classList.add("visible");
    else el.classList.remove("visible");
  });

  // Also update master field visibility
  updateNtpMasterFieldVisibility();
}

// Toggle visibility of NTP Master stratum field
function updateNtpMasterFieldVisibility() {
  const tierIsCORE = ntpNetworkTier && ntpNetworkTier.value === "CORE";
  const masterEnabled = ntpUseMaster && ntpUseMaster.value === "true";
  const show = tierIsCORE && masterEnabled;

  document.querySelectorAll(".ntp-master-field").forEach((el) => {
    if (show) el.classList.add("visible");
    else el.classList.remove("visible");
  });
}

if (ntpNetworkTier) {
  ntpNetworkTier.addEventListener("change", updateNtpTierFields);
  updateNtpTierFields(); // initial state
}

if (ntpUseMaster) {
  ntpUseMaster.addEventListener("change", updateNtpMasterFieldVisibility);
}

if (ntpUseAuth) {
  ntpUseAuth.addEventListener("change", updateNtpAuthFieldsVisibility);
  updateNtpAuthFieldsVisibility(); // initial state
}

if (ntpUseAcl) {
  ntpUseAcl.addEventListener("change", updateNtpAclFieldsVisibility);
  updateNtpAclFieldsVisibility(); // initial state
}

if (ntpForm && ntpOutput) {
  loadFormState("ntp-form", ntpForm);
  // Re-apply visibility after loading state
  updateNtpTierFields();
  updateNtpAuthFieldsVisibility();
  updateNtpAclFieldsVisibility();

  ntpForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    ntpOutput.value = "Generating NTP config (Cisco Best Practices)...";

    const formData = new FormData(ntpForm);
    const useAuth = formData.get("use_auth") === "true";
    const useAcl = formData.get("use_access_control") === "true";
    const networkTier = formData.get("network_tier");

    // CORE-only settings
    const isCORE = networkTier === "CORE";
    const useNtpMaster = isCORE && formData.get("use_ntp_master") === "true";
    const ntpMasterStratum = useNtpMaster ? formData.get("ntp_master_stratum") || "3" : null;
    const ntpPeer = isCORE ? formData.get("ntp_peer") || null : null;

    const payload = {
      device: formData.get("device"),
      network_tier: networkTier,
      timezone: formData.get("timezone"),
      primary_server: formData.get("primary_server"),
      secondary_server: formData.get("secondary_server") || null,
      tertiary_server: formData.get("tertiary_server") || null,
      source_interface: formData.get("source_interface") || null,
      // CORE-only
      use_ntp_master: useNtpMaster,
      ntp_master_stratum: ntpMasterStratum,
      ntp_peer: ntpPeer,
      // Auth
      use_auth: useAuth,
      auth_algorithm: useAuth ? formData.get("auth_algorithm") : "sha1",
      key_id: useAuth ? formData.get("key_id") || null : null,
      key_value: useAuth ? formData.get("key_value") || null : null,
      use_logging: formData.get("use_logging") === "true",
      update_calendar: formData.get("update_calendar") === "true",
      use_access_control: useAcl,
      acl_peer_hosts: useAcl ? formData.get("acl_peer_hosts") || null : null,
      acl_serve_network: useAcl ? formData.get("acl_serve_network") || null : null,
      acl_serve_wildcard: useAcl ? formData.get("acl_serve_wildcard") || null : null,
      output_format: formData.get("output_format"),
    };

    saveFormState("ntp-form", ntpForm);

    try {
      const data = await postJSON("/generate/ntp", payload);
      ntpOutput.value = data.config || "";
      // Store last generated config for Golden Config integration
      if (data.config) {
        localStorage.setItem("lastGeneratedNtp", data.config);
        // Store payload (without output_format) for Golden Config refactor
        const payloadForGolden = { ...payload };
        delete payloadForGolden.output_format;
        localStorage.setItem("lastPayloadNtp", JSON.stringify(payloadForGolden));
        // Update Golden Config status indicators
        if (typeof updateGoldenPayloadStatus === "function") {
          updateGoldenPayloadStatus();
        }
      }
    } catch (err) {
      ntpOutput.value = `Error: ${err.message}`;
    }
  });
}

// -----------------------------
// AAA form
// -----------------------------
const aaaForm = document.getElementById("aaa-form");
const aaaOutput = document.getElementById("aaa-output");
const aaaModeSelect = document.getElementById("aaa-mode");

// Toggle TACACS-specific fields based on mode
function updateAaaModeFields() {
  if (!aaaModeSelect) return;
  const mode = aaaModeSelect.value;
  const tacacsFields = document.querySelectorAll(".aaa-tacacs-field");

  tacacsFields.forEach((el) => {
    if (mode === "tacacs") {
      el.classList.remove("hidden");
    } else {
      el.classList.add("hidden");
    }
  });
}

// Wire up mode change listener
if (aaaModeSelect) {
  aaaModeSelect.addEventListener("change", updateAaaModeFields);
  // Initialize on page load
  updateAaaModeFields();
}

if (aaaForm && aaaOutput) {
  loadFormState("aaa-form", aaaForm);
  // Re-apply mode visibility after loading saved state
  updateAaaModeFields();

  aaaForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    aaaOutput.value = "Generating AAA config...";

    const formData = new FormData(aaaForm);
    const mode = formData.get("mode") === "local-only" ? "local-only" : "tacacs";

    const payload = {
      device: formData.get("device"),
      mode: mode,
      // SSH Prerequisites
      domain_name: formData.get("domain_name") || null,
      ssh_modulus: formData.get("ssh_modulus") || "2048",
      ssh_version: formData.get("ssh_version") || "2",
      // Credentials
      enable_secret: formData.get("enable_secret") || null,
      use_sha256_secret: formData.get("use_sha256_secret") === "true",
      // Local Fallback User
      local_username: formData.get("local_username") || null,
      local_password: formData.get("local_password") || null,
      // TACACS+ Settings
      tacacs_group_name: formData.get("tacacs_group_name") || "TAC-SERVERS",
      tacacs1_name: formData.get("tacacs1_name") || null,
      tacacs1_ip: formData.get("tacacs1_ip") || null,
      tacacs1_key: formData.get("tacacs1_key") || null,
      tacacs2_name: formData.get("tacacs2_name") || null,
      tacacs2_ip: formData.get("tacacs2_ip") || null,
      tacacs2_key: formData.get("tacacs2_key") || null,
      source_interface: formData.get("source_interface") || null,
      server_timeout: formData.get("server_timeout") ? parseInt(formData.get("server_timeout")) : null,
      use_exec_accounting: formData.get("use_exec_accounting") === "true",
      use_command_accounting: formData.get("use_command_accounting") === "true",
      output_format: formData.get("output_format"),
    };

    saveFormState("aaa-form", aaaForm);

    try {
      const data = await postJSON("/generate/aaa", payload);
      aaaOutput.value = data.config || "";
      // Store last generated config for Golden Config integration
      if (data.config) {
        localStorage.setItem("lastGeneratedAaa", data.config);
        // Store payload (without output_format) for Golden Config refactor
        const payloadForGolden = { ...payload };
        delete payloadForGolden.output_format;
        localStorage.setItem("lastPayloadAaa", JSON.stringify(payloadForGolden));
        // Update Golden Config status indicators
        if (typeof updateGoldenPayloadStatus === "function") {
          updateGoldenPayloadStatus();
        }
      }
    } catch (err) {
      aaaOutput.value = `Error: ${err.message}`;
    }
  });
}

// -----------------------------
// iPerf3 form
// -----------------------------
const iperfForm = document.getElementById("iperf-form");
const iperfOutput = document.getElementById("iperf-output");

if (iperfForm && iperfOutput) {
  loadFormState("iperf-form", iperfForm);

  iperfForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    iperfOutput.value = "Generating iPerf3 commands...";

    const formData = new FormData(iperfForm);

    const payload = {
      link_speed: formData.get("link_speed"),
      test_type: formData.get("test_type"),
      direction: formData.get("direction"),
      server_ip: formData.get("server_ip"),
      port: parseInt(formData.get("port")) || 5201,
      port_secondary: parseInt(formData.get("port_secondary")) || 5202,
      duration: parseInt(formData.get("duration")) || 60,
      interval: parseInt(formData.get("interval")) || 10,
      parallel_streams: parseInt(formData.get("parallel_streams")) || 4,
      target_bandwidth: formData.get("target_bandwidth") || null,
      json_output: formData.get("json_output") === "true",
      output_format: formData.get("output_format"),
    };

    saveFormState("iperf-form", iperfForm);

    try {
      const data = await postJSON("/generate/iperf", payload);
      iperfOutput.value = data.config || "";
    } catch (err) {
      iperfOutput.value = `Error: ${err.message}`;
    }
  });
}

// -----------------------------
// Golden Config form
// -----------------------------
const goldenForm = document.getElementById("golden-form");
const goldenOutput = document.getElementById("golden-output");

// Check payload availability and update status indicators
function updateGoldenPayloadStatus() {
  // AAA - simple available/not available
  const aaaStatusEl = document.getElementById("aaa-payload-status");
  const aaaCheckboxEl = document.getElementById("golden-use-aaa");
  const aaaPayload = localStorage.getItem("lastPayloadAaa");

  if (aaaStatusEl) {
    if (aaaPayload) {
      aaaStatusEl.textContent = "✓ Available";
      aaaStatusEl.classList.add("available");
      aaaStatusEl.classList.remove("not-available");
    } else {
      aaaStatusEl.textContent = "✗ Not saved";
      aaaStatusEl.classList.add("not-available");
      aaaStatusEl.classList.remove("available");
    }
  }
  if (aaaCheckboxEl && aaaPayload) {
    aaaCheckboxEl.checked = true;
  }

  // NTP - show tier in status
  updateGoldenNtpStatus();

  // SNMP - depends on source selection (single/multi)
  updateGoldenSnmpStatus();
}

// Update NTP status showing saved tier (CORE/DIST/ACCESS)
function updateGoldenNtpStatus() {
  const statusEl = document.getElementById("ntp-payload-status");
  const checkboxEl = document.getElementById("golden-use-ntp");
  const payload = localStorage.getItem("lastPayloadNtp");

  if (!statusEl) return;

  if (payload) {
    try {
      const data = JSON.parse(payload);
      const tier = data.network_tier || "ACCESS";
      // Short labels: CORE, DIST, ACCESS
      const tierLabel = tier === "DISTRIBUTION" ? "DIST" : tier;
      statusEl.textContent = `✓ ${tierLabel}`;
    } catch {
      statusEl.textContent = "✓ Available";
    }
    statusEl.classList.add("available");
    statusEl.classList.remove("not-available");
    if (checkboxEl) checkboxEl.checked = true;
  } else {
    statusEl.textContent = "✗ Not saved";
    statusEl.classList.add("not-available");
    statusEl.classList.remove("available");
  }
}

// Update SNMP status based on selected source (single/multi)
function updateGoldenSnmpStatus() {
  const sourceSelect = document.getElementById("golden-snmp-source");
  const statusEl = document.getElementById("snmpv3-payload-status");
  const checkboxEl = document.getElementById("golden-use-snmpv3");

  if (!sourceSelect || !statusEl) return;

  const source = sourceSelect.value; // "single" or "multi"
  const key = source === "multi" ? "lastPayloadSnmpv3Multi" : "lastPayloadSnmpv3";
  const payload = localStorage.getItem(key);

  if (payload) {
    const label = source === "multi" ? "✓ Multi" : "✓ Single";
    statusEl.textContent = label;
    statusEl.classList.add("available");
    statusEl.classList.remove("not-available");
    if (checkboxEl) checkboxEl.checked = true;
  } else {
    const label = source === "multi" ? "✗ Multi not saved" : "✗ Single not saved";
    statusEl.textContent = label;
    statusEl.classList.add("not-available");
    statusEl.classList.remove("available");
  }
}

// Wire up SNMP source dropdown change
const goldenSnmpSource = document.getElementById("golden-snmp-source");
if (goldenSnmpSource) {
  goldenSnmpSource.addEventListener("change", updateGoldenSnmpStatus);
}

if (goldenForm && goldenOutput) {
  loadFormState("golden-form", goldenForm);
  updateGoldenPayloadStatus();

  goldenForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    goldenOutput.value = "Generating Golden Config...";

    const formData = new FormData(goldenForm);

    // Check if "Use saved config" checkboxes are checked
    const useSnmpv3 = document.getElementById("golden-use-snmpv3")?.checked;
    const useNtp = document.getElementById("golden-use-ntp")?.checked;
    const useAaa = document.getElementById("golden-use-aaa")?.checked;

    // Get SNMP source selection (single/multi)
    const snmpSource = document.getElementById("golden-snmp-source")?.value || "single";

    // Get payloads from localStorage if checkbox is checked
    let snmpv3Payload = null;
    let snmpv3MultiPayload = null;
    let ntpPayload = null;
    let aaaPayload = null;

    if (useSnmpv3) {
      if (snmpSource === "multi") {
        const stored = localStorage.getItem("lastPayloadSnmpv3Multi");
        if (stored) snmpv3MultiPayload = JSON.parse(stored);
      } else {
        const stored = localStorage.getItem("lastPayloadSnmpv3");
        if (stored) snmpv3Payload = JSON.parse(stored);
      }
    }
    if (useNtp) {
      const stored = localStorage.getItem("lastPayloadNtp");
      if (stored) ntpPayload = JSON.parse(stored);
    }
    if (useAaa) {
      const stored = localStorage.getItem("lastPayloadAaa");
      if (stored) aaaPayload = JSON.parse(stored);
    }

    const payload = {
      device: formData.get("device"),
      mode: formData.get("mode"),
      // Config strings (fallback when checkbox unchecked)
      snmpv3_config: !useSnmpv3 ? (formData.get("snmpv3_config") || null) : null,
      ntp_config: !useNtp ? (formData.get("ntp_config") || null) : null,
      aaa_config: !useAaa ? (formData.get("aaa_config") || null) : null,
      // Payloads (when checkbox checked)
      snmpv3_payload: snmpv3Payload,
      snmpv3_multi_payload: snmpv3MultiPayload,
      ntp_payload: ntpPayload,
      aaa_payload: aaaPayload,
      // Baseline sections (modular)
      include_banner: formData.get("include_banner") === "true",
      custom_banner: formData.get("custom_banner") || null,
      include_logging: formData.get("include_logging") === "true",
      include_security: formData.get("include_security") === "true",
      output_format: formData.get("output_format"),
    };

    saveFormState("golden-form", goldenForm);

    try {
      const data = await postJSON("/generate/golden-config", payload);
      goldenOutput.value = data.config || "";
    } catch (err) {
      goldenOutput.value = `Error: ${err.message}`;
    }
  });
}

// -----------------------------
// CVE Analyzer form (v0.3.1 data enrichment visible)
// + Security summary + Collapsible cards
// -----------------------------
const cveForm = document.getElementById("cve-form");
const cveOutput = document.getElementById("cve-output");
const cveSummary = document.getElementById("cve-summary");
const cveCards = document.getElementById("cve-cards");

function formatCvss(score) {
  if (score === null || score === undefined) return "N/A";
  const n = Number(score);
  if (Number.isNaN(n)) return "N/A";
  return n.toFixed(1);
}

if (cveForm && cveOutput) {
  loadFormState("cve-form", cveForm);

  cveForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    cveOutput.value = "Analyzing CVEs...";
    if (cveCards) cveCards.innerHTML = "";

    const formData = new FormData(cveForm);
    const payload = {
      platform: formData.get("platform"),
      version: formData.get("version"),
      include_suggestions: formData.get("include_suggestions") === "true",
    };

    saveFormState("cve-form", cveForm);

    try {
      const data = await postJSON("/analyze/cve", payload);

      if (!data.matched || data.matched.length === 0) {
        cveOutput.value = "No CVEs matched for this platform/version.\n";

        if (cveSummary) {
          cveSummary.innerHTML = `
            <h3>Security posture</h3>
            <p class="summary-muted">
              No CVEs from the current dataset matched this platform/version.
            </p>
          `;
        }
        return;
      }

      // Text report output
      let out = "";
      out += `Platform: ${data.platform}\n`;
      out += `Version: ${data.version}\n`;
      out += `Timestamp: ${data.timestamp}\n\n`;

      out += "Matched CVEs:\n";
      data.matched.forEach((cve) => {
        out += `${cve.cve_id} [${(cve.severity || "").toUpperCase()}]\n`;
        out += `  Title: ${cve.title}\n`;
        out += `  Source: ${cve.source || "N/A"}\n`;
        out += `  CVSS: ${formatCvss(cve.cvss_score)}${
          cve.cvss_vector ? ` (${cve.cvss_vector})` : ""
        }\n`;
        if (cve.cwe) out += `  CWE: ${cve.cwe}\n`;
        out += `  Tags: ${(cve.tags || []).join(", ")}\n`;
        out += `  Description: ${cve.description}\n`;
        if (cve.fixed_in) out += `  Fixed in: ${cve.fixed_in}\n`;
        if (cve.workaround) out += `  Workaround: ${cve.workaround}\n`;
        out += `  Advisory: ${cve.advisory_url}\n`;
        if (cve.references && cve.references.length > 0) {
          out += `  References: ${cve.references.join(" | ")}\n`;
        }
        out += "\n";
      });

      out += "Summary:\n";
      Object.entries(data.summary || {}).forEach(([sev, count]) => {
        out += `  ${sev}: ${count}\n`;
      });

      if (data.recommended_upgrade) {
        out += `\nRecommended upgrade target: ${data.recommended_upgrade}\n`;
      }

      cveOutput.value = out;

      // Collapsible CVE cards
      if (cveCards) {
        const badgeClass = (sev) => {
          const s = (sev || "").toLowerCase();
          if (s === "critical") return "severity-badge sev-critical";
          if (s === "high") return "severity-badge sev-high";
          if (s === "medium") return "severity-badge sev-medium";
          return "severity-badge sev-low";
        };

        cveCards.innerHTML = "";
        data.matched.forEach((cve) => {
          const card = document.createElement("div");
          card.className = "cve-item";

          const metaBits = [];
          metaBits.push(`Source: ${cve.source || "N/A"}`);
          metaBits.push(`CVSS: ${formatCvss(cve.cvss_score)}`);
          if (cve.cwe) metaBits.push(`CWE: ${cve.cwe}`);
          if (cve.fixed_in) metaBits.push(`Fixed in: ${cve.fixed_in}`);

          card.innerHTML = `
            <div class="cve-item-header">
              <div>
                <div class="cve-item-title">
                  <span class="${badgeClass(cve.severity)}">${(cve.severity || "").toUpperCase()}</span>
                  ${cve.cve_id} — ${cve.title}
                </div>
                <div class="cve-item-meta">
                  ${metaBits.join(" • ")}
                </div>
                <div class="cve-item-meta">
                  Tags: ${(cve.tags || []).join(", ")}
                </div>
              </div>
              <div class="cve-item-meta">Click</div>
            </div>

            <div class="cve-item-body">
              <div><strong>Description:</strong> ${cve.description}</div>
              ${
                cve.workaround
                  ? `<div style="margin-top:8px;"><strong>Workaround:</strong> ${cve.workaround}</div>`
                  : ""
              }
              ${
                cve.advisory_url
                  ? `<div style="margin-top:8px;"><strong>Advisory:</strong> ${cve.advisory_url}</div>`
                  : ""
              }
              ${
                cve.references && cve.references.length > 0
                  ? `<div style="margin-top:8px;"><strong>References:</strong> ${cve.references.join(
                      " | "
                    )}</div>`
                  : ""
              }
            </div>
          `;

          const header = card.querySelector(".cve-item-header");
          const body = card.querySelector(".cve-item-body");
          header.addEventListener("click", () => {
            body.classList.toggle("open");
          });

          cveCards.appendChild(card);
        });
      }

      // Security posture summary (with Max CVSS)
      if (cveSummary) {
        const s = data.summary || {};
        const critical = s.critical || 0;
        const high = s.high || 0;
        const medium = s.medium || 0;
        const low = s.low || 0;

        const scores = (data.matched || [])
          .map((x) => Number(x.cvss_score))
          .filter((n) => !Number.isNaN(n));

        const maxCvss = scores.length ? Math.max(...scores) : null;

        cveSummary.innerHTML = `
          <h3>Security posture</h3>
          <div class="summary-row"><span>Severity breakdown</span></div>
          <div class="summary-row">
            <span>
              <span class="severity-badge sev-critical">CRITICAL</span>
              <span class="severity-badge sev-high">HIGH</span>
              <span class="severity-badge sev-medium">MEDIUM</span>
              <span class="severity-badge sev-low">LOW</span>
            </span>
          </div>
          <div class="summary-row"><span>Counts</span><span>${critical} / ${high} / ${medium} / ${low}</span></div>
          <div class="summary-row"><span>Max CVSS</span><span>${formatCvss(maxCvss)}</span></div>
          ${
            data.recommended_upgrade
              ? `<div class="summary-upgrade">
                   Recommended upgrade target:<br/>
                   <strong>${data.recommended_upgrade}</strong>
                 </div>`
              : `<div class="summary-upgrade summary-muted">
                   No specific upgrade target recommended based on current CVEs.
                 </div>`
          }
        `;
      }
    } catch (err) {
      cveOutput.value = `Error: ${err.message}`;
      if (cveSummary) {
        cveSummary.innerHTML = `
          <h3>Security posture</h3>
          <p class="summary-muted">Error during CVE analysis: ${err.message}</p>
        `;
      }
    }
  });
}

// -----------------------------
// Profiles UI v2 (backend-driven) + UX polish
// Endpoints used:
// - GET    /profiles/list
// - GET    /profiles/load/{name}
// - POST   /profiles/save
// - DELETE /profiles/delete/{name}
// -----------------------------
const profilesSearch = document.getElementById("profiles-search");
const profilesConfirmDelete = document.getElementById("profiles-confirm-delete");
const profilesSelect = document.getElementById("profiles-select");
const profilesRefreshBtn = document.getElementById("profiles-refresh");
const profilesLoadBtn = document.getElementById("profiles-load");
const profilesDeleteBtn = document.getElementById("profiles-delete");
const profilesSaveBtn = document.getElementById("profiles-save");

const profileNameInput = document.getElementById("profile-name");
const profileDescriptionInput = document.getElementById("profile-description");

const profilesStatus = document.getElementById("profiles-status");
const profilesSaveStatus = document.getElementById("profiles-save-status");
const profilesEditor = document.getElementById("profiles-editor");
const profilesEditorStatus = document.getElementById("profiles-editor-status");
const profilesUpdateBtn = document.getElementById("profiles-update");
const profilesApplyToFormsBtn = document.getElementById("profiles-apply-to-forms");

// View toggle elements
const profilesCreateView = document.getElementById("profiles-create-view");
const profilesEditView = document.getElementById("profiles-edit-view");
const profilesEditName = document.getElementById("profiles-edit-name");
const profilesNewBtn = document.getElementById("profiles-new");

let profilesCache = [];

function setProfilesStatus(message) {
  if (!profilesStatus) return;
  profilesStatus.textContent = message;
}

function setProfilesSaveStatus(message) {
  if (!profilesSaveStatus) return;
  profilesSaveStatus.textContent = message;
}

function setProfilesEditorStatus(message) {
  if (!profilesEditorStatus) return;
  profilesEditorStatus.textContent = message;
}

function setProfilesEditorContent(jsonObj) {
  if (!profilesEditor) return;
  profilesEditor.value = JSON.stringify(jsonObj, null, 2);
}

// View switching functions
function showCreateView() {
  if (profilesCreateView) profilesCreateView.style.display = "block";
  if (profilesEditView) profilesEditView.style.display = "none";
}

function showEditView(profileName) {
  if (profilesCreateView) profilesCreateView.style.display = "none";
  if (profilesEditView) profilesEditView.style.display = "block";
  if (profilesEditName) profilesEditName.textContent = profileName || "—";
}

function setBtnEnabled(btn, enabled) {
  if (!btn) return;
  if (enabled) btn.classList.remove("btn-disabled");
  else btn.classList.add("btn-disabled");
}

function getSelectedProfileName() {
  if (!profilesSelect) return "";
  return profilesSelect.value || "";
}

function updateProfilesButtonsState() {
  const hasSelection = !!getSelectedProfileName();
  setBtnEnabled(profilesLoadBtn, hasSelection);
  setBtnEnabled(profilesDeleteBtn, hasSelection);
}

async function fetchProfilesList() {
  const res = await fetch(`${API_BASE_URL}/profiles/list`);
  if (!res.ok) throw new Error(`Profiles list failed (${res.status})`);
  return res.json();
}

async function fetchProfile(name) {
  const res = await fetch(
    `${API_BASE_URL}/profiles/load/${encodeURIComponent(name)}`
  );
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Load failed (${res.status}): ${text || "unknown error"}`);
  }
  return res.json();
}

async function saveProfile(profilePayload) {
  const res = await fetch(`${API_BASE_URL}/profiles/save`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(profilePayload),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Save failed (${res.status}): ${text || "unknown error"}`);
  }
  return res.json();
}

async function deleteProfile(name) {
  const res = await fetch(
    `${API_BASE_URL}/profiles/delete/${encodeURIComponent(name)}`,
    {
      method: "DELETE",
    }
  );
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Delete failed (${res.status}): ${text || "unknown error"}`);
  }
  return res.json();
}

function renderProfilesOptions(filterText = "") {
  if (!profilesSelect) return;

  const ft = (filterText || "").toLowerCase();
  const filtered = profilesCache.filter((p) => p.toLowerCase().includes(ft));

  profilesSelect.innerHTML = "";

  if (filtered.length === 0) {
    const opt = document.createElement("option");
    opt.value = "";
    opt.textContent = "(no matches)";
    profilesSelect.appendChild(opt);
    updateProfilesButtonsState();
    return;
  }

  filtered.forEach((name) => {
    const opt = document.createElement("option");
    opt.value = name;
    opt.textContent = name;
    profilesSelect.appendChild(opt);
  });

  // Auto-select first after render (nice UX)
  profilesSelect.value = filtered[0] || "";
  updateProfilesButtonsState();
}

function getCurrentFormSnapshot() {
  const snmpForm = document.getElementById("snmpv3-form");
  const ntpForm = document.getElementById("ntp-form");
  const aaaForm = document.getElementById("aaa-form");

  const snmp = {};
  const ntp = {};
  const aaa = {};

  if (snmpForm) {
    const fd = new FormData(snmpForm);
    snmp.host = fd.get("host") || null;
    snmp.user = fd.get("user") || null;
    snmp.group = fd.get("group") || null;
    snmp.auth_password = fd.get("auth_password") || null;
    snmp.priv_password = fd.get("priv_password") || null;
  }

  if (ntpForm) {
    const fd = new FormData(ntpForm);
    ntp.primary_server = fd.get("primary_server") || null;
    ntp.secondary_server = fd.get("secondary_server") || null;
    ntp.timezone = fd.get("timezone") || null;
  }

  if (aaaForm) {
    const fd = new FormData(aaaForm);
    aaa.enable_secret = fd.get("enable_secret") || null;
    aaa.tacacs1_name = fd.get("tacacs1_name") || null;
    aaa.tacacs1_ip = fd.get("tacacs1_ip") || null;
    aaa.tacacs1_key = fd.get("tacacs1_key") || null;
    aaa.tacacs2_name = fd.get("tacacs2_name") || null;
    aaa.tacacs2_ip = fd.get("tacacs2_ip") || null;
    aaa.tacacs2_key = fd.get("tacacs2_key") || null;
  }

  return { snmp, ntp, aaa };
}

function applyProfileToForms(profileData) {
  const snmpForm = document.getElementById("snmpv3-form");
  const ntpForm = document.getElementById("ntp-form");
  const aaaForm = document.getElementById("aaa-form");

  const setField = (form, name, value) => {
    if (!form) return;
    const field = form.querySelector(`[name="${name}"]`);
    if (!field) return;
    if (value === undefined || value === null) return;
    field.value = value;
  };

  if (profileData.snmp) {
    setField(snmpForm, "host", profileData.snmp.host);
    setField(snmpForm, "user", profileData.snmp.user);
    setField(snmpForm, "group", profileData.snmp.group);
    setField(snmpForm, "auth_password", profileData.snmp.auth_password);
    setField(snmpForm, "priv_password", profileData.snmp.priv_password);
  }

  if (profileData.ntp) {
    setField(ntpForm, "primary_server", profileData.ntp.primary_server);
    setField(ntpForm, "secondary_server", profileData.ntp.secondary_server);
    setField(ntpForm, "timezone", profileData.ntp.timezone);
  }

  if (profileData.aaa) {
    setField(aaaForm, "enable_secret", profileData.aaa.enable_secret);
    setField(aaaForm, "tacacs1_name", profileData.aaa.tacacs1_name);
    setField(aaaForm, "tacacs1_ip", profileData.aaa.tacacs1_ip);
    setField(aaaForm, "tacacs1_key", profileData.aaa.tacacs1_key);
    setField(aaaForm, "tacacs2_name", profileData.aaa.tacacs2_name);
    setField(aaaForm, "tacacs2_ip", profileData.aaa.tacacs2_ip);
    setField(aaaForm, "tacacs2_key", profileData.aaa.tacacs2_key);
  }

  if (snmpForm) saveFormState("snmpv3-form", snmpForm);
  if (ntpForm) saveFormState("ntp-form", ntpForm);
  if (aaaForm) saveFormState("aaa-form", aaaForm);
}

async function refreshProfilesUI() {
  if (!profilesSelect) return;

  setProfilesStatus("Loading profiles...");
  profilesSelect.innerHTML = "";

  try {
    const data = await fetchProfilesList();
    profilesCache = data.profiles || [];

    if (profilesCache.length === 0) {
      profilesSelect.innerHTML = `<option value="">(no profiles found)</option>`;
      setProfilesStatus(
        "No profiles found on the backend. Save one to get started."
      );
      updateProfilesButtonsState();
      return;
    }

    renderProfilesOptions(profilesSearch ? profilesSearch.value : "");
    setProfilesStatus(`Loaded ${profilesCache.length} profile(s).`);
  } catch (err) {
    setProfilesStatus(`Error: ${err.message}`);
    updateProfilesButtonsState();
  }
}

// Wire up listeners once (no duplicates)
if (profilesSelect) {
  profilesSelect.addEventListener("change", () => {
    updateProfilesButtonsState();
  });
}

if (profilesSearch) {
  profilesSearch.addEventListener("input", () => {
    renderProfilesOptions(profilesSearch.value);
  });
}

if (profilesRefreshBtn) {
  profilesRefreshBtn.addEventListener("click", async () => {
    await refreshProfilesUI();
    showToast("Profiles", "Refreshed list");
  });
}

if (profilesLoadBtn) {
  profilesLoadBtn.addEventListener("click", async () => {
    const name = getSelectedProfileName();
    if (!name) {
      setProfilesStatus("Select a profile first.");
      return;
    }

    setProfilesStatus(`Loading profile: ${name}...`);

    try {
      const profile = await fetchProfile(name);
      applyProfileToForms(profile);

      if (profileNameInput) profileNameInput.value = profile.name || name;
      if (profileDescriptionInput)
        profileDescriptionInput.value = profile.description || "";

      setProfilesStatus(`Profile loaded: ${name}. Forms updated.`);
      setProfilesEditorContent(profile);
      setProfilesEditorStatus(`Editing: ${name}`);
      showToast("Profile loaded", name);

      // Switch to Edit view
      showEditView(name);
    } catch (err) {
      setProfilesStatus(`Error: ${err.message}`);
    }
  });
}

if (profilesDeleteBtn) {
  profilesDeleteBtn.addEventListener("click", async () => {
    const name = getSelectedProfileName();
    if (!name) {
      setProfilesStatus("Select a profile first.");
      return;
    }

    if (!profilesConfirmDelete || !profilesConfirmDelete.checked) {
      setProfilesStatus("Tick the confirmation checkbox before deleting.");
      showToast(
        "Delete blocked",
        "Enable confirmation checkbox to delete a profile."
      );
      return;
    }

    setProfilesStatus(`Deleting profile: ${name}...`);

    try {
      await deleteProfile(name);
      setProfilesStatus(`Deleted profile: ${name}`);
      setProfilesEditorStatus(`Deleted: ${name}`);
      if (profilesEditor) profilesEditor.value = "";
      if (profilesConfirmDelete) profilesConfirmDelete.checked = false;
      showToast("Profile deleted", name);
      await refreshProfilesUI();
    } catch (err) {
      setProfilesStatus(`Error: ${err.message}`);
    }
  });
}

if (profilesSaveBtn) {
  profilesSaveBtn.addEventListener("click", async () => {
    const name = ((profileNameInput && profileNameInput.value) || "").trim();
    const description = (
      (profileDescriptionInput && profileDescriptionInput.value) ||
      ""
    ).trim();

    if (!name) {
      setProfilesStatus("Profile name is required.");
      return;
    }

    // Check if this is an update (profile exists) or create (new profile)
    const isUpdate = profilesCache.includes(name);

    const snapshot = getCurrentFormSnapshot();
    const payload = {
      name,
      description: description || null,
      snmp: snapshot.snmp,
      ntp: snapshot.ntp,
      aaa: snapshot.aaa,
    };

    const action = isUpdate ? "Updating" : "Saving";
    setProfilesStatus(`${action} profile: ${name}...`);

    try {
      await saveProfile(payload);

      const actionDone = isUpdate ? "updated" : "saved";
      const actionTitle = isUpdate ? "Profile updated" : "Profile saved";

      setProfilesSaveStatus(`Profile ${actionDone}: ${name}`);
      setProfilesEditorContent(payload);
      setProfilesEditorStatus(`Saved: ${name}`);
      showToast(actionTitle, name);
      await refreshProfilesUI();

      // keep selection after refresh if available
      if (profilesSelect) profilesSelect.value = name;
      updateProfilesButtonsState();
    } catch (err) {
      setProfilesStatus(`Error: ${err.message}`);
    }
  });
}

// Update profile from editor (JSON)
if (profilesUpdateBtn) {
  profilesUpdateBtn.addEventListener("click", async () => {
    if (!profilesEditor || !profilesEditor.value.trim()) {
      setProfilesEditorStatus("Editor is empty. Load a profile first.");
      return;
    }

    let profileData;
    try {
      profileData = JSON.parse(profilesEditor.value);
    } catch (err) {
      setProfilesEditorStatus(`Invalid JSON: ${err.message}`);
      showToast("JSON Error", "Invalid JSON format");
      return;
    }

    if (!profileData.name) {
      setProfilesEditorStatus("Profile must have a 'name' field.");
      return;
    }

    setProfilesEditorStatus(`Updating profile: ${profileData.name}...`);

    try {
      await saveProfile(profileData);
      setProfilesEditorStatus(`Profile updated: ${profileData.name}`);
      showToast("Profile updated", profileData.name);
      await refreshProfilesUI();

      // Keep selection
      if (profilesSelect) profilesSelect.value = profileData.name;
      updateProfilesButtonsState();
    } catch (err) {
      setProfilesEditorStatus(`Error: ${err.message}`);
    }
  });
}

// Apply editor JSON to forms
if (profilesApplyToFormsBtn) {
  profilesApplyToFormsBtn.addEventListener("click", () => {
    if (!profilesEditor || !profilesEditor.value.trim()) {
      setProfilesEditorStatus("Editor is empty. Load a profile first.");
      return;
    }

    let profileData;
    try {
      profileData = JSON.parse(profilesEditor.value);
    } catch (err) {
      setProfilesEditorStatus(`Invalid JSON: ${err.message}`);
      showToast("JSON Error", "Invalid JSON format");
      return;
    }

    applyProfileToForms(profileData);

    if (profileNameInput && profileData.name) {
      profileNameInput.value = profileData.name;
    }
    if (profileDescriptionInput && profileData.description) {
      profileDescriptionInput.value = profileData.description;
    }

    setProfilesEditorStatus("Applied to forms. Switch to generator tabs to see values.");
    showToast("Applied to forms", profileData.name || "profile");
  });
}

// New Profile button → switch to Create view
if (profilesNewBtn) {
  profilesNewBtn.addEventListener("click", () => {
    showCreateView();
    // Clear form fields for new profile
    if (profileNameInput) profileNameInput.value = "";
    if (profileDescriptionInput) profileDescriptionInput.value = "";
    setProfilesSaveStatus("");
  });
}

// Initial state
updateProfilesButtonsState();
refreshProfilesUI();

// -----------------------------
// v0.3.5: Vulnerability Status Widget
// -----------------------------
const vulnRefreshBtn = document.getElementById("vuln-refresh");
const vulnContent = document.getElementById("vuln-content");

async function fetchVulnerabilities() {
  const res = await fetch(`${API_BASE_URL}/profiles/vulnerabilities`);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Vulnerabilities check failed (${res.status}): ${text || "unknown error"}`);
  }
  return res.json();
}

function renderVulnerabilityWidget(data) {
  if (!vulnContent) return;

  const { summary, results, profiles_checked } = data;

  // Build summary badges
  const summaryItems = [];
  if (summary.critical > 0) summaryItems.push(`<span class="vuln-summary-item critical">Critical: ${summary.critical}</span>`);
  if (summary.high > 0) summaryItems.push(`<span class="vuln-summary-item high">High: ${summary.high}</span>`);
  if (summary.medium > 0) summaryItems.push(`<span class="vuln-summary-item medium">Medium: ${summary.medium}</span>`);
  if (summary.low > 0) summaryItems.push(`<span class="vuln-summary-item low">Low: ${summary.low}</span>`);
  if (summary.clean > 0) summaryItems.push(`<span class="vuln-summary-item clean">Clean: ${summary.clean}</span>`);
  if (summary.unknown > 0) summaryItems.push(`<span class="vuln-summary-item unknown">Unknown: ${summary.unknown}</span>`);

  // Build profile rows
  const profileRows = results.map((r) => {
    const meta = r.platform && r.version ? `${r.platform} • ${r.version}` : "No platform/version";
    const cveText = r.cve_count > 0 ? `${r.cve_count} CVE${r.cve_count > 1 ? "s" : ""}` : "";
    const maxCvss = r.max_cvss !== null ? `CVSS ${r.max_cvss.toFixed(1)}` : "";
    const statusInfo = [cveText, maxCvss].filter(Boolean).join(" • ");

    return `
      <div class="vuln-profile-row">
        <div class="vuln-profile-info">
          <div class="vuln-profile-name">${r.profile_name}</div>
          <div class="vuln-profile-meta">${meta}</div>
        </div>
        <div class="vuln-profile-status">
          ${statusInfo ? `<span class="vuln-cve-count">${statusInfo}</span>` : ""}
          <span class="vuln-status-badge ${r.status}">${r.status}</span>
        </div>
      </div>
    `;
  }).join("");

  vulnContent.innerHTML = `
    <div class="vuln-summary">
      ${summaryItems.join("")}
    </div>
    <div class="vuln-profiles-list">
      ${profileRows}
    </div>
    <p class="summary-muted" style="margin-top: 10px; font-size: 0.78rem;">
      Checked ${profiles_checked} profile(s) • ${data.timestamp}
    </p>
  `;
}

async function refreshVulnerabilityWidget() {
  if (!vulnContent) return;

  vulnContent.innerHTML = `<p class="summary-muted">Loading vulnerability status...</p>`;

  try {
    const data = await fetchVulnerabilities();
    renderVulnerabilityWidget(data);
    showToast("Vulnerabilities", `Checked ${data.profiles_checked} profiles`);
  } catch (err) {
    vulnContent.innerHTML = `<p class="summary-muted">Error: ${err.message}</p>`;
  }
}

if (vulnRefreshBtn) {
  vulnRefreshBtn.addEventListener("click", refreshVulnerabilityWidget);
}

// -----------------------------
// v0.4.0: Security Score Widget
// -----------------------------
const scoreRefreshBtn = document.getElementById("score-refresh");
const scoreContent = document.getElementById("score-content");

async function fetchSecurityScores() {
  const res = await fetch(`${API_BASE_URL}/profiles/security-scores`);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Security scores failed (${res.status}): ${text || "unknown error"}`);
  }
  return res.json();
}

function getScoreColor(label) {
  const colors = {
    "Excellent": "#22c55e",
    "Good": "#84cc16",
    "Fair": "#eab308",
    "Poor": "#f97316",
    "Critical": "#ef4444",
  };
  return colors[label] || "#6b7280";
}

function renderSecurityScoreWidget(data) {
  if (!scoreContent) return;

  const { summary, results, profiles_checked, average_score, lowest_score, highest_score } = data;

  // Build summary badges
  const summaryItems = [];
  if (summary.excellent > 0) summaryItems.push(`<span class="score-summary-item excellent">Excellent: ${summary.excellent}</span>`);
  if (summary.good > 0) summaryItems.push(`<span class="score-summary-item good">Good: ${summary.good}</span>`);
  if (summary.fair > 0) summaryItems.push(`<span class="score-summary-item fair">Fair: ${summary.fair}</span>`);
  if (summary.poor > 0) summaryItems.push(`<span class="score-summary-item poor">Poor: ${summary.poor}</span>`);
  if (summary.critical > 0) summaryItems.push(`<span class="score-summary-item critical">Critical: ${summary.critical}</span>`);
  if (summary.unknown > 0) summaryItems.push(`<span class="score-summary-item unknown">Unknown: ${summary.unknown}</span>`);

  // Build profile rows
  const profileRows = results.map((r) => {
    const meta = r.platform && r.version ? `${r.platform} • ${r.version}` : "No platform/version";
    const scoreDisplay = r.score !== null ? r.score : "—";
    const labelDisplay = r.label || "Unknown";
    const scoreColor = getScoreColor(r.label);

    // CVE breakdown summary
    let breakdownHtml = "";
    if (r.cve_breakdown && r.cve_breakdown.length > 0) {
      const cveItems = r.cve_breakdown.map((b) => {
        const mods = b.modifiers_applied.length > 0 ? ` (${b.modifiers_applied.join(", ")})` : "";
        return `<div class="score-cve-item">${b.cve_id}: -${b.final_penalty.toFixed(1)}${mods}</div>`;
      }).join("");
      breakdownHtml = `<div class="score-breakdown">${cveItems}</div>`;
    }

    return `
      <div class="score-profile-row">
        <div class="score-profile-info">
          <div class="score-profile-name">${r.profile_name}</div>
          <div class="score-profile-meta">${meta}</div>
          ${breakdownHtml}
        </div>
        <div class="score-profile-score">
          <div class="score-badge" style="background: ${scoreColor};">${scoreDisplay}</div>
          <div class="score-label">${labelDisplay}</div>
        </div>
      </div>
    `;
  }).join("");

  // Stats line
  const statsLine = average_score !== null
    ? `Avg: ${average_score} • Low: ${lowest_score} • High: ${highest_score}`
    : "No scores available";

  scoreContent.innerHTML = `
    <div class="score-stats">${statsLine}</div>
    <div class="score-summary">
      ${summaryItems.join("")}
    </div>
    <div class="score-profiles-list">
      ${profileRows}
    </div>
    <p class="summary-muted" style="margin-top: 10px; font-size: 0.78rem;">
      Scored ${profiles_checked} profile(s) • ${data.timestamp}
    </p>
  `;
}

async function refreshSecurityScoreWidget() {
  if (!scoreContent) return;

  scoreContent.innerHTML = `<p class="summary-muted">Calculating security scores...</p>`;

  try {
    const data = await fetchSecurityScores();
    renderSecurityScoreWidget(data);
    showToast("Security Scores", `Scored ${data.profiles_checked} profiles (avg: ${data.average_score || "N/A"})`);
  } catch (err) {
    scoreContent.innerHTML = `<p class="summary-muted">Error: ${err.message}</p>`;
  }
}

if (scoreRefreshBtn) {
  scoreRefreshBtn.addEventListener("click", refreshSecurityScoreWidget);
}

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

// -----------------------------
// Subnet Calculator
// -----------------------------
const subnetForm = document.getElementById("subnet-form");
const subnetOutput = document.getElementById("subnet-output");
const subnetAddress = document.getElementById("subnet-address");
const subnetNetmask = document.getElementById("subnet-netmask");
const subnetSplitSelect = document.getElementById("subnet-split-select");
const subnetAdvancedToggle = document.getElementById("subnet-advanced-toggle");
const subnetAdvancedSection = document.getElementById("subnet-advanced-section");
const subnetSupernetModal = document.getElementById("subnet-supernet-modal");
const subnetSupernetInput = document.getElementById("subnet-supernet-input");

// Toggle advanced section
if (subnetAdvancedToggle && subnetAdvancedSection) {
  subnetAdvancedToggle.addEventListener("click", () => {
    const isHidden = subnetAdvancedSection.style.display === "none";
    subnetAdvancedSection.style.display = isHidden ? "block" : "none";
    subnetAdvancedToggle.textContent = isHidden ? "Advanced Options ▲" : "Advanced Options ▼";
  });
}

// Format subnet info results
function formatSubnetInfo(data, splitData = null) {
  const info = data.subnet_info;
  let result = `
IP Subnet Calculator
====================

Input: ${data.input}

Network Information
-------------------
Network Address:    ${info.network}
Broadcast Address:  ${info.broadcast}
CIDR Notation:      ${info.cidr}
Netmask:            ${info.netmask}
Wildcard Mask:      ${info.wildcard}

Host Range
----------
First Usable Host:  ${info.first_host}
Last Usable Host:   ${info.last_host}
Total Addresses:    ${info.total_addresses.toLocaleString()}
Usable Hosts:       ${info.usable_hosts.toLocaleString()}

Additional Info
---------------
Network Class:      ${info.network_class}
Private Network:    ${info.is_private ? "Yes" : "No"}

Binary Netmask
--------------
${info.netmask_binary}
`;

  // Add split results if available
  if (splitData) {
    result += `

Subnet Split (/${splitData.new_prefix})
${"=".repeat(20)}
Total Subnets:      ${splitData.total_subnets}
Hosts per Subnet:   ${splitData.hosts_per_subnet}

`;
    splitData.subnets.forEach((s) => {
      result += `#${s.index.toString().padStart(2, "0")} | ${s.cidr.padEnd(18)} | ${s.first_host} - ${s.last_host}\n`;
    });

    if (splitData.truncated) {
      result += `\n... (showing first 64 of ${splitData.total_subnets} subnets)`;
    }
  }

  return result.trim();
}

// Format supernet results
function formatSupernet(data) {
  let result = `
Supernet / Aggregation
======================

Input Networks: ${data.input_count}
`;

  data.input_networks.forEach((n) => {
    result += `  - ${n}\n`;
  });

  result += `
Result: ${data.result_count} network(s)
`;

  data.result_networks.forEach((n) => {
    result += `  → ${n.cidr} (${n.usable_hosts.toLocaleString()} usable hosts)\n`;
  });

  result += `
${data.aggregation_possible ? "✓ Networks were successfully aggregated" : "✗ Networks could not be aggregated (not contiguous)"}
`;

  return result.trim();
}

// Main form submit
if (subnetForm && subnetOutput) {
  subnetForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    let address = subnetAddress ? subnetAddress.value.trim() : "";
    let netmask = subnetNetmask ? subnetNetmask.value.trim() : "/24";

    if (!address) {
      subnetOutput.value = "Error: Please enter an IP address";
      return;
    }

    // Normalize netmask
    if (netmask && !netmask.startsWith("/") && !netmask.includes(".")) {
      netmask = "/" + netmask;
    }

    // Combine address and netmask
    let ipCidr = address;
    if (!address.includes("/")) {
      if (netmask.startsWith("/")) {
        ipCidr = address + netmask;
      } else {
        // Convert dotted decimal to CIDR - let backend handle it
        try {
          const convertData = await postJSON("/tools/subnet/convert", { value: netmask });
          ipCidr = address + "/" + convertData.prefix;
        } catch (err) {
          subnetOutput.value = `Error: Invalid netmask "${netmask}"`;
          return;
        }
      }
    }

    subnetOutput.value = "Calculating...";

    try {
      // Get main subnet info
      const data = await postJSON("/tools/subnet/info", { ip_cidr: ipCidr });

      // Check if split is requested
      let splitData = null;
      if (subnetSplitSelect && subnetSplitSelect.value) {
        const newPrefix = parseInt(subnetSplitSelect.value, 10);
        if (newPrefix > data.subnet_info.prefix_length) {
          splitData = await postJSON("/tools/subnet/split", { ip_cidr: ipCidr, new_prefix: newPrefix });
        }
      }

      subnetOutput.value = formatSubnetInfo(data, splitData);
    } catch (err) {
      subnetOutput.value = `Error: ${err.message}`;
    }
  });
}

// Supernet tool toggle
const subnetSupernetBtn = document.getElementById("subnet-supernet-btn");
const subnetSupernetCloseBtn = document.getElementById("subnet-supernet-close-btn");
const subnetSupernetCalcBtn = document.getElementById("subnet-supernet-calc-btn");

if (subnetSupernetBtn && subnetSupernetModal) {
  subnetSupernetBtn.addEventListener("click", (e) => {
    e.preventDefault();
    subnetSupernetModal.style.display = "block";
  });
}

if (subnetSupernetCloseBtn && subnetSupernetModal) {
  subnetSupernetCloseBtn.addEventListener("click", () => {
    subnetSupernetModal.style.display = "none";
  });
}

if (subnetSupernetCalcBtn && subnetSupernetInput && subnetOutput) {
  subnetSupernetCalcBtn.addEventListener("click", async () => {
    const input = subnetSupernetInput.value.trim();
    if (!input) {
      subnetOutput.value = "Error: Please enter at least 2 networks (one per line)";
      return;
    }

    const networks = input.split("\n").map((n) => n.trim()).filter((n) => n.length > 0);

    if (networks.length < 2) {
      subnetOutput.value = "Error: Please enter at least 2 networks for aggregation";
      return;
    }

    subnetOutput.value = "Calculating supernet...";

    try {
      const data = await postJSON("/tools/subnet/supernet", { networks: networks });
      subnetOutput.value = formatSupernet(data);
    } catch (err) {
      subnetOutput.value = `Error: ${err.message}`;
    }
  });
}

// =============================================
// MTU CALCULATOR
// =============================================

const mtuForm = document.getElementById("mtu-form");
const mtuOutput = document.getElementById("mtu-output");
const mtuInterfaceMtu = document.getElementById("mtu-interface");
const mtuTunnelType = document.getElementById("mtu-tunnel-type");
const mtuMplsLabels = document.getElementById("mtu-mpls-labels");
const mtuMplsRow = document.getElementById("mtu-mpls-row");
const mtuIncludeMss = document.getElementById("mtu-include-mss");

// Show/hide MPLS labels field based on tunnel type
if (mtuTunnelType && mtuMplsRow) {
  mtuTunnelType.addEventListener("change", () => {
    mtuMplsRow.style.display = mtuTunnelType.value === "mpls" ? "flex" : "none";
  });
}

// Format MTU result
function formatMtuResult(data) {
  let result = `MTU Calculation Results
=======================

Interface MTU:    ${data.interface_mtu} bytes
Tunnel Type:      ${data.tunnel_type}
Overhead:         ${data.overhead_bytes} bytes
  └─ ${data.overhead_breakdown}

Effective MTU:    ${data.effective_mtu} bytes`;

  if (data.tcp_mss) {
    result += `
TCP MSS:          ${data.tcp_mss} bytes`;
  }

  if (data.warnings && data.warnings.length > 0) {
    result += `

⚠️  Warnings
`;
    data.warnings.forEach((w) => {
      result += `  • ${w}\n`;
    });
  }

  if (data.recommendations && data.recommendations.length > 0) {
    result += `
📋 Recommendations
`;
    data.recommendations.forEach((r) => {
      result += `  • ${r}\n`;
    });
  }

  return result.trim();
}

// MTU form submit handler
if (mtuForm && mtuOutput) {
  mtuForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    const interfaceMtu = parseInt(mtuInterfaceMtu?.value || "1500", 10);
    const tunnelType = mtuTunnelType?.value || "gre";
    const mplsLabels = parseInt(mtuMplsLabels?.value || "1", 10);
    const includeMss = mtuIncludeMss?.checked ?? true;

    mtuOutput.value = "Calculating...";

    try {
      const data = await postJSON("/tools/mtu/calculate", {
        interface_mtu: interfaceMtu,
        tunnel_type: tunnelType,
        mpls_labels: mplsLabels,
        include_tcp_mss: includeMss,
      });

      mtuOutput.value = formatMtuResult(data);
    } catch (err) {
      mtuOutput.value = `Error: ${err.message}`;
    }
  });
}

// Initialize MTU hints panel
initHintsPanel("mtu-hints-panel", "mtu-hints-toggle");
