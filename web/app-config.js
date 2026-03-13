// Depends on: app-core.js (postJSON, saveFormState, loadFormState, showToast, updateGoldenPayloadStatus)

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

      // Update download filename based on format
      const downloadBtn = document.querySelector('[data-download-target="iperf-output"]');
      if (downloadBtn) {
        const formatExtensions = {
          cli: "iperf3_commands.txt",
          bash: "iperf3_test.sh",
          powershell: "iperf3_test.ps1",
          python: "iperf3_test.py",
        };
        downloadBtn.dataset.filename = formatExtensions[payload.output_format] || "iperf3_commands.txt";
      }
    } catch (err) {
      iperfOutput.value = `Error: ${err.message}`;
    }
  });
}
