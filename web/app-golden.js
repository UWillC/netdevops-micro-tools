// Depends on: app-core.js (postJSON, saveFormState, loadFormState, showToast)

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

