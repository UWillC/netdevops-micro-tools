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
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(
      `Request failed (${res.status}): ${text || res.statusText}`
    );
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
      if (field.tagName === "SELECT" || field.tagName === "INPUT" || field.tagName === "TEXTAREA") {
        field.value = value;
      }
    });
  } catch (_) {
    // ignore
  }
}

// -----------------------------
// Profiles (Lab / Branch / DC)
// -----------------------------
const profiles = {
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

function applyProfile(profileKey) {
  const profile = profiles[profileKey];
  if (!profile) return;

  // SNMPv3
  const snmpForm = document.getElementById("snmpv3-form");
  if (snmpForm && profile.snmp) {
    const set = (name, val) => {
      const field = snmpForm.querySelector(`[name="${name}"]`);
      if (field && val) field.value = val;
    };
    set("host", profile.snmp.host);
    set("user", profile.snmp.user);
    set("group", profile.snmp.group);
    set("auth_password", profile.snmp.auth_password);
    set("priv_password", profile.snmp.priv_password);
  }

  // NTP
  const ntpForm = document.getElementById("ntp-form");
  if (ntpForm && profile.ntp) {
    const set = (name, val) => {
      const field = ntpForm.querySelector(`[name="${name}"]`);
      if (field && val) field.value = val;
    };
    set("primary_server", profile.ntp.primary_server);
    set("secondary_server", profile.ntp.secondary_server);
    set("timezone", profile.ntp.timezone);
  }

  // AAA
  const aaaForm = document.getElementById("aaa-form");
  if (aaaForm && profile.aaa) {
    const set = (name, val) => {
      const field = aaaForm.querySelector(`[name="${name}"]`);
      if (field && val) field.value = val;
    };
    set("enable_secret", profile.aaa.enable_secret);
    set("tacacs1_name", profile.aaa.tacacs1_name);
    set("tacacs1_ip", profile.aaa.tacacs1_ip);
    set("tacacs1_key", profile.aaa.tacacs1_key);
  }
}

// Global profile selector
const globalProfileSelect = document.getElementById("global-profile");
const applyProfileBtn = document.getElementById("apply-profile");

if (applyProfileBtn && globalProfileSelect) {
  applyProfileBtn.addEventListener("click", () => {
    const key = globalProfileSelect.value;
    if (!key) return;
    applyProfile(key);
  });
}

// -----------------------------
// SNMPv3 form
// -----------------------------
const snmpForm = document.getElementById("snmpv3-form");
const snmpOutput = document.getElementById("snmpv3-output");

if (snmpForm && snmpOutput) {
  // load previous state
  loadFormState("snmpv3-form", snmpForm);

  snmpForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    snmpOutput.value = "Generating SNMPv3 config...";

    const formData = new FormData(snmpForm);
    const payload = {
      mode: formData.get("mode"),
      device: formData.get("device"),
      host: formData.get("host"),
      user: formData.get("user"),
      group: formData.get("group"),
      auth_password: formData.get("auth_password"),
      priv_password: formData.get("priv_password"),
      output_format: formData.get("output_format"),
    };

    // save last used values
    saveFormState("snmpv3-form", snmpForm);

    try {
      const data = await postJSON("/generate/snmpv3", payload);
      snmpOutput.value = data.config || "";
    } catch (err) {
      snmpOutput.value = `Error: ${err.message}`;
    }
  });
}

// -----------------------------
// NTP form
// -----------------------------
const ntpForm = document.getElementById("ntp-form");
const ntpOutput = document.getElementById("ntp-output");

if (ntpForm && ntpOutput) {
  loadFormState("ntp-form", ntpForm);

  ntpForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    ntpOutput.value = "Generating NTP config...";

    const formData = new FormData(ntpForm);
    const useAuth = formData.get("use_auth") === "true";

    const payload = {
      device: formData.get("device"),
      primary_server: formData.get("primary_server"),
      secondary_server: formData.get("secondary_server") || null,
      timezone: formData.get("timezone"),
      use_auth: useAuth,
      key_id: useAuth ? formData.get("key_id") || null : null,
      key_value: useAuth ? formData.get("key_value") || null : null,
      output_format: formData.get("output_format"),
    };

    saveFormState("ntp-form", ntpForm);

    try {
      const data = await postJSON("/generate/ntp", payload);
      ntpOutput.value = data.config || "";
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

if (aaaForm && aaaOutput) {
  loadFormState("aaa-form", aaaForm);

  aaaForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    aaaOutput.value = "Generating AAA config...";

    const formData = new FormData(aaaForm);

    const payload = {
      device: formData.get("device"),
      mode: formData.get("mode") === "local-only" ? "local-only" : "tacacs",
      enable_secret: formData.get("enable_secret") || null,
      tacacs1_name: formData.get("tacacs1_name") || null,
      tacacs1_ip: formData.get("tacacs1_ip") || null,
      tacacs1_key: formData.get("tacacs1_key") || null,
      tacacs2_name: formData.get("tacacs2_name") || null,
      tacacs2_ip: formData.get("tacacs2_ip") || null,
      tacacs2_key: formData.get("tacacs2_key") || null,
      source_interface: formData.get("source_interface") || null,
      output_format: formData.get("output_format"),
    };

    saveFormState("aaa-form", aaaForm);

    try {
      const data = await postJSON("/generate/aaa", payload);
      aaaOutput.value = data.config || "";
    } catch (err) {
      aaaOutput.value = `Error: ${err.message}`;
    }
  });
}

// -----------------------------
// Golden Config form
// -----------------------------
const goldenForm = document.getElementById("golden-form");
const goldenOutput = document.getElementById("golden-output");

if (goldenForm && goldenOutput) {
  loadFormState("golden-form", goldenForm);

  goldenForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    goldenOutput.value = "Generating Golden Config...";

    const formData = new FormData(goldenForm);

    const payload = {
      device: formData.get("device"),
      mode: formData.get("mode"),
      snmpv3_config: formData.get("snmpv3_config") || null,
      ntp_config: formData.get("ntp_config") || null,
      aaa_config: formData.get("aaa_config") || null,
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
// CVE Analyzer form
// -----------------------------
const cveForm = document.getElementById("cve-form");
const cveOutput = document.getElementById("cve-output");
const cveSummary = document.getElementById("cve-summary");

if (cveForm && cveOutput) {
  loadFormState("cve-form", cveForm);

  cveForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    cveOutput.value = "Analyzing CVEs...";

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
        let out = "No CVEs matched for this platform/version.\n\n";
        cveOutput.value = out;

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

      let out = "";
      out += `Platform: ${data.platform}\n`;
      out += `Version: ${data.version}\n`;
      out += `Timestamp: ${data.timestamp}\n\n`;

      out += "Matched CVEs:\n";
      data.matched.forEach((cve) => {
        out += `${cve.cve_id} [${cve.severity.toUpperCase()}]\n`;
        out += `  Title: ${cve.title}\n`;
        out += `  Tags: ${cve.tags.join(", ")}\n`;
        out += `  Description: ${cve.description}\n`;
        if (cve.fixed_in) out += `  Fixed in: ${cve.fixed_in}\n`;
        if (cve.workaround) out += `  Workaround: ${cve.workaround}\n`;
        out += `  Advisory: ${cve.advisory_url}\n\n`;
      });

      out += "Summary:\n";
      Object.entries(data.summary).forEach(([sev, count]) => {
        out += `  ${sev}: ${count}\n`;
      });

      if (data.recommended_upgrade) {
        out += `\nRecommended upgrade target: ${data.recommended_upgrade}\n`;
      }

      cveOutput.value = out;

      if (cveSummary) {
        const s = data.summary || {};
        const critical = s.critical || 0;
        const high = s.high || 0;
        const medium = s.medium || 0;
        const low = s.low || 0;

        cveSummary.innerHTML = `
          <h3>Security posture</h3>
          <div class="summary-row">
            <span>Severity breakdown</span>
          </div>
          <div class="summary-row">
            <span>
              <span class="severity-badge sev-critical">CRITICAL</span>
              <span class="severity-badge sev-high">HIGH</span>
              <span class="severity-badge sev-medium">MEDIUM</span>
              <span class="severity-badge sev-low">LOW</span>
            </span>
          </div>
          <div class="summary-row">
            <span>Counts</span>
            <span>${critical} / ${high} / ${medium} / ${low}</span>
          </div>
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
// Profiles UI v2 (backend-driven)
// Endpoints used:
// - GET    /profiles/list            -> { profiles: ["lab", "branch"] }
// - GET    /profiles/load/{name}     -> DeviceProfile JSON
// - POST   /profiles/save            -> DeviceProfile JSON
// - DELETE /profiles/delete/{name}   -> { status: "deleted" }
// -----------------------------

const profilesSelect = document.getElementById("profiles-select");
const profilesRefreshBtn = document.getElementById("profiles-refresh");
const profilesLoadBtn = document.getElementById("profiles-load");
const profilesDeleteBtn = document.getElementById("profiles-delete");
const profilesSaveBtn = document.getElementById("profiles-save");

const profileNameInput = document.getElementById("profile-name");
const profileDescriptionInput = document.getElementById("profile-description");

const profilesStatus = document.getElementById("profiles-status");
const profilesPreview = document.getElementById("profiles-preview");

function setProfilesStatus(message) {
  if (!profilesStatus) return;
  profilesStatus.textContent = message;
}

function setProfilesPreview(message) {
  if (!profilesPreview) return;
  profilesPreview.textContent = message;
}

async function fetchProfilesList() {
  const data = await fetch(`${API_BASE_URL}/profiles/list`);
  if (!data.ok) {
    throw new Error(`Profiles list failed (${data.status})`);
  }
  return data.json();
}

async function fetchProfile(name) {
  const res = await fetch(`${API_BASE_URL}/profiles/load/${encodeURIComponent(name)}`);
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
  const res = await fetch(`${API_BASE_URL}/profiles/delete/${encodeURIComponent(name)}`, {
    method: "DELETE",
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Delete failed (${res.status}): ${text || "unknown error"}`);
  }
  return res.json();
}

function getCurrentFormSnapshot() {
  // SNMPv3 form snapshot
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
  // Applies only SNMP/NTP/AAA keys that exist in the profile payload.
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

  // Persist form state in localStorage (re-using your existing persistence)
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
    const profiles = data.profiles || [];

    if (profiles.length === 0) {
      profilesSelect.innerHTML = `<option value="">(no profiles found)</option>`;
      setProfilesStatus("No profiles found on the backend. Save one to get started.");
      return;
    }

    profiles.forEach((name) => {
      const opt = document.createElement("option");
      opt.value = name;
      opt.textContent = name;
      profilesSelect.appendChild(opt);
    });

    setProfilesStatus(`Loaded ${profiles.length} profile(s).`);
  } catch (err) {
    setProfilesStatus(`Error: ${err.message}`);
  }
}

function getSelectedProfileName() {
  if (!profilesSelect) return "";
  return profilesSelect.value || "";
}

// Wire up buttons
if (profilesRefreshBtn) {
  profilesRefreshBtn.addEventListener("click", async () => {
    await refreshProfilesUI();
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

      // Update UI fields for visibility
      if (profileNameInput) profileNameInput.value = profile.name || name;
      if (profileDescriptionInput) profileDescriptionInput.value = profile.description || "";

      setProfilesStatus(`Profile loaded: ${name}. Forms updated.`);
      setProfilesPreview(JSON.stringify(profile, null, 2));
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

    setProfilesStatus(`Deleting profile: ${name}...`);

    try {
      await deleteProfile(name);
      setProfilesStatus(`Deleted profile: ${name}`);
      await refreshProfilesUI();
    } catch (err) {
      setProfilesStatus(`Error: ${err.message}`);
    }
  });
}

if (profilesSaveBtn) {
  profilesSaveBtn.addEventListener("click", async () => {
    const name = (profileNameInput && profileNameInput.value || "").trim();
    const description = (profileDescriptionInput && profileDescriptionInput.value || "").trim();

    if (!name) {
      setProfilesStatus("Profile name is required.");
      return;
    }

    // Build payload from current form values
    const snapshot = getCurrentFormSnapshot();
    const payload = {
      name,
      description: description || null,
      snmp: snapshot.snmp,
      ntp: snapshot.ntp,
      aaa: snapshot.aaa,
    };

    setProfilesStatus(`Saving profile: ${name}...`);

    try {
      await saveProfile(payload);
      setProfilesStatus(`Saved profile: ${name}`);
      setProfilesPreview(JSON.stringify(payload, null, 2));
      await refreshProfilesUI();
      if (profilesSelect) profilesSelect.value = name;
    } catch (err) {
      setProfilesStatus(`Error: ${err.message}`);
    }
  });
}

// Auto-load list on page load
refreshProfilesUI();
