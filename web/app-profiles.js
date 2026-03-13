// Depends on: app-core.js (API_BASE_URL, saveFormState, showToast)

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

// v0.4.2: Export PDF button
const scoreExportPdfBtn = document.getElementById("score-export-pdf");
if (scoreExportPdfBtn) {
  scoreExportPdfBtn.addEventListener("click", async () => {
    scoreExportPdfBtn.disabled = true;
    scoreExportPdfBtn.textContent = "Generating...";

    try {
      const res = await fetch(`${API_BASE_URL}/export/security-report?format=pdf`);
      if (!res.ok) {
        throw new Error(`Export failed (${res.status})`);
      }

      // Get filename from Content-Disposition header or use default
      const contentDisposition = res.headers.get("Content-Disposition");
      let filename = "security-report.pdf";
      if (contentDisposition) {
        const match = contentDisposition.match(/filename=(.+)/);
        if (match) filename = match[1];
      }

      // Download the PDF
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      a.remove();

      showToast("Export PDF", "Security report downloaded successfully!");
    } catch (err) {
      showToast("Export PDF", `Error: ${err.message}`, true);
    } finally {
      scoreExportPdfBtn.disabled = false;
      scoreExportPdfBtn.textContent = "Export PDF";
    }
  });
}

// v0.4.5: Export JSON button
const scoreExportJsonBtn = document.getElementById("score-export-json");
if (scoreExportJsonBtn) {
  scoreExportJsonBtn.addEventListener("click", async () => {
    scoreExportJsonBtn.disabled = true;
    scoreExportJsonBtn.textContent = "Generating...";

    try {
      const res = await fetch(`${API_BASE_URL}/export/security-report?format=json`);
      if (!res.ok) {
        throw new Error(`Export failed (${res.status})`);
      }

      const data = await res.json();
      const jsonStr = JSON.stringify(data, null, 2);
      const blob = new Blob([jsonStr], { type: "application/json" });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      const timestamp = new Date().toISOString().slice(0, 19).replace(/[T:]/g, "-");
      a.download = `security-report-${timestamp}.json`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      a.remove();

      showToast("Export JSON", "Security report downloaded successfully!");
    } catch (err) {
      showToast("Export JSON", `Error: ${err.message}`, true);
    } finally {
      scoreExportJsonBtn.disabled = false;
      scoreExportJsonBtn.textContent = "Export JSON";
    }
  });
}

// v0.4.6: Export Markdown button
const scoreExportMdBtn = document.getElementById("score-export-md");
if (scoreExportMdBtn) {
  scoreExportMdBtn.addEventListener("click", async () => {
    scoreExportMdBtn.disabled = true;
    scoreExportMdBtn.textContent = "Generating...";

    try {
      const res = await fetch(`${API_BASE_URL}/export/security-report?format=md`);
      if (!res.ok) {
        throw new Error(`Export failed (${res.status})`);
      }

      // Get filename from Content-Disposition header or use default
      const contentDisposition = res.headers.get("Content-Disposition");
      let filename = "security-report.md";
      if (contentDisposition) {
        const match = contentDisposition.match(/filename=(.+)/);
        if (match) filename = match[1];
      }

      // Download the markdown file
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      a.remove();

      showToast("Export MD", "Security report downloaded successfully!");
    } catch (err) {
      showToast("Export MD", `Error: ${err.message}`, true);
    } finally {
      scoreExportMdBtn.disabled = false;
      scoreExportMdBtn.textContent = "Export MD";
    }
  });
}

