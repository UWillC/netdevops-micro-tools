// API base URL - auto-detect based on how the page is loaded
// - file:// protocol (direct open) → localhost:8000
// - localhost/127.0.0.1 → localhost:8000 (Live Server + backend)
// - cloud deploy → same origin (empty string)
const API_BASE_URL = (function() {
  const proto = window.location.protocol;
  const host = window.location.hostname;
  if (proto === "file:" || host === "127.0.0.1" || host === "localhost") {
    return "http://127.0.0.1:8000";
  }
  return "";
})();

// -----------------------------
// Theme Toggle (Dark/Light Mode)
// -----------------------------
const THEME_KEY = "netdevops_theme";

function getStoredTheme() {
  return localStorage.getItem(THEME_KEY) || "dark";
}

function setTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  localStorage.setItem(THEME_KEY, theme);

  const icon = document.getElementById("theme-icon");
  if (icon) {
    icon.textContent = theme === "dark" ? "🌙" : "☀️";
  }
}

// Initialize theme
setTheme(getStoredTheme());

// Theme toggle button
const themeToggle = document.getElementById("theme-toggle");
if (themeToggle) {
  themeToggle.addEventListener("click", () => {
    const current = getStoredTheme();
    setTheme(current === "dark" ? "light" : "dark");
  });
}

// -----------------------------
// Quick Access (Last Used Tools)
// -----------------------------
const QUICK_ACCESS_KEY = "netdevops_quick_access";
const MAX_QUICK_ACCESS = 3;

const toolIcons = {
  "snmpv3": "📡",
  "snmp-multi": "📡",
  "ntp": "🕐",
  "aaa": "🔐",
  "golden": "✨",
  "cve": "🔍",
  "mitigation": "🚨",
  "iperf": "📊",
  "subnet": "🧮",
  "mtu": "📏",
  "timezone": "🌍",
  "config-parser": "📄",
  "profiles": "💾"
};

const toolNames = {
  "snmpv3": "SNMPv3",
  "snmp-multi": "SNMP Multi",
  "ntp": "NTP",
  "aaa": "AAA",
  "golden": "Golden",
  "cve": "CVE Analyzer",
  "mitigation": "CVE Mitigation",
  "iperf": "iPerf3",
  "subnet": "Subnet",
  "mtu": "MTU",
  "timezone": "Timezone",
  "config-parser": "Parser",
  "profiles": "Profiles"
};

function getQuickAccess() {
  try {
    return JSON.parse(localStorage.getItem(QUICK_ACCESS_KEY)) || [];
  } catch {
    return [];
  }
}

function addToQuickAccess(tab) {
  let items = getQuickAccess();
  items = items.filter(t => t !== tab);
  items.unshift(tab);
  items = items.slice(0, MAX_QUICK_ACCESS);
  localStorage.setItem(QUICK_ACCESS_KEY, JSON.stringify(items));
  renderQuickAccess();
}

function renderQuickAccess() {
  const container = document.getElementById("quick-access-items");
  const wrapper = document.getElementById("quick-access");
  const items = getQuickAccess();

  if (items.length === 0) {
    wrapper.classList.add("hidden");
    return;
  }

  wrapper.classList.remove("hidden");
  container.innerHTML = items.map(tab => `
    <button class="quick-access-btn" data-tab="${tab}">
      <span class="tool-icon">${toolIcons[tab] || "🔹"}</span>
      ${toolNames[tab] || tab}
    </button>
  `).join("");

  // Add click handlers
  container.querySelectorAll(".quick-access-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const tab = btn.dataset.tab;
      const tabBtn = document.querySelector(`.tab-button[data-tab="${tab}"]`);
      if (tabBtn) tabBtn.click();
    });
  });
}

// Initial render
renderQuickAccess();

// -----------------------------
// Home Button
// -----------------------------
const homeButton = document.getElementById("home-button");
const homeTab = document.getElementById("tab-home");

homeButton.addEventListener("click", () => {
  // Deactivate all tabs and buttons
  document.querySelectorAll(".tab-button").forEach(b => b.classList.remove("active"));
  document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));

  // Collapse all nav groups
  document.querySelectorAll(".nav-group-items").forEach(g => g.classList.add("collapsed"));
  document.querySelectorAll(".nav-group-header").forEach(h => {
    h.classList.remove("expanded");
    const arrow = h.querySelector(".nav-group-arrow");
    if (arrow) arrow.textContent = "▶";
  });

  // Activate home
  homeButton.classList.add("active");
  homeTab.classList.add("active");
});

// Home tool cards - navigate to tool
document.querySelectorAll(".home-tool-card").forEach(card => {
  card.addEventListener("click", () => {
    const tab = card.dataset.tab;
    const tabBtn = document.querySelector(`.tab-button[data-tab="${tab}"]`);
    if (tabBtn) tabBtn.click();
  });
});

// -----------------------------
// Nav Group Toggle (collapsible sections)
// -----------------------------
const navGroupHeaders = document.querySelectorAll(".nav-group-header");

navGroupHeaders.forEach((header) => {
  header.addEventListener("click", () => {
    const groupId = header.dataset.group;
    const groupItems = document.getElementById(`group-${groupId}`);
    const arrow = header.querySelector(".nav-group-arrow");

    if (groupItems.classList.contains("collapsed")) {
      // Expand
      groupItems.classList.remove("collapsed");
      header.classList.add("expanded");
      arrow.textContent = "▼";
    } else {
      // Collapse
      groupItems.classList.add("collapsed");
      header.classList.remove("expanded");
      arrow.textContent = "▶";
    }
  });
});

// -----------------------------
// Tabs
// -----------------------------
const tabButtons = document.querySelectorAll(".tab-button");
const tabContents = document.querySelectorAll(".tab-content");

tabButtons.forEach((btn) => {
  btn.addEventListener("click", () => {
    const tab = btn.dataset.tab;

    // Deactivate home button
    const homeBtn = document.getElementById("home-button");
    if (homeBtn) homeBtn.classList.remove("active");

    tabButtons.forEach((b) => b.classList.remove("active"));
    tabContents.forEach((c) => c.classList.remove("active"));

    btn.classList.add("active");
    const section = document.getElementById(`tab-${tab}`);
    if (section) section.classList.add("active");

    // Auto-expand the group containing this tab
    const parentGroup = btn.closest(".nav-group-items");
    if (parentGroup && parentGroup.classList.contains("collapsed")) {
      const groupId = parentGroup.id.replace("group-", "");
      const header = document.querySelector(`.nav-group-header[data-group="${groupId}"]`);
      const arrow = header.querySelector(".nav-group-arrow");
      parentGroup.classList.remove("collapsed");
      header.classList.add("expanded");
      arrow.textContent = "▼";
    }

    // Track in Quick Access
    addToQuickAccess(tab);

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

