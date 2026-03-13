// Depends on: app-core.js (postJSON, API_BASE_URL, showToast)

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

// =============================================
// CONFIG PARSER
// =============================================

const configParserForm = document.getElementById("config-parser-form");
const configParserOutput = document.getElementById("config-parser-output");
const configParserInput = document.getElementById("config-parser-input");
const configParserSummary = document.getElementById("config-parser-summary");

// Format parsed config result
function formatParsedConfig(data, summaryOnly) {
  if (summaryOnly) {
    // Summary mode - show counts
    let result = `Configuration Summary
====================

Hostname: ${data.hostname || "(not found)"}

Counts:
  Interfaces:       ${data.summary.total_interfaces} total (${data.summary.active_interfaces} active, ${data.summary.l3_interfaces} with IP)
  SNMP Communities: ${data.summary.snmp_communities}
  SNMPv3 Users:     ${data.summary.snmp_v3_users}
  NTP Servers:      ${data.summary.ntp_servers}
  AAA Enabled:      ${data.summary.aaa_enabled ? "Yes" : "No"}
  Local Users:      ${data.summary.local_users}
  TACACS Servers:   ${data.summary.tacacs_servers}`;
    return result;
  }

  // Full JSON output
  return JSON.stringify(data, null, 2);
}

// Config Parser form submit handler
if (configParserForm && configParserOutput) {
  configParserForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    const configText = configParserInput?.value || "";
    const summaryOnly = configParserSummary?.checked ?? false;

    if (!configText.trim()) {
      configParserOutput.value = "Error: Please paste a configuration to parse.";
      return;
    }

    configParserOutput.value = "Parsing configuration...";

    try {
      const endpoint = summaryOnly ? "/tools/config/parse/summary" : "/tools/config/parse";
      const data = await postJSON(endpoint, {
        config_text: configText,
      });

      configParserOutput.value = formatParsedConfig(data, summaryOnly);
    } catch (err) {
      configParserOutput.value = `Error: ${err.message}`;
    }
  });
}

// Initialize Config Parser hints panel
initHintsPanel("config-parser-hints-panel", "config-parser-hints-toggle");

// =====================
// CVE MITIGATION ADVISOR
// =====================

const mitigationForm = document.getElementById("mitigation-form");
const mitigationCveIdInput = document.getElementById("mitigation-cve-id");
const mitigationListBtn = document.getElementById("mitigation-list-btn");
const mitigationAvailable = document.getElementById("mitigation-available");
const mitigationCveList = document.getElementById("mitigation-cve-list");
const mitigationResult = document.getElementById("mitigation-result");
const mitigationNotFound = document.getElementById("mitigation-not-found");

// Helper to set text content safely
function setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text || "";
}

// Helper to set textarea value
function setTextarea(id, lines) {
  const el = document.getElementById(id);
  if (el) el.value = Array.isArray(lines) ? lines.join("\n") : (lines || "");
}

// Render workaround steps
function renderWorkarounds(steps) {
  const container = document.getElementById("mitigation-workarounds");
  if (!container) return;

  container.innerHTML = "";

  steps.forEach((step) => {
    const stepDiv = document.createElement("div");
    stepDiv.className = "mitigation-step card";
    stepDiv.innerHTML = `
      <h4>Step ${step.order}: ${step.description}</h4>
      ${step.platform_notes ? `<p class="step-notes"><em>${step.platform_notes}</em></p>` : ""}
      <div class="output-card">
        <div class="output-header">
          <span>Commands</span>
          <button class="btn-secondary copy-step-btn">Copy</button>
        </div>
        <textarea class="output-text step-commands" readonly>${step.commands.join("\n")}</textarea>
      </div>
    `;

    // Add copy handler
    const copyBtn = stepDiv.querySelector(".copy-step-btn");
    const textarea = stepDiv.querySelector(".step-commands");
    if (copyBtn && textarea) {
      copyBtn.addEventListener("click", () => {
        navigator.clipboard.writeText(textarea.value);
        copyBtn.textContent = "Copied!";
        setTimeout(() => (copyBtn.textContent = "Copy"), 1500);
      });
    }

    container.appendChild(stepDiv);
  });
}

// Render references
function renderReferences(mitigation) {
  const container = document.getElementById("mitigation-references");
  if (!container) return;

  container.innerHTML = "";

  const refs = [];
  if (mitigation.cisco_psirt) refs.push({ label: "Cisco PSIRT Advisory", url: mitigation.cisco_psirt });
  if (mitigation.cisa_alert) refs.push({ label: "CISA Alert", url: mitigation.cisa_alert });
  if (mitigation.field_notice) refs.push({ label: "Field Notice", url: mitigation.field_notice });

  refs.forEach((ref) => {
    const li = document.createElement("li");
    li.innerHTML = `<a href="${ref.url}" target="_blank" rel="noopener">${ref.label}</a>`;
    container.appendChild(li);
  });

  if (refs.length === 0) {
    container.innerHTML = "<li>No external references available</li>";
  }
}

// Display mitigation result
function displayMitigation(data) {
  mitigationResult.style.display = "block";
  mitigationNotFound.style.display = "none";
  mitigationAvailable.style.display = "none";

  const m = data.mitigation;

  // Risk summary
  setText("mitigation-risk-summary", m.risk_summary);
  setText("mitigation-attack-vector", m.attack_vector);

  // Workarounds
  renderWorkarounds(m.workaround_steps || []);

  // ACL mitigation
  const aclSection = document.getElementById("mitigation-acl-section");
  if (m.acl_mitigation) {
    aclSection.style.display = "block";
    setText("mitigation-acl-description", m.acl_mitigation.description);
    setTextarea("mitigation-acl-output", m.acl_mitigation.commands);
  } else {
    aclSection.style.display = "none";
  }

  // Recommended fix
  setText("mitigation-recommended-fix", m.recommended_fix);
  setText("mitigation-upgrade-path", m.upgrade_path || "");

  // Detection
  setText("mitigation-detection-desc", m.detection?.description || "");
  setTextarea("mitigation-detection-cmds", m.detection?.commands || []);
  setText("mitigation-vulnerable-if", m.detection?.vulnerable_if || "");

  // Verification
  setText("mitigation-verification-desc", m.verification?.description || "");
  setTextarea("mitigation-verification-cmds", m.verification?.commands || []);
  setText("mitigation-expected-output", m.verification?.expected_output || "");

  // References
  renderReferences(m);
}

// Fetch and display mitigation
async function fetchMitigation(cveId) {
  try {
    const response = await fetch(`${API_BASE_URL}/mitigate/cve/${encodeURIComponent(cveId)}`);
    const data = await response.json();

    if (data.found) {
      displayMitigation(data);
    } else {
      mitigationResult.style.display = "none";
      mitigationNotFound.style.display = "block";
      mitigationAvailable.style.display = "none";
      document.getElementById("mitigation-not-found-msg").textContent =
        data.message || `No mitigation data available for ${cveId}.`;
    }
  } catch (err) {
    mitigationResult.style.display = "none";
    mitigationNotFound.style.display = "block";
    document.getElementById("mitigation-not-found-msg").textContent = `Error: ${err.message}`;
  }
}

// Fetch available CVEs list
async function fetchMitigationList() {
  try {
    const response = await fetch(`${API_BASE_URL}/mitigate/list`);
    const cves = await response.json();

    mitigationCveList.innerHTML = "";
    cves.forEach((cveId) => {
      const btn = document.createElement("button");
      btn.className = "btn-secondary cve-list-item";
      btn.textContent = cveId;
      btn.addEventListener("click", () => {
        mitigationCveIdInput.value = cveId;
        fetchMitigation(cveId);
      });
      mitigationCveList.appendChild(btn);
    });

    mitigationAvailable.style.display = "block";
    mitigationResult.style.display = "none";
    mitigationNotFound.style.display = "none";
  } catch (err) {
    mitigationCveList.innerHTML = `<p>Error loading CVE list: ${err.message}</p>`;
    mitigationAvailable.style.display = "block";
  }
}

// Form submit handler
if (mitigationForm) {
  mitigationForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const cveId = mitigationCveIdInput?.value?.trim();
    if (cveId) {
      await fetchMitigation(cveId);
    }
  });
}

// List button handler
if (mitigationListBtn) {
  mitigationListBtn.addEventListener("click", fetchMitigationList);
}

// =====================
// TIMEZONE CONVERTER
// =====================

const tzForm = document.getElementById("timezone-form");
const tzTimestampInput = document.getElementById("tz-timestamp");
const tzFromSelect = document.getElementById("tz-from");
const tzResults = document.getElementById("tz-results");
const tzResultsGrid = document.getElementById("tz-results-grid");
const tzNowBtn = document.getElementById("tz-now-btn");
const tzNowResults = document.getElementById("tz-now-results");
const tzNowGrid = document.getElementById("tz-now-grid");
const tzGeneratedAt = document.getElementById("tz-generated-at");
const tzBatchForm = document.getElementById("tz-batch-form");
const tzBatchInput = document.getElementById("tz-batch-input");
const tzBatchFrom = document.getElementById("tz-batch-from");
const tzBatchTo = document.getElementById("tz-batch-to");
const tzBatchOutput = document.getElementById("tz-batch-output");
const tzBatchOutputCard = document.getElementById("tz-batch-output-card");

// All target timezones for conversion
const TARGET_TIMEZONES = [
  "UTC",
  "America/New_York",
  "America/Los_Angeles",
  "Europe/Warsaw",
  "Europe/London",
  "Asia/Tokyo",
  "Asia/Singapore",
  "Australia/Sydney"
];

// Render timezone result card
function renderTzResult(result) {
  const div = document.createElement("div");
  div.className = "tz-result-card";
  div.innerHTML = `
    <div class="tz-result-label">${result.label}</div>
    <div class="tz-result-time">${result.datetime_formatted}</div>
    <div class="tz-result-offset">${result.offset}</div>
  `;
  return div;
}

// Convert single timestamp
async function convertTimestamp(timestamp, fromTz) {
  try {
    const response = await fetch(`${API_BASE_URL}/tools/timezone/convert`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        timestamp: timestamp,
        from_timezone: fromTz,
        to_timezones: TARGET_TIMEZONES
      })
    });

    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.detail || "Conversion failed");
    }

    const data = await response.json();

    tzResultsGrid.innerHTML = "";
    data.results.forEach((result) => {
      tzResultsGrid.appendChild(renderTzResult(result));
    });

    tzResults.style.display = "block";
    tzNowResults.style.display = "none";
  } catch (err) {
    tzResultsGrid.innerHTML = `<p class="error">Error: ${err.message}</p>`;
    tzResults.style.display = "block";
  }
}

// Get current time in all zones
async function fetchCurrentTime() {
  try {
    const response = await fetch(`${API_BASE_URL}/tools/timezone/now`);
    const data = await response.json();

    tzGeneratedAt.textContent = `Generated at: ${data.generated_at_utc}`;

    tzNowGrid.innerHTML = "";
    data.timezones.forEach((result) => {
      tzNowGrid.appendChild(renderTzResult(result));
    });

    tzNowResults.style.display = "block";
    tzResults.style.display = "none";
  } catch (err) {
    tzNowGrid.innerHTML = `<p class="error">Error: ${err.message}</p>`;
    tzNowResults.style.display = "block";
  }
}

// Batch convert
async function batchConvert(timestamps, fromTz, toTz) {
  try {
    const response = await fetch(`${API_BASE_URL}/tools/timezone/batch`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        timestamps: timestamps,
        from_timezone: fromTz,
        to_timezone: toTz
      })
    });

    const results = await response.json();

    let output = `# Batch conversion: ${fromTz} → ${toTz}\n`;
    output += "# Original → Converted\n\n";

    results.forEach((r) => {
      if (r.success) {
        output += `${r.original} → ${r.converted}\n`;
      } else {
        output += `${r.original} → ERROR: ${r.error}\n`;
      }
    });

    tzBatchOutput.value = output;
    tzBatchOutputCard.style.display = "block";
  } catch (err) {
    tzBatchOutput.value = `Error: ${err.message}`;
    tzBatchOutputCard.style.display = "block";
  }
}

// Form handlers
if (tzForm) {
  tzForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const timestamp = tzTimestampInput?.value?.trim();
    const fromTz = tzFromSelect?.value || "UTC";
    if (timestamp) {
      await convertTimestamp(timestamp, fromTz);
    }
  });
}

if (tzNowBtn) {
  tzNowBtn.addEventListener("click", fetchCurrentTime);
}

if (tzBatchForm) {
  tzBatchForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const input = tzBatchInput?.value?.trim();
    if (!input) return;

    const timestamps = input.split("\n").map((l) => l.trim()).filter((l) => l);
    const fromTz = tzBatchFrom?.value || "UTC";
    const toTz = tzBatchTo?.value || "America/New_York";

    await batchConvert(timestamps, fromTz, toTz);
  });
}

// =====================
// NATO DTG FORMAT
// =====================

// Elements - Picker form
const dtgPickerForm = document.getElementById("dtg-picker-form");
const dtgMonth = document.getElementById("dtg-month");
const dtgDay = document.getElementById("dtg-day");
const dtgYear = document.getElementById("dtg-year");
const dtgHour = document.getElementById("dtg-hour");
const dtgMinute = document.getElementById("dtg-minute");
const dtgSecond = document.getElementById("dtg-second");
const dtgTzLetter = document.getElementById("dtg-tz-letter");
const dtgPreviewValue = document.getElementById("dtg-preview-value");
const dtgNowBtn = document.getElementById("dtg-now-btn");
const dtgClearBtn = document.getElementById("dtg-clear-btn");

// Elements - Manual form
const dtgForm = document.getElementById("dtg-form");
const dtgInput = document.getElementById("dtg-input");

// Elements - Results
const dtgResults = document.getElementById("dtg-results");
const dtgResultsGrid = document.getElementById("dtg-results-grid");
const dtgParsedUtc = document.getElementById("dtg-parsed-utc");

// Month names for DTG format
const MONTH_NAMES = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

// Populate dropdown with range
function populateSelect(select, start, end, padZero = true) {
  if (!select) return;
  select.innerHTML = "";
  for (let i = start; i <= end; i++) {
    const opt = document.createElement("option");
    opt.value = padZero ? String(i).padStart(2, "0") : String(i);
    opt.textContent = padZero ? String(i).padStart(2, "0") : String(i);
    select.appendChild(opt);
  }
}

// Calendar state
let calViewYear = new Date().getUTCFullYear();
let calViewMonth = new Date().getUTCMonth(); // 0-based
let calSelectedDate = null; // { year, month, day }

const dtgCalGrid = document.getElementById("dtg-cal-grid");
const dtgCalTitle = document.getElementById("dtg-cal-title");
const dtgCalPrev = document.getElementById("dtg-cal-prev");
const dtgCalNext = document.getElementById("dtg-cal-next");

// Render the calendar grid for current calViewYear/calViewMonth
function renderCalendar() {
  if (!dtgCalGrid) return;
  dtgCalGrid.innerHTML = "";

  const firstDay = new Date(calViewYear, calViewMonth, 1);
  const lastDay = new Date(calViewYear, calViewMonth + 1, 0);
  const daysInMonth = lastDay.getDate();

  // Monday=0 start (ISO week)
  let startWeekday = firstDay.getDay() - 1;
  if (startWeekday < 0) startWeekday = 6;

  const today = new Date();
  const todayStr = `${today.getUTCFullYear()}-${today.getUTCMonth()}-${today.getUTCDate()}`;

  // Title
  if (dtgCalTitle) {
    dtgCalTitle.textContent = `${MONTH_NAMES[calViewMonth]} ${calViewYear}`;
  }

  // Empty cells before day 1
  for (let i = 0; i < startWeekday; i++) {
    const empty = document.createElement("div");
    empty.className = "dtg-cal-day empty";
    dtgCalGrid.appendChild(empty);
  }

  // Day cells
  for (let d = 1; d <= daysInMonth; d++) {
    const cell = document.createElement("div");
    cell.className = "dtg-cal-day";
    cell.textContent = d;

    const cellStr = `${calViewYear}-${calViewMonth}-${d}`;
    if (cellStr === todayStr) {
      cell.classList.add("today");
    }

    if (calSelectedDate &&
        calSelectedDate.year === calViewYear &&
        calSelectedDate.month === calViewMonth &&
        calSelectedDate.day === d) {
      cell.classList.add("selected");
    }

    cell.addEventListener("click", () => {
      calSelectedDate = { year: calViewYear, month: calViewMonth, day: d };
      syncCalendarToHidden();
      renderCalendar();
      updateDtgPreview();
    });

    dtgCalGrid.appendChild(cell);
  }
}

// Sync calendar selection to hidden inputs (for buildDtgFromPicker)
function syncCalendarToHidden() {
  if (!calSelectedDate) return;
  if (dtgMonth) dtgMonth.value = String(calSelectedDate.month + 1).padStart(2, "0");
  if (dtgDay) dtgDay.value = String(calSelectedDate.day).padStart(2, "0");
  if (dtgYear) dtgYear.value = String(calSelectedDate.year).slice(-2);
}

// Navigate calendar
if (dtgCalPrev) {
  dtgCalPrev.addEventListener("click", () => {
    calViewMonth--;
    if (calViewMonth < 0) { calViewMonth = 11; calViewYear--; }
    renderCalendar();
  });
}
if (dtgCalNext) {
  dtgCalNext.addEventListener("click", () => {
    calViewMonth++;
    if (calViewMonth > 11) { calViewMonth = 0; calViewYear++; }
    renderCalendar();
  });
}

// Initialize DTG picker
function initDtgPicker() {
  // Populate hours (00-23)
  populateSelect(dtgHour, 0, 23);

  // Populate minutes (00-59)
  populateSelect(dtgMinute, 0, 59);

  // Populate seconds (00-59)
  populateSelect(dtgSecond, 0, 59);

  // Set to current time
  setDtgPickerToNow();
}

// Set picker to current UTC time
function setDtgPickerToNow() {
  const now = new Date();
  calViewYear = now.getUTCFullYear();
  calViewMonth = now.getUTCMonth();
  calSelectedDate = { year: calViewYear, month: calViewMonth, day: now.getUTCDate() };
  syncCalendarToHidden();
  renderCalendar();

  if (dtgHour) dtgHour.value = String(now.getUTCHours()).padStart(2, "0");
  if (dtgMinute) dtgMinute.value = String(now.getUTCMinutes()).padStart(2, "0");
  if (dtgSecond) dtgSecond.value = String(now.getUTCSeconds()).padStart(2, "0");
  if (dtgTzLetter) dtgTzLetter.value = "Z";

  updateDtgPreview();
}

// Clear picker to defaults
function clearDtgPicker() {
  const now = new Date();
  calViewYear = now.getUTCFullYear();
  calViewMonth = 0;
  calSelectedDate = { year: calViewYear, month: 0, day: 1 };
  syncCalendarToHidden();
  renderCalendar();

  if (dtgHour) dtgHour.value = "00";
  if (dtgMinute) dtgMinute.value = "00";
  if (dtgSecond) dtgSecond.value = "00";
  if (dtgTzLetter) dtgTzLetter.value = "Z";

  updateDtgPreview();
}

// Build DTG string from picker values
function buildDtgFromPicker() {
  const day = dtgDay?.value || "01";
  const hour = dtgHour?.value || "00";
  const minute = dtgMinute?.value || "00";
  const second = dtgSecond?.value || "00";
  const tzLetter = dtgTzLetter?.value || "Z";
  const monthIdx = parseInt(dtgMonth?.value || "1", 10) - 1;
  const monthName = MONTH_NAMES[monthIdx] || "Jan";
  const year = dtgYear?.value || "26";

  // Include seconds only if non-zero
  if (second !== "00") {
    return `${day}${hour}${minute}${second}${tzLetter}${monthName}${year}`;
  }
  return `${day}${hour}${minute}${tzLetter}${monthName}${year}`;
}

// Update DTG preview
function updateDtgPreview() {
  if (dtgPreviewValue) {
    dtgPreviewValue.textContent = buildDtgFromPicker();
  }
}

// Render DTG result card
function renderDtgResult(result) {
  const div = document.createElement("div");
  div.className = "tz-result-card dtg-result-card";
  div.innerHTML = `
    <div class="tz-result-label">${result.label}</div>
    <div class="dtg-military">${result.military_letter} (${result.military_name})</div>
    <div class="dtg-time">${result.dtg_full}</div>
    <div class="tz-result-time">${result.datetime_formatted}</div>
  `;
  return div;
}

// Convert DTG via API
async function convertDtg(dtg) {
  try {
    const response = await fetch(`${API_BASE_URL}/tools/timezone/dtg/convert`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ dtg: dtg })
    });

    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.detail || "DTG conversion failed");
    }

    const data = await response.json();

    dtgParsedUtc.textContent = `Parsed UTC: ${data.parsed_utc} | Zulu DTG: ${data.dtg_zulu}`;

    dtgResultsGrid.innerHTML = "";
    data.results.forEach((result) => {
      dtgResultsGrid.appendChild(renderDtgResult(result));
    });

    dtgResults.style.display = "block";
  } catch (err) {
    dtgResultsGrid.innerHTML = `<p class="error">Error: ${err.message}</p>`;
    dtgResults.style.display = "block";
  }
}

// Get current DTG in all zones
async function fetchCurrentDtg() {
  try {
    const response = await fetch(`${API_BASE_URL}/tools/timezone/dtg/now`);
    const data = await response.json();

    dtgParsedUtc.textContent = `Current Zulu: ${data.dtg_zulu_full} (${data.generated_at_utc})`;

    dtgResultsGrid.innerHTML = "";
    data.timezones.forEach((result) => {
      dtgResultsGrid.appendChild(renderDtgResult(result));
    });

    dtgResults.style.display = "block";

    // Also update picker to current time
    setDtgPickerToNow();
  } catch (err) {
    dtgResultsGrid.innerHTML = `<p class="error">Error: ${err.message}</p>`;
    dtgResults.style.display = "block";
  }
}

// Initialize picker on load
initDtgPicker();

// Add change listeners for live preview (time + timezone only — calendar handles date)
[dtgHour, dtgMinute, dtgSecond, dtgTzLetter].forEach(el => {
  if (el) el.addEventListener("change", updateDtgPreview);
});

// Picker form submit
if (dtgPickerForm) {
  dtgPickerForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const dtg = buildDtgFromPicker();
    await convertDtg(dtg);
  });
}

// Manual form submit (power users)
if (dtgForm) {
  dtgForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const dtg = dtgInput?.value?.trim();
    if (dtg) {
      await convertDtg(dtg);
    }
  });
}

// Now button
if (dtgNowBtn) {
  dtgNowBtn.addEventListener("click", () => {
    setDtgPickerToNow();
    fetchCurrentDtg();
  });
}

// Clear button
if (dtgClearBtn) {
  dtgClearBtn.addEventListener("click", clearDtgPicker);
}

// =============================================
// IP PATH TRACER
// =============================================

const iptAnalyzeForm = document.getElementById("ipt-analyze-form");
const iptGenerateForm = document.getElementById("ipt-generate-form");
const iptModeAnalyze = document.getElementById("ipt-mode-analyze");
const iptModeGenerate = document.getElementById("ipt-mode-generate");
const iptOutput = document.getElementById("ipt-output");
const iptGenTcp = document.getElementById("ipt-gen-tcp");
const iptGenPortRow = document.getElementById("ipt-gen-port-row");

// Mode toggle
if (iptModeAnalyze && iptModeGenerate) {
  iptModeAnalyze.addEventListener("click", () => {
    iptAnalyzeForm.style.display = "";
    iptGenerateForm.style.display = "none";
    iptModeAnalyze.className = "btn-primary";
    iptModeGenerate.className = "btn-secondary";
  });
  iptModeGenerate.addEventListener("click", () => {
    iptAnalyzeForm.style.display = "none";
    iptGenerateForm.style.display = "";
    iptModeAnalyze.className = "btn-secondary";
    iptModeGenerate.className = "btn-primary";
  });
}

// TCP checkbox shows port field
if (iptGenTcp && iptGenPortRow) {
  iptGenTcp.addEventListener("change", () => {
    iptGenPortRow.style.display = iptGenTcp.checked ? "" : "none";
  });
}

// Format analyze results
function formatPathAnalysis(data) {
  let out = [];

  out.push(`PATH ANALYSIS`);
  out.push(`${"=".repeat(50)}`);
  out.push(`Summary: ${data.summary}`);
  out.push(`Hops: ${data.hop_count} | Destination: ${data.destination_reached ? "REACHED" : "NOT REACHED"}`);
  if (data.destination_ip) out.push(`Destination IP: ${data.destination_ip}`);
  if (data.total_latency_ms != null) out.push(`Total Latency: ${data.total_latency_ms} ms`);
  out.push("");

  // Warnings
  if (data.warnings && data.warnings.length > 0) {
    out.push(`WARNINGS`);
    out.push(`${"-".repeat(50)}`);
    data.warnings.forEach(w => out.push(`  ⚠  ${w}`));
    out.push("");
  }

  // Hop table
  out.push(`HOP DETAILS`);
  out.push(`${"-".repeat(50)}`);
  out.push(`${"#".padEnd(4)} ${"IP Address".padEnd(18)} ${"Hostname".padEnd(20)} ${"Avg RTT".padEnd(10)} Flags`);
  out.push(`${"-".repeat(70)}`);

  data.hops.forEach(hop => {
    const num = String(hop.hop_number).padEnd(4);
    const ip = (hop.ip_address || "* * *").padEnd(18);
    const host = (hop.hostname || "").padEnd(20);
    const rtt = hop.rtt_avg_ms != null ? `${hop.rtt_avg_ms} ms`.padEnd(10) : "timeout".padEnd(10);

    let flags = [];
    if (hop.is_destination) flags.push("DST");
    if (hop.is_private) flags.push("RFC1918");
    if (hop.packet_loss) flags.push("LOSS");

    out.push(`${num} ${ip} ${host} ${rtt} ${flags.join(" ")}`);

    if (hop.issues && hop.issues.length > 0) {
      hop.issues.forEach(issue => {
        out.push(`     └─ ${issue}`);
      });
    }
  });

  return out.join("\n");
}

// Format generate results
function formatPathCommands(data) {
  let out = [];
  out.push(`TRACEROUTE COMMANDS — ${data.platform}`);
  out.push(`${"=".repeat(50)}`);
  out.push("");
  data.commands.forEach((cmd, i) => {
    out.push(`${i + 1}. ${cmd}`);
  });
  if (data.notes && data.notes.length > 0) {
    out.push("");
    out.push(`NOTES`);
    out.push(`${"-".repeat(50)}`);
    data.notes.forEach(n => out.push(`  • ${n}`));
  }
  return out.join("\n");
}

// Analyze form
if (iptAnalyzeForm && iptOutput) {
  iptAnalyzeForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const traceOutput = document.getElementById("ipt-analyze-input")?.value || "";
    const destIp = document.getElementById("ipt-analyze-dest")?.value?.trim() || null;

    if (!traceOutput.trim()) {
      iptOutput.value = "Error: Please paste traceroute output to analyze.";
      return;
    }

    iptOutput.value = "Analyzing traceroute...";

    try {
      const payload = { traceroute_output: traceOutput };
      if (destIp) payload.destination_ip = destIp;
      const data = await postJSON("/tools/ip-path-tracer/analyze", payload);
      iptOutput.value = formatPathAnalysis(data);
    } catch (err) {
      iptOutput.value = `Error: ${err.message}`;
    }
  });
}

// Generate form
if (iptGenerateForm && iptOutput) {
  iptGenerateForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const dest = document.getElementById("ipt-gen-dest")?.value?.trim();
    if (!dest) {
      iptOutput.value = "Error: Destination is required.";
      return;
    }

    const payload = {
      destination: dest,
      platform: document.getElementById("ipt-gen-platform")?.value || "ios-xe",
      source_ip: document.getElementById("ipt-gen-source")?.value?.trim() || null,
      vrf: document.getElementById("ipt-gen-vrf")?.value?.trim() || null,
      max_ttl: parseInt(document.getElementById("ipt-gen-ttl")?.value || "30", 10),
      timeout: parseInt(document.getElementById("ipt-gen-timeout")?.value || "3", 10),
      probe_count: parseInt(document.getElementById("ipt-gen-probes")?.value || "3", 10),
      use_tcp: document.getElementById("ipt-gen-tcp")?.checked || false,
    };

    if (payload.use_tcp) {
      payload.port = parseInt(document.getElementById("ipt-gen-port")?.value || "443", 10);
    }

    // Remove null values
    Object.keys(payload).forEach(k => { if (payload[k] === null) delete payload[k]; });

    iptOutput.value = "Generating commands...";

    try {
      const data = await postJSON("/tools/ip-path-tracer/generate", payload);
      iptOutput.value = formatPathCommands(data);
    } catch (err) {
      iptOutput.value = `Error: ${err.message}`;
    }
  });
}

// =============================================
// CONFIG EXPLAINER
// =============================================

const ceForm = document.getElementById("ce-form");
const ceOutput = document.getElementById("ce-output");

function formatExplanation(data) {
  let out = [];

  out.push(`CONFIG EXPLANATION`);
  out.push(`${"=".repeat(60)}`);
  if (data.hostname) out.push(`Device: ${data.hostname}`);
  out.push(`Mode: ${data.mode === "junior" ? "Junior-friendly" : "Standard"}`);
  out.push(`Coverage: ${data.explained_lines}/${data.total_lines} lines explained (${data.coverage_pct}%)`);
  out.push("");

  // Security notes first
  if (data.security_notes && data.security_notes.length > 0) {
    out.push(`SECURITY NOTES`);
    out.push(`${"-".repeat(60)}`);
    data.security_notes.forEach(note => {
      const prefix = note.startsWith("CRITICAL") ? "!!!" : note.startsWith("WARNING") ? " ! " : "   ";
      out.push(`${prefix} ${note}`);
    });
    out.push("");
  }

  // Sections
  data.sections.forEach(section => {
    out.push(`${section.title.toUpperCase()}`);
    out.push(`${"-".repeat(60)}`);

    section.lines.forEach(line => {
      if (!line.explanation) {
        // Unexplained line — show dimmed
        out.push(`  ${line.line}`);
        return;
      }

      const riskTag = line.risk === "critical" ? " [CRITICAL]"
        : line.risk === "warning" ? " [WARNING]"
        : line.risk === "info" ? " [INFO]"
        : "";

      out.push(`  ${line.line}`);
      out.push(`    -> ${line.explanation}${riskTag}`);
      if (line.tip) {
        out.push(`    TIP: ${line.tip}`);
      }
    });

    out.push("");
  });

  return out.join("\n");
}

if (ceForm && ceOutput) {
  ceForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const configText = document.getElementById("ce-config-input")?.value || "";
    const mode = document.getElementById("ce-mode")?.value || "standard";

    if (!configText.trim()) {
      ceOutput.value = "Error: Please paste a Cisco config to explain.";
      return;
    }

    ceOutput.value = "Analyzing config...";

    try {
      const data = await postJSON("/tools/config-explainer/explain", {
        config_text: configText,
        mode: mode,
      });
      ceOutput.value = formatExplanation(data);
    } catch (err) {
      ceOutput.value = `Error: ${err.message}`;
    }
  });
}

// =============================================
// CONFIG DRIFT DETECTION
// =============================================

const cdForm = document.getElementById("cd-form");
const cdOutput = document.getElementById("cd-output");
const cdSummary = document.getElementById("cd-summary");
const cdResults = document.getElementById("cd-results");

function formatDrift(data) {
  let out = [];

  out.push("CONFIG DRIFT REPORT");
  out.push("=".repeat(60));
  if (data.hostname_a || data.hostname_b) {
    out.push(`Config A: ${data.hostname_a || "unknown"}  →  Config B: ${data.hostname_b || "unknown"}`);
  }
  out.push(`Drift Score: ${data.drift_score}%`);
  out.push(`Added: ${data.total_added} | Removed: ${data.total_removed} | Unchanged: ${data.total_unchanged}`);
  out.push("");

  data.summary.forEach(s => out.push(s));
  out.push("");

  data.sections.forEach(sec => {
    out.push("-".repeat(60));
    out.push(`[${sec.title}]  +${sec.added_count} -${sec.removed_count}`);
    out.push("");

    sec.changes.forEach(c => {
      const prefix = c.change_type === "added" ? "+" : c.change_type === "removed" ? "-" : " ";
      const risk = c.risk ? ` [${c.risk.toUpperCase()}]` : "";
      const note = c.note ? ` — ${c.note}` : "";
      out.push(`  ${prefix} ${c.line}${risk}${note}`);
    });
    out.push("");
  });

  return out.join("\n");
}

function formatDriftSummary(data) {
  const scoreColor = data.drift_score === 0 ? "#22c55e" :
    data.drift_score < 20 ? "#22c55e" :
    data.drift_score < 50 ? "#eab308" :
    data.drift_score < 80 ? "#f97316" : "#ef4444";

  let html = `<div style="display:flex; align-items:center; gap:1.5rem; flex-wrap:wrap;">`;
  html += `<div style="text-align:center;">
    <div style="font-size:2.5rem; font-weight:bold; color:${scoreColor}">${data.drift_score}%</div>
    <div style="font-size:0.8rem; color:var(--text-dim);">Drift Score</div>
  </div>`;
  html += `<div style="flex:1; min-width:200px;">`;
  html += `<div style="display:flex; gap:1rem; margin-bottom:0.5rem;">
    <span style="color:#22c55e; font-weight:600;">+${data.total_added} added</span>
    <span style="color:#ef4444; font-weight:600;">-${data.total_removed} removed</span>
    <span style="color:var(--text-dim);">${data.total_unchanged} unchanged</span>
  </div>`;
  data.summary.forEach(s => {
    const cls = s.includes("CRITICAL") ? "color:#ef4444" : s.includes("WARNING") ? "color:#eab308" : "";
    html += `<div style="${cls}; font-size:0.85rem;">${s}</div>`;
  });
  html += `</div></div>`;
  return html;
}

if (cdForm) {
  cdForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const configA = document.getElementById("cd-config-a")?.value || "";
    const configB = document.getElementById("cd-config-b")?.value || "";

    if (!configA.trim() || !configB.trim()) {
      if (cdOutput) cdOutput.value = "Error: Please paste both configs.";
      return;
    }

    if (cdOutput) cdOutput.value = "Comparing configs...";
    if (cdSummary) cdSummary.style.display = "none";
    if (cdResults) cdResults.style.display = "none";

    try {
      const data = await postJSON("/tools/config-drift/compare", {
        config_a: configA,
        config_b: configB,
        ignore_cosmetic: document.getElementById("cd-ignore-cosmetic")?.checked ?? true,
      });

      if (cdSummary) {
        document.getElementById("cd-summary-content").innerHTML = formatDriftSummary(data);
        cdSummary.style.display = "block";
      }
      if (cdResults) cdResults.style.display = "block";
      if (cdOutput) cdOutput.value = formatDrift(data);
    } catch (err) {
      if (cdOutput) cdOutput.value = `Error: ${err.message}`;
    }
  });
}

// =============================================
// CIS COMPLIANCE AUDIT
// =============================================

const cisForm = document.getElementById("cis-form");
const cisOutput = document.getElementById("cis-output");
const cisSummary = document.getElementById("cis-summary");
const cisResults = document.getElementById("cis-results");

function formatCisAudit(data) {
  let out = [];

  out.push("CIS COMPLIANCE AUDIT REPORT");
  out.push("=".repeat(60));
  if (data.hostname) out.push(`Device: ${data.hostname}`);
  out.push(`CIS Level: ${data.level}`);
  out.push(`Score: ${data.score}% (Grade ${data.grade})`);
  out.push(`Passed: ${data.passed} | Failed: ${data.failed} | Warnings: ${data.warnings}`);
  out.push("");

  data.summary.forEach(s => out.push(s));
  out.push("");

  data.categories.forEach(cat => {
    out.push("-".repeat(60));
    out.push(`[${cat.name}]  Pass: ${cat.passed} | Fail: ${cat.failed} | Warn: ${cat.warnings}`);
    out.push("");

    cat.rules.forEach(r => {
      const icon = r.result === "PASS" ? "PASS" : r.result === "FAIL" ? "FAIL" : r.result === "WARNING" ? "WARN" : "N/A ";
      const sev = r.severity === "critical" ? " [CRITICAL]" : r.severity === "high" ? " [HIGH]" : "";
      out.push(`  [${icon}] ${r.rule_id} ${r.title}${sev}`);
      out.push(`         ${r.evidence}`);
      if (r.result === "FAIL" && r.remediation) {
        out.push(`         FIX: ${r.remediation}`);
      }
    });
    out.push("");
  });

  return out.join("\n");
}

function formatCisSummary(data) {
  const gradeColor = data.grade === "A" ? "#22c55e" :
    data.grade === "B" ? "#22c55e" :
    data.grade === "C" ? "#eab308" :
    data.grade === "D" ? "#f97316" : "#ef4444";

  let html = `<div style="display:flex; align-items:center; gap:1.5rem; flex-wrap:wrap;">`;
  html += `<div style="text-align:center;">
    <div style="font-size:2.5rem; font-weight:bold; color:${gradeColor}">${data.grade}</div>
    <div style="font-size:0.8rem; color:var(--text-dim);">${data.score}%</div>
  </div>`;

  // Score bar
  html += `<div style="flex:1; min-width:200px;">`;
  html += `<div style="background:rgba(148,163,184,0.2); border-radius:8px; height:12px; margin-bottom:0.5rem; overflow:hidden;">
    <div style="width:${data.score}%; height:100%; background:${gradeColor}; border-radius:8px; transition:width 0.5s;"></div>
  </div>`;
  html += `<div style="display:flex; gap:1rem; font-size:0.85rem;">
    <span style="color:#22c55e; font-weight:600;">${data.passed} passed</span>
    <span style="color:#ef4444; font-weight:600;">${data.failed} failed</span>
    <span style="color:#eab308; font-weight:600;">${data.warnings} warnings</span>
    <span style="color:var(--text-dim);">Level ${data.level}</span>
  </div>`;

  // Critical failures
  const critFails = [];
  data.categories.forEach(cat => {
    cat.rules.forEach(r => {
      if (r.result === "FAIL" && r.severity === "critical") critFails.push(r.title);
    });
  });
  if (critFails.length > 0) {
    html += `<div style="color:#ef4444; font-size:0.85rem; margin-top:0.5rem;">Critical: ${critFails.join(", ")}</div>`;
  }

  html += `</div></div>`;
  return html;
}

if (cisForm) {
  cisForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const configText = document.getElementById("cis-config")?.value || "";
    const level = document.getElementById("cis-level")?.value || "1";

    if (!configText.trim()) {
      if (cisOutput) cisOutput.value = "Error: Please paste a running-config.";
      return;
    }

    if (cisOutput) cisOutput.value = "Running CIS audit...";
    if (cisSummary) cisSummary.style.display = "none";
    if (cisResults) cisResults.style.display = "none";

    try {
      const data = await postJSON("/tools/cis-audit/check", {
        config_text: configText,
        level: level,
      });

      if (cisSummary) {
        document.getElementById("cis-summary-content").innerHTML = formatCisSummary(data);
        cisSummary.style.display = "block";
      }
      if (cisResults) cisResults.style.display = "block";
      if (cisOutput) cisOutput.value = formatCisAudit(data);
    } catch (err) {
      if (cisOutput) cisOutput.value = `Error: ${err.message}`;
    }
  });
}
