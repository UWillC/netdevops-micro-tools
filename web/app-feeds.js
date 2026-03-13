// Depends on: app-core.js (postJSON)

// =============================================
// CRITICAL THREAT FEED (Home Dashboard)
// =============================================

const threatFeedList = document.getElementById("threat-feed-list");
const threatFeedAge = document.getElementById("threat-feed-age");
const threatFeedRefresh = document.getElementById("threat-feed-refresh");
const threatFeedPlatform = document.getElementById("threat-feed-platform");

async function loadThreatFeed() {
  if (!threatFeedList) return;
  threatFeedList.innerHTML = '<p class="summary-muted">Loading threat feed...</p>';

  const platform = threatFeedPlatform?.value || "all";

  try {
    const resp = await fetch(`/analyze/critical-feed?platform=${platform}`);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();

    if (data.cache_age_hours != null && threatFeedAge) {
      threatFeedAge.textContent = `Cache: ${data.cache_age_hours}h ago · ${data.total_advisories} advisories`;
    }

    if (!data.items || data.items.length === 0) {
      threatFeedList.innerHTML = '<p class="summary-muted">No threat data available. Feed populates automatically when Cisco PSIRT API credentials are configured.</p>';
      return;
    }

    threatFeedList.innerHTML = "";

    data.items.forEach(item => {
      const a = document.createElement("a");
      a.className = "threat-feed-item";
      a.href = item.url || "#";
      a.target = "_blank";
      a.rel = "noopener";

      const cvssClass = item.severity === "critical" ? "critical" : "high";
      const cvssText = item.cvss != null ? item.cvss.toFixed(1) : "—";

      a.innerHTML = `
        <span class="threat-feed-cvss ${cvssClass}">${cvssText}</span>
        <span class="threat-feed-cve">${item.cve_id}</span>
        <span class="threat-feed-desc">${item.title}</span>
        <span class="threat-feed-date">${item.updated ? item.updated.slice(0, 10) : ""}</span>
        <span class="threat-feed-severity ${cvssClass}">${item.severity}</span>
      `;

      threatFeedList.appendChild(a);
    });
  } catch (err) {
    threatFeedList.innerHTML = `<p class="summary-muted">Could not load threat feed: ${err.message}</p>`;
  }
}

// Load feed on page load
loadThreatFeed();

// Refresh button
if (threatFeedRefresh) {
  threatFeedRefresh.addEventListener("click", loadThreatFeed);
}

// Platform filter
if (threatFeedPlatform) {
  threatFeedPlatform.addEventListener("change", loadThreatFeed);
}

// =============================================
// PORT AUDITOR
// =============================================

const paForm = document.getElementById("pa-form");
const paOutput = document.getElementById("pa-output");
const paConfigOutput = document.getElementById("pa-config-output");
const paCopyConfig = document.getElementById("pa-copy-config");

function formatPortAudit(data) {
  let out = [];

  out.push(`UNUSED PORT AUDIT`);
  out.push(`${"=".repeat(60)}`);
  if (data.hostname) out.push(`Device: ${data.hostname}`);
  out.push(`Summary: ${data.summary}`);
  out.push("");

  out.push(`STATISTICS`);
  out.push(`${"-".repeat(60)}`);
  out.push(`  Total ports scanned:  ${data.total_ports}`);
  out.push(`  Not connected:        ${data.notconnect_ports}`);
  out.push(`  Disabled:             ${data.disabled_ports}`);
  out.push(`  Identified as UNUSED: ${data.unused_ports}`);
  out.push("");

  if (data.ports.length === 0) {
    out.push("No unused ports found with current settings.");
    return out.join("\n");
  }

  // Table header
  out.push(`UNUSED PORTS`);
  out.push(`${"-".repeat(60)}`);
  out.push(`${"Interface".padEnd(16)} ${"Status".padEnd(14)} ${"Last Input".padEnd(12)} ${"VLAN".padEnd(6)} Description`);
  out.push(`${"-".repeat(80)}`);

  data.ports.forEach(port => {
    const ifc = port.interface.padEnd(16);
    const status = port.status.padEnd(14);
    const lastIn = (port.last_input || "n/a").padEnd(12);
    const vlan = (port.vlan || "").padEnd(6);
    const desc = port.description || "";
    out.push(`${ifc} ${status} ${lastIn} ${vlan} ${desc}`);
    if (port.reason) {
      out.push(`  └─ ${port.reason}`);
    }
  });

  return out.join("\n");
}

if (paForm && paOutput) {
  paForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const statusInput = document.getElementById("pa-status-input")?.value || "";
    const detailInput = document.getElementById("pa-detail-input")?.value?.trim() || null;
    const threshold = parseInt(document.getElementById("pa-threshold")?.value || "180", 10);
    const includeDisabled = document.getElementById("pa-include-disabled")?.checked ?? true;
    const excludeUplinks = document.getElementById("pa-exclude-uplinks")?.checked ?? true;

    if (!statusInput.trim()) {
      paOutput.value = "Error: Please paste 'show interface status' output.";
      return;
    }

    paOutput.value = "Analyzing ports...";
    if (paConfigOutput) { paConfigOutput.style.display = "none"; paConfigOutput.value = ""; }
    if (paCopyConfig) paCopyConfig.style.display = "none";

    try {
      const payload = {
        interface_status: statusInput,
        threshold_days: threshold,
        include_disabled: includeDisabled,
        exclude_uplinks: excludeUplinks,
      };
      if (detailInput) payload.interface_detail = detailInput;

      const data = await postJSON("/tools/port-auditor/analyze", payload);
      paOutput.value = formatPortAudit(data);

      // Show shutdown config if available
      if (data.shutdown_config && data.shutdown_config.length > 0) {
        if (paConfigOutput) {
          paConfigOutput.value = data.shutdown_config.join("\n");
          paConfigOutput.style.display = "";
        }
        if (paCopyConfig) {
          paCopyConfig.style.display = "";
          paCopyConfig.onclick = () => {
            navigator.clipboard.writeText(data.shutdown_config.join("\n"));
            paCopyConfig.textContent = "Copied!";
            setTimeout(() => { paCopyConfig.textContent = "Copy Shutdown Config"; }, 2000);
          };
        }
      }
    } catch (err) {
      paOutput.value = `Error: ${err.message}`;
    }
  });
}
