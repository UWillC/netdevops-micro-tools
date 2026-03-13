// Depends on: app-core.js (postJSON, saveFormState, loadFormState)

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

