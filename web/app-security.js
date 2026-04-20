// Depends on: app-core.js (postJSON, saveFormState, loadFormState)

// -----------------------------
// CVE Analyzer form (v0.3.1 data enrichment visible)
// + Security summary + Collapsible cards
// -----------------------------
const cveForm = document.getElementById("cve-form");
const cveOutput = document.getElementById("cve-output");
const cveSummary = document.getElementById("cve-summary");
const cveCards = document.getElementById("cve-cards");
const cveEolBanner = document.getElementById("cve-eol-banner");
const cveProvenance = document.getElementById("cve-provenance");

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
    if (cveEolBanner) cveEolBanner.innerHTML = "";
    if (cveProvenance) cveProvenance.innerHTML = "";

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
        // Even with zero CVE matches, EoL platforms get the banner —
        // an EoL device with no listed CVEs is more dangerous, not less.
        if (cveEolBanner && data.eol_status && data.eol_status.is_eol) {
          cveEolBanner.innerHTML = `
            <div class="eol-banner">
              <div class="eol-banner-title">⚠ End-of-Life platform detected</div>
              <div class="eol-banner-body">${data.eol_status.banner_text}</div>
            </div>
          `;
        }
        let header = "";
        if (data.eol_status && data.eol_status.is_eol) {
          header = `EoL platform: ${data.eol_status.banner_text}\n\n`;
        }
        cveOutput.value = header + "No CVEs from current dataset matched this platform/version.\n";

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

      // v0.6.18 CVE-009: render EoL banner above CVE list when platform
      // is past end-of-vulnerability-security-support. Operator must see
      // this BEFORE wasting time on per-CVE remediation steps.
      if (cveEolBanner && data.eol_status && data.eol_status.is_eol) {
        const hw = data.eol_status.hardware;
        const train = data.eol_status.ios_train;
        const links = [];
        if (hw && hw.bulletin_url) {
          links.push(
            `<a href="${hw.bulletin_url}" target="_blank" rel="noopener">Hardware EoL bulletin</a>`
          );
        }
        cveEolBanner.innerHTML = `
          <div class="eol-banner">
            <div class="eol-banner-title">⚠ End-of-Life platform detected</div>
            <div class="eol-banner-body">${data.eol_status.banner_text}</div>
            ${links.length ? `<div class="eol-banner-links">${links.join(" • ")}</div>` : ""}
          </div>
        `;
      }

      // v0.6.16 CVE-007/010: severity transparency + bundle lookup.
      const sevDetails = data.severity_details || {};
      const bundles = data.bundles || {};

      // Derive the severity the UI should display for each CVE. Prefer the
      // backend-computed primary_severity (NVD CVSS bucket when score known);
      // fall back to the legacy severity field for older API responses.
      const displaySeverity = (cve) => {
        const d = sevDetails[cve.cve_id];
        if (d && d.primary_severity) return d.primary_severity;
        return (cve.severity || "").toUpperCase();
      };

      // Recount summary based on primary severity so the breakdown matches
      // what the badges show.
      const primaryCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, NONE: 0, UNKNOWN: 0 };
      data.matched.forEach((cve) => {
        const sev = displaySeverity(cve);
        if (primaryCounts[sev] !== undefined) primaryCounts[sev] += 1;
      });

      // Text report output
      let out = "";
      out += `Platform: ${data.platform}\n`;
      out += `Version: ${data.version}\n`;
      out += `Timestamp: ${data.timestamp}\n\n`;

      if (data.eol_status && data.eol_status.is_eol) {
        out += "*** END-OF-LIFE PLATFORM ***\n";
        out += data.eol_status.banner_text + "\n\n";
      }

      out += "Matched CVEs:\n";
      data.matched.forEach((cve) => {
        const primary = displaySeverity(cve);
        const d = sevDetails[cve.cve_id] || {};
        const bundle = bundles[cve.cve_id];
        let line = `${cve.cve_id} [${primary}]`;
        if (d.cisco_sir) line += ` [Cisco SIR: ${d.cisco_sir}]`;
        if (bundle) line += ` [Bundle: ${bundle}]`;
        out += line + "\n";
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

      out += "Severity breakdown (NVD CVSS v3.x):\n";
      ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"].forEach((sev) => {
        if (primaryCounts[sev] > 0) out += `  ${sev}: ${primaryCounts[sev]}\n`;
      });

      if (data.recommended_upgrade) {
        out += `\nRecommended upgrade target: ${data.recommended_upgrade}\n`;
      }

      if (data.severity_policy) {
        out += `\nNote: ${data.severity_policy}\n`;
      }

      if (data.provenance && Object.keys(data.provenance).length) {
        const p = data.provenance;
        out += "\n--- Provenance ---\n";
        out += `Tool: ${p.tool_version || "?"}  Engine: ${p.cve_engine_version || "?"}  Ruleset: ${p.ruleset_version || "?"}\n`;
        out += `Generated: ${p.report_generated || "?"}\n`;
        if (p.source_distribution) {
          const dist = Object.entries(p.source_distribution)
            .map(([k, v]) => `${k}=${v}`)
            .join(", ");
          out += `Per-CVE source attribution: ${dist}\n`;
        }
        out += "Live provider cache freshness:\n";
        (p.sources || []).forEach((s) => {
          if (s.available) {
            out += `  ${s.name}: ${s.last_refreshed} (${s.age_hours}h ago, ${s.file_count} files)\n`;
          } else {
            out += `  ${s.name}: not present (cache empty; records may still appear in attribution above)\n`;
          }
        });
      }

      cveOutput.value = out;

      // Collapsible CVE cards
      if (cveCards) {
        const badgeClass = (sev) => {
          const s = (sev || "").toLowerCase();
          if (s === "critical") return "severity-badge sev-critical";
          if (s === "high") return "severity-badge sev-high";
          if (s === "medium") return "severity-badge sev-medium";
          if (s === "low") return "severity-badge sev-low";
          return "severity-badge sev-unknown";
        };

        cveCards.innerHTML = "";
        data.matched.forEach((cve) => {
          const card = document.createElement("div");
          card.className = "cve-item";

          const primary = displaySeverity(cve);
          const d = sevDetails[cve.cve_id] || {};
          const bundle = bundles[cve.cve_id];

          // Secondary tags (Cisco SIR, bundle, escalation reason)
          const secondaryTags = [];
          if (d.cisco_sir) {
            secondaryTags.push(
              `<span class="secondary-tag tag-cisco-sir" title="Cisco Security Impact Rating — separate scale from NVD CVSS">Cisco SIR: ${d.cisco_sir}</span>`
            );
          }
          if (bundle) {
            secondaryTags.push(
              `<span class="secondary-tag tag-bundle" title="Part of Cisco semi-annual bundled publication">Bundle: ${bundle}</span>`
            );
          }
          if (d.escalation_reason) {
            secondaryTags.push(
              `<span class="secondary-tag tag-escalation" title="Risk-escalation flag from feed metadata">${d.escalation_reason}</span>`
            );
          }

          const metaBits = [];
          metaBits.push(`Source: ${cve.source || "N/A"}`);
          metaBits.push(`CVSS: ${formatCvss(cve.cvss_score)}`);
          if (cve.cwe) metaBits.push(`CWE: ${cve.cwe}`);
          if (cve.fixed_in) metaBits.push(`Fixed in: ${cve.fixed_in}`);

          card.innerHTML = `
            <div class="cve-item-header">
              <div>
                <div class="cve-item-title">
                  <span class="${badgeClass(primary)}">${primary}</span>
                  ${secondaryTags.join("")}
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

      // Security posture summary — counts derived from PRIMARY severity
      // (NVD CVSS v3.x bucket) so the breakdown matches the badges.
      if (cveSummary) {
        const critical = primaryCounts.CRITICAL;
        const high = primaryCounts.HIGH;
        const medium = primaryCounts.MEDIUM;
        const low = primaryCounts.LOW;

        const scores = (data.matched || [])
          .map((x) => Number(x.cvss_score))
          .filter((n) => !Number.isNaN(n));

        const maxCvss = scores.length ? Math.max(...scores) : null;

        // Count CVEs whose Cisco SIR diverges from CVSS bucket (CVE-007).
        const sirDistinct = (data.matched || []).filter(
          (cve) => (sevDetails[cve.cve_id] || {}).cisco_sir
        ).length;
        // Count CVEs marked as part of a Cisco semi-annual bundle (CVE-010).
        const bundleCount = Object.values(bundles).filter((v) => v).length;

        cveSummary.innerHTML = `
          <h3>Security posture</h3>
          <div class="summary-row"><span>Severity breakdown (NVD CVSS v3.x)</span></div>
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
            sirDistinct > 0
              ? `<div class="summary-row summary-muted"><span>Cisco SIR ≠ CVSS</span><span>${sirDistinct} CVE(s)</span></div>`
              : ""
          }
          ${
            bundleCount > 0
              ? `<div class="summary-row summary-muted"><span>In Cisco bundle</span><span>${bundleCount} CVE(s)</span></div>`
              : ""
          }
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
          ${
            data.severity_policy
              ? `<div class="severity-policy-footer">${data.severity_policy}</div>`
              : ""
          }
        `;
      }

      // v0.6.19 XCUT-002 + v0.6.20 UX clarification: provenance footer.
      // Two distinct concepts surfaced separately so an auditor doesn't
      // misread "cache not present" as "no data from that provider":
      //   (1) Per-CVE source attribution = where each record originally came
      //       from (counts per provider).
      //   (2) Live provider cache freshness = current state of on-disk
      //       caches used for re-fetch. May be empty even when attribution
      //       counts are non-zero.
      if (cveProvenance && data.provenance && Object.keys(data.provenance).length) {
        const p = data.provenance;
        const sourceRows = (p.sources || [])
          .map((s) => {
            const status = s.available
              ? `<span class="prov-fresh">${s.last_refreshed} (${s.age_hours}h ago, ${s.file_count} file${s.file_count === 1 ? "" : "s"})</span>`
              : `<span class="prov-missing" title="On-disk cache is empty. Records from this provider may still appear in attribution above (imported into local-json earlier).">not present</span>`;
            return `<div class="prov-row"><span class="prov-name">${s.name}</span> ${status}<div class="prov-desc">${s.description}</div></div>`;
          })
          .join("");
        const distRows = Object.entries(p.source_distribution || {})
          .map(
            ([src, n]) =>
              `<span class="prov-pill" title="Provider that originally supplied ${n} of the matched records.">${src}: ${n}</span>`
          )
          .join(" ");
        cveProvenance.innerHTML = `
          <details class="provenance-block">
            <summary>Provenance & sourcing — tool ${p.tool_version || "?"} • ruleset ${p.ruleset_version || "?"} • generated ${p.report_generated || "?"}</summary>
            <div class="provenance-body">
              <div class="prov-meta">
                Engine ${p.cve_engine_version || "?"} • Tool ${p.tool_version || "?"} • Ruleset ${p.ruleset_version || "?"}
              </div>
              ${distRows ? `<div class="prov-section"><div class="prov-section-title">Per-CVE source attribution <span class="prov-section-hint">(which provider originally supplied each record)</span></div><div class="prov-pills">${distRows}</div></div>` : ""}
              <div class="prov-section">
                <div class="prov-section-title">Live provider cache freshness <span class="prov-section-hint">(current on-disk cache state for re-fetch)</span></div>
                ${sourceRows}
              </div>
              ${p.policy_note ? `<div class="prov-note">${p.policy_note}</div>` : ""}
            </div>
          </details>
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

