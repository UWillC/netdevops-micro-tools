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
        // A result that was never computed must not read as a clean one.
        const notEvaluated = typeof data.coverage_note === "string" && data.coverage_note.startsWith("NOT EVALUATED");
        const emptyLine = notEvaluated
          ? data.coverage_note
          : "No CVEs from current dataset matched this platform/version.";
        cveOutput.value = header + emptyLine + "\n" +
          (!notEvaluated && data.coverage_note ? "\n" + data.coverage_note + "\n" : "");
        if (cveCards) cveCards.innerHTML = "";

        if (cveSummary) {
          cveSummary.innerHTML = notEvaluated
            ? `<h3>Security posture</h3>
               <p style="color:#f97316; font-weight:600;">Not evaluated</p>
               <p class="summary-muted">${esc(data.coverage_note)}</p>`
            : `<h3>Security posture</h3>
               <p class="summary-muted">No CVEs from the current dataset matched this platform/version.</p>
               ${data.coverage_note ? `<p class="summary-muted">${esc(data.coverage_note)}</p>` : ""}`;
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

      // EOSM-01: software-lifecycle caveat for the queried train. Same slot as
      // the EoL banner but its own wording — "replace the hardware" would be
      // false for a software-maintenance phase. textContent, not innerHTML.
      if (cveEolBanner && data.lifecycle_note && !(data.eol_status && data.eol_status.is_eol)) {
        const box = document.createElement("div");
        box.className = "eol-banner";
        const title = document.createElement("div");
        title.className = "eol-banner-title";
        title.textContent = "\u26a0 Software lifecycle notice for your release";
        const body = document.createElement("div");
        body.className = "eol-banner-body";
        body.textContent = data.lifecycle_note;
        box.appendChild(title);
        box.appendChild(body);
        cveEolBanner.innerHTML = "";
        cveEolBanner.appendChild(box);
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
      // What the page lists is "display items", not raw CVEs:
      //  - a hardening release is ONE item (Cisco assigns one CVE per CWE
      //    category; seven CVEs of one release are one job, not seven);
      //  - confirmed matches come first, unconfirmed ones in their own section.
      // The headline counts describe confirmed items only. Before this, an
      // IOS XE 17.12.4 report read "10 CRITICAL" where 7 were one hardening
      // release and 2 were unconfirmed matches from 2012 and 2015.
      const uncertainIds = new Set(Array.isArray(data.coverage_uncertain) ? data.coverage_uncertain : []);
      const bundledIdSet = new Set(Array.isArray(data.bundled_cves) ? data.bundled_cves : []);
      const sevOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, NONE: 4, UNKNOWN: 5 };
      const buildItems = (list) => {
        const items = [];
        const groups = {};
        list.forEach((cve) => {
          if (bundledIdSet.has(cve.cve_id) && cve.advisory_url) {
            let g = groups[cve.advisory_url];
            if (!g) {
              g = { group: true, cves: [], advisory_url: cve.advisory_url, title: cve.title };
              groups[cve.advisory_url] = g;
              items.push(g);
            }
            g.cves.push(cve);
          } else {
            items.push({ group: false, cve });
          }
        });
        return items;
      };
      const itemSeverity = (it) => it.group
        ? it.cves.map(displaySeverity).sort((a, b) => (sevOrder[a] ?? 9) - (sevOrder[b] ?? 9))[0]
        : displaySeverity(it.cve);
      const confirmedItems = buildItems(data.matched.filter((c) => !uncertainIds.has(c.cve_id)));
      const unconfirmedItems = buildItems(data.matched.filter((c) => uncertainIds.has(c.cve_id)));

      const primaryCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, NONE: 0, UNKNOWN: 0 };
      confirmedItems.forEach((it) => {
        const sev = itemSeverity(it);
        if (primaryCounts[sev] !== undefined) primaryCounts[sev] += 1;
      });
      const hardeningGroups = confirmedItems.concat(unconfirmedItems).filter((it) => it.group);

      // Text report output
      let out = "";
      out += `Platform: ${data.platform}\n`;
      out += `Version: ${data.version}\n`;
      out += `Timestamp: ${data.timestamp}\n\n`;

      if (data.eol_status && data.eol_status.is_eol) {
        out += "*** END-OF-LIFE PLATFORM ***\n";
        out += data.eol_status.banner_text + "\n\n";
      }

      if (data.dataset_syncing) {
        out += "NOTE: the dataset is still synchronising with Cisco after a server restart. " +
               "This list may grow; run the analysis again in a minute.\n\n";
      }
      if (data.coverage_note) {
        out += data.coverage_note + "\n\n";
      }

      if (data.lifecycle_note) {
        out += "*** SOFTWARE LIFECYCLE NOTICE ***\n";
        out += data.lifecycle_note + "\n\n";
      }

      const bundledCveIds = new Set(Array.isArray(data.bundled_cves) ? data.bundled_cves : []);

      const writeGroup = (g) => {
        const sev = itemSeverity(g);
        const maxScore = Math.max(...g.cves.map((c) => Number(c.cvss_score) || 0));
        out += `HARDENING RELEASE [${sev}] [${g.cves.length} CVEs, ONE JOB]\n`;
        out += `  Title: ${g.title}\n`;
        out += `  CVEs (one per CWE category): ${g.cves.map((c) => `${c.cve_id} (${formatCvss(c.cvss_score)})`).join(", ")}\n`;
        out += `  Max CVSS: ${formatCvss(maxScore)}\n`;
        out += "  Note: each CVE here stands for a category of fixes, not one defect. None can be\n";
        out += "        mitigated on its own; the only remediation is the hardened release. Do not\n";
        out += "        open one ticket per CVE.\n";
        out += `  Advisory: ${g.advisory_url}\n\n`;
      };
      const writeCve = (cve) => {
        const primary = displaySeverity(cve);
        const d = sevDetails[cve.cve_id] || {};
        const bundle = bundles[cve.cve_id];
        let line = `${cve.cve_id} [${primary}]`;
        if (d.cisco_sir) line += ` [Cisco SIR: ${d.cisco_sir}]`;
        if (bundle) line += ` [Bundle: ${bundle}]`;
        // CVE-007: a hardening-release CVE is a CWE class, not a single bug.
        const isBundledCve = bundledCveIds.has(cve.cve_id);
        if (isBundledCve) line += " [CLASS OF DEFECTS]";
        if (cve.kev) line += ` [CISA KEV, due ${cve.kev.due_date}]`;
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
        // ISE-03: ISE is fixed per train, so list every train's fix.
        const trainFixes = (cve.first_fixed_version && cve.first_fixed_version.fixes) || null;
        if (trainFixes && Object.keys(trainFixes).some((k) => k.startsWith("ise-"))) {
          const parts = Object.keys(trainFixes).sort().map((k) => trainFixes[k]);
          out += `  Fixed in (per train): ${parts.join(" | ")}\n`;
        }
        if (isBundledCve) {
          out += "  Note: hardening-release CVE. One CVE covers many fixes in a single CWE\n";
          out += "        category. It cannot be mitigated on its own; remediation is the\n";
          out += "        hardened release.\n";
        }
        if (cve.workaround) out += `  Workaround: ${cve.workaround}\n`;
        out += `  Advisory: ${cve.advisory_url}\n`;
        if (cve.references && cve.references.length > 0) {
          out += `  References: ${cve.references.join(" | ")}\n`;
        }
        out += "\n";
      };
      const writeItems = (items) => items.forEach((it) => (it.group ? writeGroup(it) : writeCve(it.cve)));

      const confirmedCves = confirmedItems.reduce((n, it) => n + (it.group ? it.cves.length : 1), 0);
      out += `Matched, confirmed for your release: ${confirmedItems.length} item(s) (${confirmedCves} CVE(s))\n`;
      out += "=".repeat(60) + "\n";
      writeItems(confirmedItems);
      if (unconfirmedItems.length > 0) {
        const unconfirmedCves = unconfirmedItems.reduce((n, it) => n + (it.group ? it.cves.length : 1), 0);
        out += `Lower confidence, NOT confirmed for your release: ${unconfirmedCves} CVE(s)\n`;
        out += "=".repeat(60) + "\n";
        out += "(Cisco names the product in these advisories without listing releases, or the advisory\n";
        out += " is years older than your release. Not counted in the severity breakdown below.\n";
        out += " Check the advisory before acting on any of them.)\n\n";
        writeItems(unconfirmedItems);
      }

      // MATCH-01: say what was ruled out, and on whose authority.
      const notListed = Array.isArray(data.excluded_not_listed) ? data.excluded_not_listed : [];
      if ((data.matched_on_known_affected || 0) > 0 || notListed.length > 0) {
        out += `Cisco Known Affected lists: ${data.matched_on_known_affected || 0} match(es) are an exact hit on your release; `;
        out += `${notListed.length} advisory CVE(s) were ruled out because your release is not listed.\n`;
        const conflicts = Array.isArray(data.cisco_source_conflicts) ? data.cisco_source_conflicts : [];
        if (conflicts.length > 0) {
          out += `${conflicts.length} CVE(s) not reported: Cisco's release list includes your release, but the advisory's own\n`;
          out += "Fixed Software table names it as the first fixed release. The table is the part PSIRT validates,\n";
          out += `so it was followed (${conflicts.slice(0, 3).join(", ")}${conflicts.length > 3 ? ", …" : ""}). Check those advisories if in doubt.\n`;
        }
        const kaDates = data.known_affected_as_of;
        if (kaDates && kaDates.oldest) {
          out += kaDates.oldest === kaDates.newest
            ? `Lists read from Cisco on ${kaDates.oldest}; refreshed automatically when Cisco revises an advisory.\n`
            : `Lists read from Cisco between ${kaDates.oldest} and ${kaDates.newest}; refreshed automatically when Cisco revises an advisory.\n`;
        }
        out += "(The list is Cisco's statement as of each advisory's last revision. A release that\n";
        out += " shipped after that revision may be absent without having been assessed.)\n\n";
      }

      if (bundledCveIds.size > 0) {
        out += `Hardening-release CVEs: ${bundledCveIds.size} / ${data.matched.length}\n`;
        out += "(Since July 2026 Cisco assigns one CVE per CWE category in hardening releases,\n";
        out += " not one per defect. Read these as classes of bugs fixed together.)\n\n";
      }

      out += "Severity breakdown, confirmed matches only (NVD CVSS v3.x; a hardening release counts once):\n";
      ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"].forEach((sev) => {
        if (primaryCounts[sev] > 0) out += `  ${sev}: ${primaryCounts[sev]}\n`;
      });

      // v0.6.23: data-quality breakdown in text report
      const dqMapTxt = data.data_quality || {};
      const dqCountsTxt = { verified: 0, "max-bound": 0, uncertain: 0 };
      Object.values(dqMapTxt).forEach((v) => {
        const c = v && v.confidence;
        if (dqCountsTxt[c] !== undefined) dqCountsTxt[c]++;
      });
      if ((dqCountsTxt["max-bound"] + dqCountsTxt["uncertain"]) > 0) {
        out += `\nData quality: ${dqCountsTxt.verified} verified / ${dqCountsTxt["max-bound"]} PSIRT max-bound`;
        if (dqCountsTxt.uncertain > 0) out += ` / ${dqCountsTxt.uncertain} uncertain`;
        out += "\n(PSIRT max-bound = matched by affected.max only, less reliable than a curated fix version or a Cisco Known Affected list.)\n";
      }

      // v0.6.24 CVE-006 Phase 5+6: coverage-uncertain bucket in text report.
      // Union of non-verified data_quality results + published-date heuristic.
      const cuIds = Array.isArray(data.coverage_uncertain) ? data.coverage_uncertain : [];
      if (cuIds.length > 0) {
        const totalMatched = (data.matched || []).length;
        out += `\nCoverage uncertain: ${cuIds.length} / ${totalMatched} CVE(s) flagged for lower confidence`;
        out += `\n(Either PSIRT max-bound match OR published >3 years before target version release.`;
        out += `\n Treat as informational; manual PSIRT advisory review recommended for critical decisions.)\n`;
      }

      if (data.recommended_upgrade) {
        const label = data.eol_status && data.eol_status.is_eol ? "Remediation" : "Recommended upgrade target";
        out += `\n${label}: ${data.recommended_upgrade}\n`;
        if (
          data.eol_status &&
          data.eol_status.is_eol &&
          data.original_engine_recommendation
        ) {
          out += `(Engine's pre-EoL suggestion would have been: ${data.original_engine_recommendation} — not actionable on this hardware.)\n`;
        }
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
          // KEV-X: for the CISA catalog the version is the evidence, not the
          // file count — and "no catalog" must be said out loud, because then
          // the absence of a KEV flag in this report proves nothing.
          if (s.name === "cisa-kev") {
            out += s.catalog_version
              ? `  cisa-kev: catalog ${s.catalog_version}\n`
              : "  cisa-kev: no catalog available (KEV flags in this report come from curated records only)\n";
          } else if (s.available) {
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
        const sectionHeader = (text, sub) => {
          const h = document.createElement("div");
          h.className = "cve-section-header";
          h.style.cssText = "margin:1rem 0 0.5rem; font-weight:700;";
          h.innerHTML = `${esc(text)}${sub ? `<div class="cve-item-meta" style="font-weight:400;">${esc(sub)}</div>` : ""}`;
          cveCards.appendChild(h);
        };
        const renderGroup = (g) => {
          const card = document.createElement("div");
          card.className = "cve-item";
          const sev = itemSeverity(g);
          const maxScore = Math.max(...g.cves.map((c) => Number(c.cvss_score) || 0));
          card.innerHTML = `
            <div class="cve-item-header">
              <div>
                <div class="cve-item-title">
                  <span class="${badgeClass(sev)}">${sev}</span>
                  <span class="secondary-tag tag-bundle" title="Cisco assigns one CVE per CWE category in a hardening release">Hardening release: ${g.cves.length} CVEs, one job</span>
                  ${esc(g.title)}
                </div>
                <div class="cve-item-meta">Max CVSS: ${formatCvss(maxScore)} • ${g.cves.map((c) => esc(c.cve_id)).join(", ")}</div>
              </div>
              <div class="cve-item-meta">Click</div>
            </div>
            <div class="cve-item-body">
              <div>Each CVE here stands for a category of fixes, not one defect. None can be mitigated on its own; the only remediation is the hardened release. Do not open one ticket per CVE.</div>
              <div style="margin-top:8px;"><strong>Advisory:</strong> ${esc(g.advisory_url)}</div>
            </div>`;
          card.querySelector(".cve-item-header").addEventListener("click", () => {
            card.querySelector(".cve-item-body").classList.toggle("open");
          });
          cveCards.appendChild(card);
        };
        const renderCve = (cve) => {
          const card = document.createElement("div");
          card.className = "cve-item";

          const primary = displaySeverity(cve);
          const d = sevDetails[cve.cve_id] || {};
          const bundle = bundles[cve.cve_id];

          // Secondary tags (Cisco SIR, bundle, escalation reason, data quality)
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
          // v0.6.23: data-quality badge (only render when not "verified")
          const dq = (data.data_quality || {})[cve.cve_id];
          if (dq && dq.confidence && dq.confidence !== "verified") {
            const label = dq.confidence === "max-bound" ? "PSIRT max-bound"
                        : dq.confidence === "uncertain"  ? "Coverage uncertain"
                        : dq.confidence;
            const tip = (dq.rationale || "").replace(/"/g, "&quot;");
            secondaryTags.push(
              `<span class="secondary-tag tag-quality-${dq.confidence}" title="${tip}">${label}</span>`
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
                  ${esc(cve.cve_id)} — ${esc(cve.title)}
                </div>
                <div class="cve-item-meta">
                  ${metaBits.join(" • ")}
                </div>
                <div class="cve-item-meta">
                  Tags: ${esc((cve.tags || []).join(", "))}
                </div>
              </div>
              <div class="cve-item-meta">Click</div>
            </div>

            <div class="cve-item-body">
              <div><strong>Description:</strong> ${esc(cve.description)}</div>
              ${
                cve.workaround
                  ? `<div style="margin-top:8px;"><strong>Workaround:</strong> ${esc(cve.workaround)}</div>`
                  : ""
              }
              ${
                cve.advisory_url
                  ? `<div style="margin-top:8px;"><strong>Advisory:</strong> ${esc(cve.advisory_url)}</div>`
                  : ""
              }
              ${
                cve.references && cve.references.length > 0
                  ? `<div style="margin-top:8px;"><strong>References:</strong> ${esc(cve.references.join(" | "))}</div>`
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
        };
        const renderItems = (items) => items.forEach((it) => (it.group ? renderGroup(it) : renderCve(it.cve)));

        sectionHeader(`Confirmed for your release (${confirmedItems.length})`);
        renderItems(confirmedItems);
        if (unconfirmedItems.length > 0) {
          sectionHeader(
            `Lower confidence, not confirmed (${unconfirmedItems.length})`,
            "Cisco names the product without listing releases, or the advisory is years older than your release. Not counted in the severity breakdown."
          );
          renderItems(unconfirmedItems);
        }
      }

      // Security posture summary — counts derived from PRIMARY severity
      // (NVD CVSS v3.x bucket) so the breakdown matches the badges.
      if (cveSummary) {
        const critical = primaryCounts.CRITICAL;
        const high = primaryCounts.HIGH;
        const medium = primaryCounts.MEDIUM;
        const low = primaryCounts.LOW;

        // Confirmed matches only, like the counts above it.
        const scores = (data.matched || [])
          .filter((x) => !uncertainIds.has(x.cve_id))
          .map((x) => Number(x.cvss_score))
          .filter((n) => !Number.isNaN(n));

        const maxCvss = scores.length ? Math.max(...scores) : null;

        // Count CVEs whose Cisco SIR diverges from CVSS bucket (CVE-007).
        const sirDistinct = (data.matched || []).filter(
          (cve) => (sevDetails[cve.cve_id] || {}).cisco_sir
        ).length;
        // Count CVEs marked as part of a Cisco semi-annual bundle (CVE-010).
        const bundleCount = Object.values(bundles).filter((v) => v).length;
        // v0.6.23: Count CVEs by data-quality confidence level.
        const dqMap = data.data_quality || {};
        const dqCounts = { verified: 0, "max-bound": 0, uncertain: 0 };
        Object.values(dqMap).forEach((v) => {
          const c = v && v.confidence;
          if (dqCounts[c] !== undefined) dqCounts[c]++;
        });

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
          <div class="summary-row"><span>Confirmed</span><span>${critical} / ${high} / ${medium} / ${low}</span></div>
          ${unconfirmedItems.length > 0
            ? `<div class="summary-row summary-muted" title="Matches Cisco did not confirm for this exact release. Listed separately and not counted above."><span>Not confirmed</span><span>${unconfirmedItems.length} listed separately</span></div>`
            : ""}
          ${hardeningGroups.length > 0
            ? `<div class="summary-row summary-muted" title="A hardening release is counted once: Cisco assigns one CVE per CWE category, and the release is the only remediation."><span>Hardening releases</span><span>${hardeningGroups.length} (${hardeningGroups.reduce((n, g) => n + g.cves.length, 0)} CVEs, counted once each)</span></div>`
            : ""}
          <div class="summary-row"><span>Max CVSS</span><span>${formatCvss(maxCvss)}</span></div>
          ${
            sirDistinct > 0
              ? `<div class="summary-row summary-muted"><span>Cisco SIR ≠ CVSS</span><span>${sirDistinct} CVE(s)</span></div>`
              : ""
          }
          ${
            (dqCounts["max-bound"] + dqCounts["uncertain"]) > 0
              ? `<div class="summary-row summary-muted" title="Data-quality confidence. PSIRT-import records match via affected.max (less reliable than curated fix_version). Full fix in CVE-006 W19+ sprint."><span>Data quality</span><span>${dqCounts.verified} verified / ${dqCounts["max-bound"]} PSIRT max-bound${dqCounts.uncertain ? ` / ${dqCounts.uncertain} uncertain` : ""}</span></div>`
              : ""
          }
          ${
            (Array.isArray(data.coverage_uncertain) && data.coverage_uncertain.length > 0)
              ? `<div class="summary-row summary-muted" title="Coverage uncertain = matched via PSIRT max-bound OR published >3 years before target version release. Treat as informational. CVE-006 Phase 5+6 transparency layer."><span>Coverage uncertain</span><span>${data.coverage_uncertain.length} / ${(data.matched || []).length} CVE(s)</span></div>`
              : ""
          }
          ${
            bundleCount > 0
              ? `<div class="summary-row summary-muted"><span>In Cisco bundle</span><span>${bundleCount} CVE(s)</span></div>`
              : ""
          }
          ${
            data.recommended_upgrade
              ? `<div class="summary-upgrade${data.eol_status && data.eol_status.is_eol ? " summary-upgrade-eol" : ""}">
                   ${data.eol_status && data.eol_status.is_eol ? "Remediation:" : "Recommended upgrade target:"}<br/>
                   <strong>${data.recommended_upgrade}</strong>
                   ${
                     data.eol_status && data.eol_status.is_eol && data.original_engine_recommendation
                       ? `<div class="summary-upgrade-context">Engine's pre-EoL suggestion would have been: <code>${data.original_engine_recommendation}</code> (not actionable on this hardware).</div>`
                       : ""
                   }
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
            if (s.name === "cisa-kev") {
              const kevStatus = s.catalog_version
                ? `<span class="prov-fresh">catalog ${s.catalog_version}</span>`
                : `<span class="prov-missing" title="No CISA KEV catalog could be obtained. KEV flags in this report come from curated records only, so a missing flag proves nothing.">no catalog available</span>`;
              return `<div class="prov-row"><span class="prov-name">${s.name}</span> ${kevStatus}<div class="prov-desc">${s.description}</div></div>`;
            }
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

// Platform select: keep the version example in step with the chosen platform,
// and replace the version only while it is still an untouched example.
(function () {
  const sel = document.getElementById("cve-platform");
  const ver = document.getElementById("cve-version");
  const hint = document.getElementById("cve-version-hint");
  if (!sel || !ver) return;
  const examples = Array.from(sel.options).map((o) => o.dataset.example);
  sel.addEventListener("change", () => {
    const ex = sel.options[sel.selectedIndex].dataset.example || "";
    if (!ver.value.trim() || examples.includes(ver.value.trim())) ver.value = ex;
    ver.placeholder = ex;
    if (hint) hint.innerHTML = `Example for this platform: <code>${ex}</code>`;
  });
})();
