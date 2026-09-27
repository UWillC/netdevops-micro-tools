// Depends on: app-feeds.js (esc)

// =============================================
// KEV WATCH (KW-01.3)
// New CISA KEV listings for the vendors a network engineer runs.
// Data: GET /api/kev/watch (services/kev_catalog.py, no other source).
// The API sorts by date added; this table sorts by federal due date, soonest
// first (decision @pm 27.09), because the deadline is what drives the week.
// =============================================

// Exact `vendorProject` spellings from the CISA catalog (checked against
// cache/kev/catalog.json, catalogVersion 2026.09.18). The API matches them
// case-insensitively but exactly, so "Palo Alto" would match nothing.
const KEV_VENDORS = [
  "Cisco", "Fortinet", "Palo Alto Networks", "Juniper", "Arista", "F5",
  "Check Point", "Citrix", "SonicWall", "Ivanti", "Zyxel", "MikroTik",
];
const KEV_SHORT_DEADLINE_DAYS = 3;
const KEV_DESC_MAX = 100;
const KEV_PREFS_KEY = "netdevops_kev_watch";

const kevVendorsBox = document.getElementById("kev-vendors");
const kevMeta = document.getElementById("kev-meta");
const kevStale = document.getElementById("kev-stale");
const kevTableWrap = document.getElementById("kev-table-wrap");
const kevWindowBtns = document.querySelectorAll(".kev-window-btn");

let kevDays = 14;
let kevRequestSeq = 0;
let kevLoaded = false;

function kevLoadPrefs() {
  try {
    const p = JSON.parse(localStorage.getItem(KEV_PREFS_KEY) || "null");
    if (p && typeof p === "object") return p;
  } catch (e) { /* storage blocked or corrupt: use defaults */ }
  return null;
}

function kevSavePrefs() {
  try {
    localStorage.setItem(KEV_PREFS_KEY, JSON.stringify({ days: kevDays, vendors: kevSelectedVendors() }));
  } catch (e) { /* per-viewer convenience only */ }
}

function kevSelectedVendors() {
  if (!kevVendorsBox) return [];
  return Array.from(kevVendorsBox.querySelectorAll("input[type=checkbox]:checked")).map(i => i.value);
}

// "YYYY-MM-DD" -> days since epoch (UTC), or NaN.
function kevDay(value) {
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(String(value || ""));
  if (!m) return NaN;
  return Date.UTC(+m[1], +m[2] - 1, +m[3]) / 86400000;
}

function kevShortDeadline(item) {
  const gap = kevDay(item.due_date) - kevDay(item.date_added);
  return !isNaN(gap) && gap <= KEV_SHORT_DEADLINE_DAYS;
}

function kevSort(items) {
  return items.slice().sort((a, b) => {
    const da = kevDay(a.due_date), db = kevDay(b.due_date);
    // Rows without a due date go last, never first.
    if (isNaN(da) !== isNaN(db)) return isNaN(da) ? 1 : -1;
    if (da !== db) return da - db;
    const aa = kevDay(a.date_added) || 0, ab = kevDay(b.date_added) || 0;
    if (aa !== ab) return ab - aa;
    return String(a.cve_id).localeCompare(String(b.cve_id));
  });
}

function kevShortText(text) {
  const t = String(text || "").trim();
  return t.length > KEV_DESC_MAX ? t.slice(0, KEV_DESC_MAX - 3).trimEnd() + "..." : t;
}

function kevFormatTimestamp(iso) {
  if (!iso) return "unknown";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return String(iso);
  return d.toISOString().slice(0, 16).replace("T", " ") + " UTC";
}

function kevRenderMeta(catalog) {
  if (!kevMeta) return;
  const c = catalog || {};
  const released = c.date_released ? String(c.date_released).slice(0, 10) : "unknown";
  kevMeta.textContent = `Catalog version ${c.catalog_version || "unknown"} · released ${released} · fetched ${kevFormatTimestamp(c.fetched_at)}`;
  if (kevStale) {
    if (c.stale) {
      kevStale.hidden = false;
      kevStale.textContent = `Stale copy: CISA could not be reached, so this is the last good catalog, fetched ${kevFormatTimestamp(c.fetched_at)}. Listings added after that date are not shown.`;
    } else {
      kevStale.hidden = true;
      kevStale.textContent = "";
    }
  }
}

function kevRenderTable(items) {
  const rows = kevSort(items).map(item => {
    const cve = esc(item.cve_id);
    const nvd = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(item.cve_id || "")}`;
    const short = kevShortDeadline(item);
    const ransom = item.ransomware === "Known"
      ? '<span class="kev-ransom known">Known</span>'
      : `<span class="kev-ransom">${esc(item.ransomware || "Unknown")}</span>`;
    // advisory_url is the first link in the KEV notes that is not a CISA or
    // NVD page (services/kev_catalog.py). Only http(s) links reach here.
    const adv = item.advisory_url && /^https?:\/\//i.test(item.advisory_url)
      ? `<a href="${esc(item.advisory_url)}" target="_blank" rel="noopener">advisory</a>`
      : '<span class="summary-muted">none</span>';
    const desc = item.short_description || "";
    return `<tr class="${short ? "kev-row-short" : ""}">
      <td class="kev-cve"><a href="${esc(nvd)}" target="_blank" rel="noopener">${cve}</a></td>
      <td>${esc(item.vendor_project)}<div class="kev-product">${esc(item.product)}</div></td>
      <td class="kev-date">${esc(item.date_added)}</td>
      <td class="kev-date">${esc(item.due_date)}${short ? ' <span class="kev-short" title="Federal deadline 3 days or less after the listing">short deadline</span>' : ""}</td>
      <td>${ransom}</td>
      <td class="kev-desc" title="${esc(desc)}">${esc(kevShortText(desc))}</td>
      <td>${adv}</td>
    </tr>`;
  }).join("");

  kevTableWrap.innerHTML = `<table class="kev-table">
    <thead><tr>
      <th>CVE</th><th>Vendor / product</th><th>Added</th><th>Due (sorted)</th>
      <th>Ransomware</th><th>Description</th><th>Advisory</th>
    </tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

async function loadKevWatch() {
  if (!kevTableWrap) return;
  const vendors = kevSelectedVendors();
  kevSavePrefs();
  const seq = ++kevRequestSeq;

  if (vendors.length === 0) {
    // An empty vendor list would make the API fall back to its default list,
    // so do not call it: say what is needed instead.
    kevTableWrap.innerHTML = '<p class="summary-muted">Select at least one vendor.</p>';
    return;
  }

  kevTableWrap.innerHTML = '<p class="summary-muted">Loading KEV Watch...</p>';
  const qs = new URLSearchParams({ days: String(kevDays), vendors: vendors.join(",") });

  try {
    const resp = await fetch(`/api/kev/watch?${qs.toString()}`);
    if (seq !== kevRequestSeq) return;   // a newer request superseded this one
    if (resp.status === 503) {
      if (kevMeta) kevMeta.textContent = "";
      if (kevStale) kevStale.hidden = true;
      kevTableWrap.innerHTML = '<p class="kev-error">The CISA KEV catalog is unavailable right now: no live copy and no cached copy. This is not an empty result. Try again in a few minutes.</p>';
      return;
    }
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    if (seq !== kevRequestSeq) return;

    kevRenderMeta(data.catalog);
    const items = Array.isArray(data.items) ? data.items : [];
    if (items.length === 0) {
      kevTableWrap.innerHTML = `<p class="summary-muted">No additions in the last ${esc(data.days)} days for selected vendors.</p>`;
      return;
    }
    kevRenderTable(items);
  } catch (err) {
    if (seq !== kevRequestSeq) return;
    kevTableWrap.innerHTML = `<p class="kev-error">Could not load KEV Watch: ${esc(err.message)}</p>`;
  }
}

function initKevWatch() {
  if (!kevVendorsBox) return;
  const prefs = kevLoadPrefs();
  if (prefs && [7, 14, 30].includes(prefs.days)) kevDays = prefs.days;
  const saved = prefs && Array.isArray(prefs.vendors) ? prefs.vendors : null;

  kevVendorsBox.innerHTML = KEV_VENDORS.map(v => {
    const checked = !saved || saved.includes(v);
    return `<label class="kev-vendor"><input type="checkbox" value="${esc(v)}"${checked ? " checked" : ""} /> ${esc(v)}</label>`;
  }).join("");
  kevVendorsBox.addEventListener("change", loadKevWatch);

  kevWindowBtns.forEach(btn => {
    btn.classList.toggle("active", Number(btn.dataset.days) === kevDays);
    btn.addEventListener("click", () => {
      kevDays = Number(btn.dataset.days);
      kevWindowBtns.forEach(b => b.classList.toggle("active", b === btn));
      loadKevWatch();
    });
  });

  const setAll = (on) => {
    kevVendorsBox.querySelectorAll("input[type=checkbox]").forEach(i => { i.checked = on; });
    loadKevWatch();
  };
  document.getElementById("kev-vendors-all")?.addEventListener("click", () => setAll(true));
  document.getElementById("kev-vendors-none")?.addEventListener("click", () => setAll(false));

  // Load on first open of the tab, not on every page load of the app.
  const tabBtn = document.querySelector('.tab-button[data-tab="kev-watch"]');
  tabBtn?.addEventListener("click", () => {
    if (!kevLoaded) { kevLoaded = true; loadKevWatch(); }
  });
}

initKevWatch();
