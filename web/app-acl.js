// Depends on: app-core.js (API_BASE_URL)

// =============================================
// ACL WHAT-IF (ACL-01.4)
// Paste IPv4 ACLs -> lint table, edge-packet table, optional trace of one packet.
// Data: POST /tools/acl/analyze (api/routers/acl.py, ACL-01.1-3).
//
// Security (@ciso N1, 28.10): the response echoes the paste (ACL names, quoted
// lines, tokens inside the lint sentences, address and port descriptions), and
// the app has no CSP. This module therefore builds every node with
// createElement and fills it with textContent / createTextNode only. It never
// assigns markup: tests/test_acl_ui.py fails on any markup API in this file
// and runs the renderers in Node with a payload in every string field.
// =============================================

const ACL_PATH = "/tools/acl/analyze";

const ACL_EXAMPLE = [
  "ip access-list extended EDGE-IN",
  " remark SSH only from the management /24",
  " 10 permit tcp 10.1.1.0 0.0.0.255 host 192.0.2.10 eq 22",
  " 20 deny tcp any host 192.0.2.10 eq 22 log",
  " 30 permit tcp 10.1.1.0 0.0.0.255 host 192.0.2.10 eq 22",
  " 40 permit tcp any 192.0.2.0 0.0.0.255 established",
  " 50 permit udp any host 192.0.2.53 eq domain",
  " 60 permit ip any any",
  " 70 permit icmp any any",
  "!",
  "access-list 10 permit 10.2.0.5 0.0.255.255",
  "access-list 10 deny any",
].join("\n");

// Python str.splitlines() boundaries: the API numbers lines the same way.
const ACL_LINE_SPLIT = /\r\n|[\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029]/;

const ACL_LEVEL_ORDER = { ERROR: 0, WARN: 1, INFO: 2 };

let aclRequestSeq = 0;

// ---------------------------------------------------------------- DOM helpers

// Element with optional class and text. Text always goes through textContent.
function aclEl(tag, className, text) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (text !== undefined && text !== null) el.textContent = String(text);
  return el;
}

function aclClear(el) {
  if (!el) return;
  while (el.firstChild) el.removeChild(el.firstChild);
}

// Table from header labels and rows; each cell is a string/number or a Node.
function aclTable(headers, rows, className) {
  const table = aclEl("table", "acl-table" + (className ? " " + className : ""));
  const thead = aclEl("thead");
  const hr = aclEl("tr");
  headers.forEach(h => hr.appendChild(aclEl("th", null, h)));
  thead.appendChild(hr);
  table.appendChild(thead);
  const tbody = aclEl("tbody");
  rows.forEach(row => {
    const tr = aclEl("tr", row.className || null);
    row.cells.forEach(cell => {
      const td = aclEl("td", cell && cell.className ? cell.className : null);
      const value = cell && cell.node !== undefined ? cell.node : (cell && cell.text !== undefined ? cell.text : cell);
      if (value && typeof value === "object" && "nodeType" in value) td.appendChild(value);
      else td.textContent = value === null || value === undefined ? "" : String(value);
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);
  return table;
}

function aclVerdictNode(verdict, matchedLine, implicitDeny) {
  const span = aclEl("span", "acl-verdict acl-verdict-" + (verdict === "permit" ? "permit" : "deny"),
    verdict === "permit" ? "PERMIT" : "DENY");
  const wrap = aclEl("span");
  wrap.appendChild(span);
  const where = implicitDeny ? " implicit deny" : (matchedLine !== null && matchedLine !== undefined ? " line " + matchedLine : "");
  wrap.appendChild(document.createTextNode(where));
  return wrap;
}

// Lines of the paste as the API numbers them (1-based).
function aclPasteLines(text) {
  return String(text || "").split(ACL_LINE_SPLIT);
}

function aclLineText(lines, n) {
  const t = lines[n - 1];
  return t === undefined ? "" : t.trim();
}

function aclPacketText(p) {
  if (!p) return "";
  const parts = ["src " + p.src];
  if (p.dst) parts.push("dst " + p.dst);
  if (p.protocol !== null && p.protocol !== undefined) parts.push(String(p.protocol));
  if (p.src_port !== null && p.src_port !== undefined) parts.push("sport " + p.src_port);
  if (p.dst_port !== null && p.dst_port !== undefined) parts.push("dport " + p.dst_port);
  if (p.established) parts.push("established");
  return parts.join(" ");
}

// ---------------------------------------------------------------- renderers

function aclRenderSummary(container, data) {
  aclClear(container);
  const totals = (data.lint && data.lint.totals) || {};
  const head = aclEl("div", "acl-summary-row");
  [["ERROR", "acl-count-error"], ["WARN", "acl-count-warn"], ["INFO", "acl-count-info"]].forEach(([lvl, cls]) => {
    const box = aclEl("div", "acl-count " + cls);
    box.appendChild(aclEl("div", "acl-count-num", totals[lvl] || 0));
    box.appendChild(aclEl("div", "acl-count-label", lvl));
    head.appendChild(box);
  });
  container.appendChild(head);

  const acls = data.acls || [];
  if (!acls.length) {
    container.appendChild(aclEl("p", "acl-note",
      "No IPv4 ACL found in the paste. Lines the parser could not use are listed in the lint table."));
    return;
  }
  container.appendChild(aclTable(
    ["ACL", "Type", "Form", "Rules", "Evaluated"],
    acls.map(a => ({ cells: [
      { text: a.acl, className: "acl-mono" }, a.type, (a.forms || []).join(", "), a.rules, a.evaluated_rules,
    ] }))
  ));
}

function aclRenderLint(container, data) {
  aclClear(container);
  const rows = [];
  const lint = data.lint || {};
  (lint.acls || []).forEach(a => {
    const findings = (a.findings || []).slice().sort((x, y) =>
      (ACL_LEVEL_ORDER[x.level] ?? 9) - (ACL_LEVEL_ORDER[y.level] ?? 9) || x.line - y.line);
    findings.forEach(f => {
      const quote = aclEl("div", "acl-quote");
      (f.quote || []).forEach((q, i) => {
        const lineNo = (f.lines || [])[i];
        quote.appendChild(aclEl("div", null, (lineNo !== undefined ? lineNo + ": " : "") + q));
      });
      rows.push({ className: "acl-level-" + String(f.level || "").toLowerCase(), cells: [
        { text: a.acl, className: "acl-mono" },
        f.line,
        { node: aclEl("span", "acl-badge acl-badge-" + String(f.level || "").toLowerCase(), f.level) },
        { text: f.id, className: "acl-mono" },
        { node: quote },
        f.effect,
        f.proposal,
      ] });
    });
    (a.not_evaluated || []).forEach(n => {
      rows.push({ className: "acl-level-ne", cells: [
        { text: a.acl, className: "acl-mono" }, n.line,
        { node: aclEl("span", "acl-badge acl-badge-ne", "NOT EVALUATED") }, "",
        { text: n.text, className: "acl-mono" }, n.reason, "",
      ] });
    });
  });
  (lint.not_evaluated || []).forEach(n => {
    rows.push({ className: "acl-level-ne", cells: [
      "", n.line, { node: aclEl("span", "acl-badge acl-badge-ne", "NOT EVALUATED") }, "",
      { text: n.text, className: "acl-mono" }, n.reason, "",
    ] });
  });
  if (!rows.length) {
    container.appendChild(aclEl("p", "acl-clean", "No findings. Every rule can match and the ACL ends with a logged deny."));
    return;
  }
  container.appendChild(aclTable(["ACL", "Line", "Level", "ID", "Lines", "What happens", "Proposal"], rows, "acl-lint-table"));
}

function aclRenderPackets(container, data, pasteLines) {
  aclClear(container);
  const groups = data.auto_packets || [];
  if (!groups.length) {
    container.appendChild(aclEl("p", "acl-note", "No packets: the paste has no evaluated rule."));
    return;
  }
  groups.forEach(g => {
    container.appendChild(aclEl("h4", "acl-group-title", "ACL " + g.acl));
    const packets = g.packets || [];
    if (!packets.length) {
      container.appendChild(aclEl("p", "acl-note", "No edge packets for this ACL (no evaluated rule with a matchable port)."));
      return;
    }
    const rows = packets.map((r, i) => {
      const from = aclEl("div");
      from.appendChild(aclEl("div", null, "line " + r.from_line + " (" + r.relation + ")"));
      from.appendChild(aclEl("div", "acl-dim acl-mono", aclLineText(pasteLines, r.from_line)));
      const also = (r.also_built_for || []).map(x => x.line).filter((v, k, arr) => arr.indexOf(v) === k);
      if (also.length) from.appendChild(aclEl("div", "acl-dim", "same packet from line " + also.join(", ")));
      // A packet built inside a rule that lands on another line = that rule is shadowed.
      const lands = r.relation === "inside" && r.matched_line !== r.from_line;
      return { className: lands ? "acl-row-shadow" : null, cells: [
        i + 1,
        { node: from },
        { text: aclPacketText(r.packet), className: "acl-mono" },
        r.why,
        { node: aclVerdictNode(r.verdict, r.matched_line, r.implicit_deny) },
        lands ? "built inside line " + r.from_line + ", decided by " + (r.implicit_deny ? "implicit deny" : "line " + r.matched_line) : "",
      ] };
    });
    container.appendChild(aclTable(["#", "Built from", "Packet", "Edge", "Result", "Note"], rows));
  });
}

function aclRenderTrace(container, t, pasteLines) {
  aclClear(container);
  const head = aclEl("div", "acl-trace-head");
  head.appendChild(aclEl("span", "acl-dim", "ACL " + t.acl + ": "));
  head.appendChild(aclVerdictNode(t.verdict, t.matched_line, t.implicit_deny));
  container.appendChild(head);
  const rows = (t.path || []).map(step => ({
    className: step.matched ? "acl-row-match" : null,
    cells: [
      step.line,
      { text: aclLineText(pasteLines, step.line), className: "acl-mono" },
      step.matched ? "yes" : "no",
      step.reason,
    ],
  }));
  if (rows.length) container.appendChild(aclTable(["Line", "Rule", "Matched", "Why"], rows));
  if ((t.unevaluated_lines || []).length) {
    container.appendChild(aclEl("p", "acl-note",
      "Not evaluated on the way (the result may differ on the device): line " + t.unevaluated_lines.join(", ") + "."));
  }
}

// Plain-text report for Copy / Download (textarea value, never markup).
function aclFormatText(data, pasteLines) {
  const out = ["ACL WHAT-IF REPORT", "=".repeat(60)];
  const totals = (data.lint && data.lint.totals) || {};
  out.push("Findings: " + (totals.ERROR || 0) + " error, " + (totals.WARN || 0) + " warn, " + (totals.INFO || 0) + " info");
  (data.acls || []).forEach(a => out.push("ACL " + a.acl + " (" + a.type + "): " + a.evaluated_rules + "/" + a.rules + " rules evaluated"));
  out.push("", "LINT", "-".repeat(60));
  ((data.lint && data.lint.acls) || []).forEach(a => {
    (a.findings || []).forEach(f => {
      out.push("[" + f.level + "] " + f.id + " " + a.acl + " line " + f.line);
      (f.quote || []).forEach((q, i) => out.push("    " + ((f.lines || [])[i] ?? "") + ": " + q));
      out.push("    " + f.effect, "    -> " + f.proposal);
    });
    (a.not_evaluated || []).forEach(n => out.push("[NOT EVALUATED] " + a.acl + " line " + n.line + ": " + n.text + " (" + n.reason + ")"));
  });
  ((data.lint && data.lint.not_evaluated) || []).forEach(n => out.push("[NOT EVALUATED] line " + n.line + ": " + n.text + " (" + n.reason + ")"));
  if (data.trace) {
    const t = data.trace;
    out.push("", "YOUR PACKET", "-".repeat(60));
    out.push("ACL " + t.acl + ": " + String(t.verdict).toUpperCase() + (t.implicit_deny ? " (implicit deny)" : " (line " + t.matched_line + ")"));
    (t.path || []).forEach(s => out.push("  line " + s.line + " " + (s.matched ? "MATCH" : "no   ") + "  " + aclLineText(pasteLines, s.line) + (s.reason ? "  [" + s.reason + "]" : "")));
  }
  out.push("", "EDGE PACKETS", "-".repeat(60));
  (data.auto_packets || []).forEach(g => {
    out.push("ACL " + g.acl);
    (g.packets || []).forEach((r, i) => out.push("  " + (i + 1) + ". " + aclPacketText(r.packet) + " -> " +
      String(r.verdict).toUpperCase() + (r.implicit_deny ? " implicit deny" : " line " + r.matched_line) +
      "  (from line " + r.from_line + ", " + r.why + ")"));
  });
  return out.join("\n");
}

function aclRenderAll(data, pasteText, ui) {
  const lines = aclPasteLines(pasteText);
  aclRenderSummary(ui.summary, data);
  aclRenderLint(ui.lint, data);
  aclRenderPackets(ui.packets, data, lines);
  if (ui.trace) {
    if (data.trace) aclRenderTrace(ui.trace, data.trace, lines);
    else aclClear(ui.trace);
  }
  if (ui.output) ui.output.value = aclFormatText(data, lines);
}

// ---------------------------------------------------------------- errors

function aclRetryAfter(res) {
  const v = parseInt((res.headers && res.headers.get && res.headers.get("Retry-After")) || "", 10);
  return isNaN(v) || v < 0 ? null : v;
}

// Human sentence for a failed request. `body` is the parsed JSON or null.
function aclErrorMessage(status, body, retryAfter) {
  const wait = retryAfter ? " Try again in " + retryAfter + " s." : " Try again in a moment.";
  const detail = body && body.detail;
  if (status === 413) {
    return "Paste too large. " + (typeof detail === "string" ? detail : "Split it into smaller parts.");
  }
  if (status === 422) {
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail) && detail.length) {
      const fields = detail.map(d => {
        const loc = (d.loc || []).filter(x => x !== "body").join(".");
        return (loc || "request") + ": " + (d.msg || "invalid");
      });
      return "Check the input. " + fields.join("; ") + ".";
    }
    return "The input could not be read. Check the ACL and the packet fields.";
  }
  if (status === 429) return "Rate limit reached for ACL analysis (10 per minute, 120 per hour)." + wait;
  if (status === 503) return "The ACL analyzer is busy right now." + wait;
  return "Request failed (HTTP " + status + ")." + (status >= 500 ? wait : "");
}

function aclShowStatus(el, message, isError) {
  if (!el) return;
  el.textContent = message || "";
  el.hidden = !message;
  el.className = "acl-status" + (isError ? " acl-status-error" : "");
}

// ---------------------------------------------------------------- form

function aclNumberOrNull(id) {
  const el = document.getElementById(id);
  if (!el || String(el.value).trim() === "") return null;
  const n = Number(el.value);
  return Number.isInteger(n) ? n : el.value;  // a non-integer goes to the API and comes back as 422
}

function aclTextOrNull(id) {
  const el = document.getElementById(id);
  const v = el ? String(el.value).trim() : "";
  return v === "" ? null : v;
}

function aclBuildTrace() {
  const on = document.getElementById("acl-trace-on");
  if (!on || !on.checked) return null;
  const proto = aclTextOrNull("acl-trace-proto");
  return {
    acl: aclTextOrNull("acl-trace-acl"),
    src: aclTextOrNull("acl-trace-src") || "",
    dst: aclTextOrNull("acl-trace-dst"),
    protocol: proto !== null && /^\d+$/.test(proto) ? Number(proto) : proto,
    src_port: aclNumberOrNull("acl-trace-sport"),
    dst_port: aclNumberOrNull("acl-trace-dport"),
    established: !!(document.getElementById("acl-trace-est") || {}).checked,
  };
}

async function aclAnalyze(pasteText, trace) {
  const body = { config_text: pasteText, auto_packets: true };
  if (trace) body.trace = trace;
  let res;
  try {
    res = await fetch(`${API_BASE_URL}${ACL_PATH}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch (e) {
    return { ok: false, message: "Could not reach the server. Check your connection and try again." };
  }
  let json = null;
  try { json = await res.json(); } catch (e) { json = null; }
  if (!res.ok) return { ok: false, message: aclErrorMessage(res.status, json, aclRetryAfter(res)) };
  if (!json) return { ok: false, message: "The server answered with something that is not a result." };
  return { ok: true, data: json };
}

(function initAclWhatIf() {
  const form = document.getElementById("acl-form");
  if (!form) return;
  const ui = {
    status: document.getElementById("acl-status"),
    summaryCard: document.getElementById("acl-summary"),
    summary: document.getElementById("acl-summary"),
    lintCard: document.getElementById("acl-lint"),
    lint: document.getElementById("acl-lint-content"),
    packetsCard: document.getElementById("acl-packets"),
    packets: document.getElementById("acl-packets-content"),
    traceCard: document.getElementById("acl-trace"),
    trace: document.getElementById("acl-trace-content"),
    results: document.getElementById("acl-results"),
    output: document.getElementById("acl-output"),
  };
  const cards = [ui.summaryCard, ui.lintCard, ui.packetsCard, ui.traceCard, ui.results];

  const traceOn = document.getElementById("acl-trace-on");
  const traceFields = document.getElementById("acl-trace-fields");
  if (traceOn && traceFields) {
    traceOn.addEventListener("change", () => { traceFields.hidden = !traceOn.checked; });
  }
  const example = document.getElementById("acl-example");
  if (example) {
    example.addEventListener("click", () => {
      const ta = document.getElementById("acl-config");
      if (ta) ta.value = ACL_EXAMPLE;
    });
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const pasteText = (document.getElementById("acl-config") || {}).value || "";
    if (!pasteText.trim()) {
      aclShowStatus(ui.status, "Paste at least one ACL.", true);
      return;
    }
    const trace = aclBuildTrace();
    if (trace && !trace.src) {
      aclShowStatus(ui.status, "Enter a source IP for the packet trace, or untick Trace one packet.", true);
      return;
    }
    const seq = ++aclRequestSeq;
    cards.forEach(c => { if (c) c.style.display = "none"; });
    aclShowStatus(ui.status, "Analyzing...", false);
    const result = await aclAnalyze(pasteText, trace);
    if (seq !== aclRequestSeq) return;  // a newer request is in flight
    if (!result.ok) {
      aclShowStatus(ui.status, result.message, true);
      return;
    }
    aclShowStatus(ui.status, "", false);
    aclRenderAll(result.data, pasteText, ui);
    [ui.summaryCard, ui.lintCard, ui.packetsCard, ui.results].forEach(c => { if (c) c.style.display = "block"; });
    if (ui.traceCard) ui.traceCard.style.display = result.data.trace ? "block" : "none";
  });
})();
