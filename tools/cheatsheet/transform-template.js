// Template for safe bulk edits of the cheat sheet DATA (merge / rename / move / drop rows and sections).
// Run:   .\Run-CheatSheetScript.ps1 -Script .\my-transform.js -OutFile .\newdata.js
// Then:  .\Splice-Data.ps1 -NewData .\newdata.js   (replaces the block between /*DATA-BEGIN*/ and /*DATA-END*/)
//        Keep a snapshot of the page first (Project_Brief.md §7 "How to edit").
// Every pick / drop is by EXACT text and throws if not found — a typo stops the run instead of silently losing rows.
(function () {
  try {
    const T = t => { const s = DATA.find(d => d[0] === t); if (!s) throw "missing section: " + t; return s; };
    const R = t => T(t)[1];
    const sub = name => ["— " + name + " —", "", ""];
    const isSub = r => !r[1] && !r[2] && r[0].startsWith("—");
    const one = (t, p) => { const r = R(t).find(x => x[0] === p); if (!r) throw "no row: " + t + " / " + p; while (r.length < 4) r.push(""); return r; };
    const pick = (t, ps) => ps.map(p => one(t, p));
    const drop = (t, ps) => ps.forEach(p => { const rows = R(t), i = rows.findIndex(x => x[0] === p); if (i < 0) throw "no row to drop: " + t + " / " + p; rows.splice(i, 1); });
    const prefixed = (t, label) => { const out = []; const rows = R(t); if (!isSub(rows[0])) out.push(sub(label));
      rows.forEach(r => out.push(isSub(r) ? sub(label + ": " + r[0].replace(/—/g, "").trim()) : r)); return out; };
    const removeSec = t => { T(t); DATA.splice(DATA.findIndex(d => d[0] === t), 1); };
    const replaceSec = (t, sec) => { T(t); DATA.splice(DATA.findIndex(d => d[0] === t), 1, sec); };
    const before = DATA.reduce((n, d) => n + d[1].length, 0), beforeSec = DATA.length;

    // ===== edits go here, e.g. =====
    // one("SNMP", "Which OIDs are being polled")[3] = "new note";
    // drop("Interface status", ["VLAN list"]);
    // replaceSec("PIM", ["PIM", [...R("PIM"), sub("Extra"), ["New row", "show ...", "", "note"]]]);
    // Remember: a renamed / new section title must also be added to CATEGORIES in the page script.

    const after = DATA.reduce((n, d) => n + d[1].length, 0);
    const out = "const DATA = [\n" + DATA.map(([t, rows, cols]) =>
      " [" + JSON.stringify(t) + ", [\n" + rows.map(r => "  " + JSON.stringify(r) + ",").join("\n") + "\n ]" + (cols ? ", " + JSON.stringify(cols) : "") + "],"
    ).join("\n") + "\n];";
    document.title = "OK sections " + beforeSec + "->" + DATA.length + " rows " + before + "->" + after;
    document.body.insertAdjacentHTML("beforeend", '<pre id="out">' + btoa(unescape(encodeURIComponent(out))) + "</pre>");
  } catch (e) {
    document.title = "ERROR " + e;
    document.body.insertAdjacentHTML("beforeend", '<pre id="out">' + btoa(unescape(encodeURIComponent("ERROR " + e))) + "</pre>");
  }
})();
