// Merge users' field checks (Favorites › Export JSON, key "verified") into the 6th row field of DATA.
// Run via Merge-Verification.ps1 (it prepends "const VERIF = <export json>;"). Runs inside the page, so it can use
// migrateFav / parseVer / cleanVer. Only "works" checks are written; "fails" / "differs" are listed for manual review.
// Output: new DATA block (between the DATA markers) + "\n/*REPORT*/" + report text.
(function () {
  try {
    const isSub = r => !r[1] && !r[2] && r[0].startsWith("—");
    const byKey = new Map();
    DATA.forEach(([t, rows]) => rows.forEach(r => { if (!isSub(r)) byKey.set(t + " :: " + r[0], r); }));
    const rep = [], src = (VERIF && VERIF.verified) || {};
    let written = 0;
    Object.entries(src).forEach(([id, list]) => {
      const k = migrateFav(id), r = byKey.get(k);
      if (!r) { rep.push("ORPHAN | " + id + " (row renamed or removed — check by hand)"); return; }
      (Array.isArray(list) ? list : []).forEach(raw => {
        const v = cleanVer(raw);
        if (!v) { rep.push("INVALID | " + k + " | " + JSON.stringify(raw).slice(0, 120)); return; }
        if (v.fix && /\b\d{1,3}(\.\d{1,3}){3}\b|\.(local|lan|corp|int)\b/i.test(v.fix)) rep.push("MASK? | " + k + " | correction may contain environment data — do not copy it as is");
        if (v.res !== "works") { rep.push("REVIEW-" + v.res.toUpperCase() + " | " + k + " | " + (v.col === "x" ? "left" : "right") + " column | " + v.rel + " | " + v.src + (v.fix ? " | suggested: " + v.fix : "")); return; }
        while (r.length < 6) r.push("");
        const cur = parseVer(r[5]).filter(x => x.col !== v.col);
        r[5] = [...cur, v].map(x => `${x.col}:${x.rel}/${x.src}/${x.date}`).join("; ");
        written++;
        if (UNV.test(r[3] || "")) rep.push("BADGE | " + k + " | verified works on " + v.rel + " — consider removing the 'not confirmed' wording from the note");
      });
    });
    // trailing empty fields are not needed when nothing follows
    DATA.forEach(([, rows]) => rows.forEach(r => { while (r.length > 3 && r[r.length - 1] === "") r.pop(); }));
    const out = "const DATA = [\n" + DATA.map(([t, rows, cl]) =>
      " [" + JSON.stringify(t) + ", [\n" + rows.map(r => "  " + JSON.stringify(r) + ",").join("\n") + "\n ]" + (cl ? ", " + JSON.stringify(cl) : "") + "],"
    ).join("\n") + "\n];" + "\n/*REPORT*/\n" + ["Field checks written: " + written, ...rep].join("\n");
    document.title = "OK written " + written + ", report lines " + rep.length;
    document.body.insertAdjacentHTML("beforeend", '<pre id="out">' + btoa(unescape(encodeURIComponent(out))) + "</pre>");
  } catch (e) {
    document.title = "ERROR " + e;
    document.body.insertAdjacentHTML("beforeend", '<pre id="out">' + btoa(unescape(encodeURIComponent("ERROR " + e))) + "</pre>");
  }
})();
