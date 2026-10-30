// Read-only audit of DATA. Writes a report into the page.
(function () {
  const out = [];
  const isSub = r => !r[1] && !r[2] && r[0].startsWith("—");
  const titles = new Set(DATA.map(d => d[0]));

  // 1. duplicate purposes inside a section
  DATA.forEach(([t, rows]) => {
    const seen = {};
    rows.filter(r => !isSub(r)).forEach(r => { seen[r[0]] = (seen[r[0]] || 0) + 1; });
    Object.entries(seen).filter(([, n]) => n > 1).forEach(([p, n]) => out.push(`DUP-PURPOSE | ${t} | ${p} x${n}`));
  });

  // 2. identical command cells repeated across sections (show only if 3+ places)
  const cmdPlaces = {};
  DATA.filter(d => d[0] !== "Symptom index").forEach(([t, rows]) => rows.forEach(r => [r[1], r[2]].forEach(c => { if (c) (cmdPlaces[c] = cmdPlaces[c] || new Set()).add(t); })));
  Object.entries(cmdPlaces).filter(([, s]) => s.size >= 3).forEach(([c, s]) => out.push(`CMD-IN-${s.size}-SECTIONS | ${c.split("\n")[0]} | ${[...s].join(" ; ")}`));

  // 3. rows with no command and no note
  DATA.forEach(([t, rows]) => rows.forEach(r => { if (!isSub(r) && !r[1] && !r[2] && !r[3]) out.push(`EMPTY-ROW | ${t} | ${r[0]}`); }));

  // 4. sub-heading with nothing after it / consecutive sub-headings
  DATA.forEach(([t, rows]) => rows.forEach((r, i) => {
    if (isSub(r) && (i === rows.length - 1 || isSub(rows[i + 1]))) out.push(`EMPTY-SUBHEADING | ${t} | ${r[0]}`);
  }));

  // 5. risky commands without a warning flag
  const risky = /^(no |clear |debug |reload|copy |write |install |configure |rollback|delete |format |erase |crypto key|test cable|udld reset|shutdown|request |restart|systemctl restart|ipconfig \/(release|renew)|podman run|ansible-playbook (?!.*(--check|--syntax-check|--list))|conn\.send_config|spanning-tree |switchport |interface |vpc domain|feature |netconf-yang|restconf|gnxi|power inline|switch \d|software auto|policy-map|copp |monitor session|monitor capture \S+ (start|interface|control-plane)|ip sla schedule|event manager run|firewall-cmd --add|clear session|debug dataplane|set system setting(?! target-vsys)|vpn-sessiondb logoff|no failover|failover active|capture )/i;
  DATA.forEach(([t, rows]) => rows.forEach(r => {
    if (isSub(r) || r[4]) return;
    const cmds = [r[1], r[2]].filter(Boolean).join("\n").split("\n");
    const hit = cmds.find(c => risky.test(c.trim()));
    if (hit) out.push(`NO-WARN | ${t} | ${r[0]} | ${hit.trim().slice(0, 70)}`);
  }));

  // 6. notes that point to a section name that does not exist
  DATA.forEach(([t, rows]) => rows.forEach(r => {
    const n = r[3] || "";
    const m = n.match(/[Ss]ee (?:the )?([A-Z][^.;—(]*?) section/g) || [];
    m.forEach(x => { const name = x.replace(/^[Ss]ee (the )?/, "").replace(/ section$/, "").trim();
      if (![...titles].some(tt => tt.toLowerCase().startsWith(name.toLowerCase()))) out.push(`BAD-REF | ${t} | ${r[0]} | "${name}"`); });
    // "→ A · B" cross-link lists (Symptom index, see-also): every entry must be an existing section title
    const ai = n.lastIndexOf("→ "); if (ai >= 0 && t === "Symptom index") n.slice(ai + 2).split(" · ").map(x => x.trim()).filter(x => !titles.has(x)).forEach(x => out.push(`BAD-XREF | ${t} | ${r[0]} | "${x}"`));
  }));

  // 7. placeholder vocabulary (spot near-duplicates like <interface> vs <intf>)
  const ph = {};
  DATA.forEach(([, rows]) => rows.forEach(r => [r[1], r[2]].forEach(c => (c || "").replace(/<([a-z0-9:\/-]+)>/gi, (_, p) => { ph[p] = (ph[p] || 0) + 1; }))));
  out.push("PLACEHOLDERS | " + Object.entries(ph).sort((a, b) => b[1] - a[1]).map(([p, n]) => p + "=" + n).join(" "));

  // 8. long sections without sub-headings
  DATA.forEach(([t, rows]) => { if (rows.length > 14 && !rows.some(isSub)) out.push(`NO-SUBHEADINGS | ${t} | ${rows.length} rows`); });

  // 9. stray whitespace in commands
  DATA.forEach(([t, rows]) => rows.forEach(r => [r[1], r[2]].forEach(c => (c || "").split("\n").forEach(l => {
    if (l !== l.trimEnd()) out.push(`TRAILING-SPACE | ${t} | ${r[0]}`);
  }))));

  document.title = "AUDIT " + out.length;
  document.body.innerHTML = '<pre id="out">' + btoa(unescape(encodeURIComponent(out.join("\n")))) + "</pre>";
})();
