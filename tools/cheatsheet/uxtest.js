(async function () {
  const out = [];
  const ok = (name, cond, extra) => out.push((cond ? "PASS " : "FAIL ") + name + (extra ? " — " + extra : ""));
  try {
    try { localStorage.clear(); sessionStorage.clear(); } catch (_) {}
    const visRows = () => ROWS.filter(r => !r.tr.classList.contains("hide")).length;
    ok("render", DATA.length === META.filter(Boolean).length && ROWS.length > 1200, `sections ${DATA.length}, rows ${ROWS.length}`);
    ok("unique row ids", new Set(ROWS.map(r => r.id)).size === ROWS.length);
    ok("unique section ids", new Set(META.filter(Boolean).map(m => m.sid)).size === META.filter(Boolean).length);

    const set = q => { qEl.value = q; filter(); return visRows(); };
    const nAll = set("");
    const nLacp = set("lacp"), nLacpNeigh = set("lacp neighbor");
    ok("multi-word AND narrows", nLacpNeigh > 0 && nLacpNeigh < nLacp, `lacp=${nLacp}, "lacp neighbor"=${nLacpNeigh}`);
    const nAbbr = set("sh ip int br");
    ok("abbreviated words (sh ip int br)", nAbbr > 0, `${nAbbr} rows`);
    const nPhrase = set('"show etherchannel summary"');
    ok("exact phrase", nPhrase > 0 && nPhrase < nLacp + 50, `${nPhrase} rows`);
    const nEx = set("lacp -nx"), nIn = set("lacp");
    ok("exclude word", nEx <= nIn, `lacp=${nIn}, lacp -nx=${nEx}`);
    set("lacp");
    ok("results grouped (chips)", resbar.querySelectorAll("a.chip").length > 1, resbar.querySelectorAll("a.chip").length + " section chips");
    ok("sub-headings kept for matching groups", SUBS.some(s => !s.tr.classList.contains("hide")));
    set("etherchanel");
    ok("did-you-mean on typo", !!resbar.querySelector("[data-with]"), (resbar.querySelector("[data-with]") || {}).textContent);
    document.querySelector('#plat [data-p="ios"]').click();
    set("show port-channel summary");
    ok("hidden-column hint", !!resbar.querySelector("[data-showboth]"), (resbar.querySelector("[data-showboth]") || {}).textContent);
    document.querySelector('#plat [data-p="both"]').click();
    set("");
    ok("filter cleared", visRows() === nAll);

    // variables
    vars = { intf: "Gi1/0/24" }; saveVars();
    const safeBtn = [...document.querySelectorAll("tr:not(.risky) .cmd")].find(b => b.dataset.c.includes("<intf>"));
    const riskyBtn = [...document.querySelectorAll("tr.risky .cmd")].find(b => b.dataset.c.includes("<intf>"));
    ok("variables shown in safe rows", safeBtn && safeBtn.textContent.includes("Gi1/0/24"), safeBtn && safeBtn.textContent);
    ok("variables NOT applied in ⚠ rows", riskyBtn && riskyBtn.textContent.includes("<intf>"), riskyBtn && riskyBtn.textContent);
    ok("copy text substituted", subst(safeBtn.dataset.c, false).includes("Gi1/0/24"));
    ok("vars badge", document.getElementById("varsbtn").classList.contains("active"), document.getElementById("varsn").textContent);
    vars = {}; saveVars();

    // keyboard nav + favorites via key handler
    const kd = (key, opts) => document.dispatchEvent(new KeyboardEvent("keydown", Object.assign({ key, bubbles: true }, opts || {})));
    window.scrollTo(0, 0);
    kd("j"); const r1 = cur; kd("j"); const r2 = cur;
    ok("j moves row focus", r1 && r2 && r1 !== r2, r2 && r2.dataset.id);
    kd("k"); ok("k moves back", cur === r1);
    kd("s"); ok("s stars the row", favs.has(r1.dataset.id), "favorites=" + favs.size);
    kd("s"); ok("s again un-stars", !favs.has(r1.dataset.id));

    // deep link
    const target = ROWS.find(r => r.sec === "EtherChannel");
    goTo(target.id, true);
    ok("deep link to row", location.hash === "#" + target.id && cur === target.tr, location.hash);
    goTo("s-vpc-nexus", true);
    ok("deep link to section", location.hash === "#s-vpc-nexus");

    // palette
    openPal(); palIn.value = "etherchannel summ"; palRender();
    ok("Ctrl+K palette finds items", pal.open && palItems.length > 0, palItems.slice(0, 3).map(i => i.label).join(" | "));
    pal.close();

    // density + print header
    document.querySelector('#dens [data-d="compact"]').click();
    ok("density compact", document.documentElement.dataset.density === "compact");
    document.querySelector('#dens [data-d="comfortable"]').click();
    window.dispatchEvent(new Event("beforeprint"));
    ok("print header + TOC", document.querySelectorAll("#printhead li").length === DATA.length);
    window.dispatchEvent(new Event("afterprint"));

    // categories + odd quotes
    const listed = [].concat(...CATEGORIES.map(c => c[1]));
    ok("all sections categorised", DATA.every(d => listed.includes(d[0])));
    const odd = [...document.querySelectorAll(".cmd")].map(b => b.dataset.c).filter(c => (c.match(/"/g) || []).length % 2);
    ok("copy text intact", odd.length <= 1, JSON.stringify(odd));

    // 2026-10-22 restructure: migration of old names, symptom index, cross-links
    const mf = migrateFav("Wireless (C9800 + AP) :: RADIUS reachable?");
    ok("old favorite migrates (split + rename)", mf === "Wireless: client cannot connect :: RADIUS server reachability", mf);
    const ms = migrateFav("Syslog :: Is the server reachable?");
    ok("old favorite migrates (per-section rename)", ms === "Syslog :: Syslog server reachability", ms);
    ok("old section link migrates", migrateId("s-wireless-c9800-ap") === "s-wireless-controller-overview" && migrateId("s-dtp") === "s-vlans-trunks-dtp");
    const oldRow = "r-" + slug("Multicast (IGMP / PIM)") + "-" + hash("Multicast routing enabled?"), mr = migrateId(oldRow);
    ok("old row link migrates (split + rename)", !!document.getElementById(mr) && mr.startsWith("r-multicast-pim-routing-"), mr);
    const symLinks = document.querySelectorAll("#s-symptom-index a.xref");
    ok("symptom index cross-links resolve", symLinks.length > 60 && [...symLinks].every(a => document.getElementById(a.getAttribute("href").slice(1))), symLinks.length + " links");
    ok("'see <section>' notes become links", document.querySelectorAll("section:not(#s-symptom-index) a.xref").length >= 10, document.querySelectorAll("section:not(#s-symptom-index) a.xref").length + " links");
    ok("16 categories, Start here first with Symptom index", CATEGORIES.length === 16 && CATEGORIES[0][1][0] === "Symptom index");

    // 2026-10-22 backlog: print favorites / quick card, field checks, verified field
    const fr1 = ROWS.find(r => r.sec === "EtherChannel" && r.ios && r.nx), fr2 = ROWS.find(r => r.risky && r.ios.includes("<"));
    favs.add(fr1.sec + " :: " + fr1.p); favs.add(fr2.sec + " :: " + fr2.p); saveFavs();
    vars = { intf: "Gi9/9/9" }; saveVars();
    document.body.classList.add("print-card"); window.dispatchEvent(new Event("beforeprint"));
    const card = document.getElementById("card");
    ok("quick card built from favorites", card.querySelectorAll(".it").length === 2 && card.querySelectorAll("h3").length >= 1, card.querySelectorAll(".it").length + " items");
    ok("quick card keeps ⚠ and labels both columns", !!card.querySelector(".w") && card.querySelectorAll(".lb").length >= 2);
    ok("print shows placeholders, not variable values", !document.querySelector(".cmd .ph.set") && !card.textContent.includes("Gi9/9/9"));
    window.dispatchEvent(new Event("afterprint"));
    ok("print mode cleared after printing", !document.body.classList.contains("print-card") && card.innerHTML === "" && !!document.querySelector(".cmd .ph.set"));
    vars = {}; saveVars(); favs.clear(); saveFavs();
    const pv = parseVer("x:17.12.4/lab/2026-11; n:10.2(6)/docs/2026-10; bad");
    ok("verified field parses (6th row element)", pv.length === 2 && pv[1].rel === "10.2(6)" && pv[1].src === "docs");
    ok("field check validation", !!cleanVer({ col: "x", rel: "17.12.4", src: "prod", res: "works", date: "2026-10" }) && !cleanVer({ col: "x", rel: "host-01", src: "prod", res: "works", date: "2026-10" }));
    verif[fr1.sec + " :: " + fr1.p] = [cleanVer({ col: "n", rel: "10.2(6)", src: "prod", res: "differs", date: "2026-10", fix: "use detail" })]; saveVerif();
    ok("field check chip shown on the row", !!fr1.tr.querySelector(".ver.mine.differs"), (fr1.tr.querySelector(".ver.mine") || {}).textContent);
    verif = {}; saveVerif();
    ok("field check removed", !fr1.tr.querySelector(".ver.mine"));

    // 2026-10-22 new features: IPv4 calculator, checklist, show-command collection, related links, new sections
    const ipc = document.getElementById("ipc"), ipt = document.getElementById("ipt"), ipo = document.getElementById("ipo");
    ipc.value = "10.1.2.3/24"; ipt.value = "10.1.2.200"; ipcalc();
    ok("IPv4 calc: prefix", ipo.textContent.includes("10.1.2.0/24") && ipo.textContent.includes("0.0.0.255") && ipo.textContent.includes("254 hosts") && ipo.textContent.includes("inside"), ipo.textContent.slice(0, 90));
    ipc.value = "10.1.2.0 0.0.3.255"; ipt.value = "10.1.9.1"; ipcalc();
    ok("IPv4 calc: wildcard + outside", ipo.textContent.includes("10.1.0.0/22") && ipo.textContent.includes("wildcard") && ipo.textContent.includes("outside"));
    ipc.value = "10.0.0.1/31"; ipt.value = ""; ipcalc();
    ok("IPv4 calc: /31 point-to-point", ipo.textContent.includes("2 hosts") && !ipo.textContent.includes("Broadcast"));
    ipc.value = "300.1.1.1/24"; ipcalc();
    ok("IPv4 calc: invalid input explained", !!ipo.querySelector(".bad"));
    ipc.value = ""; ipcalc();
    const pre = document.getElementById("s-pre-post-change-checks");
    pre.querySelector(".chk-toggle").click();
    const box = pre.querySelector("tr[data-id] .chk"); box.checked = true; box.dispatchEvent(new Event("change", { bubbles: true }));
    const ctext = checklistText(pre);
    ok("checklist: tick + time + copy text", pre.classList.contains("checking") && /\[x\] \d\d:\d\d/.test(ctext) && ctext.includes("[ ]"), ctext.split("\n")[0]);
    pre.querySelector(".chk-reset").click(); pre.querySelector(".chk-toggle").click();
    ok("checklist: reset + off", !Object.keys(checks).length && !pre.classList.contains("checking"));
    let copied = "", copyLabel = "";
    copyText = (t, b, label) => { copied = t; copyLabel = label; };   // capture instead of touching the clipboard (last test block)
    collect([...document.querySelectorAll("#s-etherchannel tr[data-id]")], "EtherChannel");
    const lines = copied.split("\n");
    ok("show cmds: collection block", lines[0] === "terminal length 0" && lines.length > 3 && copyLabel.includes("skipped"), copyLabel);
    ok("show cmds: only show lines, no placeholders", lines.slice(1).every(l => l.startsWith("show ") && !/<[a-z]/i.test(l)));
    ok("related links under section titles", document.querySelectorAll("p.related a.xref").length > 40 && [...document.querySelectorAll("p.related a.xref")].every(a => document.getElementById(a.getAttribute("href").slice(1))));
    const sdw = migrateFav("SD-WAN (Catalyst / Viptela) :: BFD summary"), sdr = migrateFav("Reference: ports & protocols :: SD-WAN DTLS / TLS (controllers)");
    ok("SD-WAN split: old favorites migrate", sdw === "SD-WAN: data plane & app-aware routing :: BFD summary" && sdr === "Reference: ports & protocols :: SD-WAN control (DTLS)", sdw + " | " + sdr);
    ok("SD-WAN old section link migrates", migrateId("s-sd-wan-catalyst-viptela") === "s-sd-wan-control-plane-onboarding");
    ok("Voice (VOIP) category with 3 sections + symptom entries", CATEGORIES.some(c => c[0] === "Voice (VOIP)" && c[1].length === 3) &&
      ROWS.filter(r => r.sec === "Symptom index" && /audio|phone|SD-WAN|transport/i.test(r.p)).length >= 8);
    const rbs = META.filter(m => m && m.title.startsWith("Runbook:"));
    ok("runbooks: 15 sections, all checklists", rbs.length === 15 && rbs.every(m => document.querySelector("#" + m.sid + " .chk-toggle") && document.querySelector("#" + m.sid + " .chk")), rbs.length + " runbooks");
    ok("runbook steps carry commands of their source rows", ROWS.find(r => r.sec === "Runbook: find a MAC across switches" && r.p === "MAC → port + VLAN on this switch").ios === ROWS.find(r => r.sec === "Find a host (MAC / IP / port)" && r.p === "MAC location (port, VLAN)").ios);
    ok("audit renames migrate", migrateFav("Stack & StackWise Virtual :: TAC bundle") === "Stack & StackWise Virtual :: TAC bundle (StackWise Virtual)" && migrateFav("DHCP :: DHCP relay feature enabled?") === "DHCP :: DHCP relay feature state");
    ok("new sections categorised + placed", META.some(m => m && m.title === "Certificates & PKI") && CATEGORIES.find(c => c[0] === "Platform")[1].includes("Hardware resources (TCAM / SDM / FED)"));
  } catch (e) { out.push("ERROR " + e + " " + (e.stack || "")); }
  document.title = "DONE";
  document.body.insertAdjacentHTML("beforeend", '<pre id="out">' + btoa(unescape(encodeURIComponent(out.join("\n")))) + "</pre>");
})();
