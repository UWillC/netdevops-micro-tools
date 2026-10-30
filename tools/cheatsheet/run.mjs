#!/usr/bin/env node
// Cisco CLI Cheat Sheet tool runner (Node + headless Chrome / Chromium). Replaces
// Run-CheatSheetScript.ps1 / Splice-Data.ps1 / Merge-Verification.ps1 one to one (same
// contract), no npm packages.
//
//   node tools/cheatsheet/run.mjs run <script.js> [--out <file>]     inject a script, print / save its result
//   node tools/cheatsheet/run.mjs check                              uxtest = all PASS, audit = only the known FPs (exit 1 otherwise)
//   node tools/cheatsheet/run.mjs splice <newdata.js>                write a new DATA block into the page (snapshot first!)
//   node tools/cheatsheet/run.mjs merge-verif <export.json> [--apply --snapshot-dir <dir>]
//
// Options: --page <html> (default cheatsheet/Cisco_CLI_Cheat_Sheet.html), CHROME=<path to the browser binary>.
// How it works: copy of the page with the script before </body> -> chrome --headless=new --dump-dom ->
// last <pre id="out"> -> base64 -> UTF-8. The page itself is never modified, except by splice /
// merge-verif --apply. All network is off for the browser (host resolver maps every name to NOTFOUND).
// Field-check exports are untrusted input: merge-verif only writes "works" results; everything else
// is listed for review by hand (content rules, tools/cheatsheet/README.md).

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "..", "..");
const DEFAULT_PAGE = path.join(REPO, "cheatsheet", "Cisco_CLI_Cheat_Sheet.html");

// The 5 known audit false positives (test contract). The audit must report exactly these, nothing else
// (CMD-IN-n-SECTIONS and PLACEHOLDERS lines are informational).
export const KNOWN_AUDIT_FP = [
  "NO-WARN | CLI tips | Configure many ports at once |",
  "NO-WARN | Packet capture (EPC / Ethanalyzer) | EPC: remove capture |",
  "NO-WARN | Offline config analysis | Parse configs with a template |",
  "NO-WARN | Git, containers & CI | Run a tool container with the current folder |",
  'BAD-REF | Linux (RHEL family) | Isolated Python environment | "Python and Ansible"',
];
export const UXTEST_COUNT = 58;

function findChrome() {
  if (process.env.CHROME) return process.env.CHROME;
  const candidates = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/usr/bin/google-chrome", "/usr/bin/google-chrome-stable", "/usr/bin/chromium", "/usr/bin/chromium-browser",
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
  ];
  const hit = candidates.find(c => fs.existsSync(c));
  if (!hit) throw new Error("No Chrome / Chromium / Edge found. Set CHROME=<path to the browser binary>.");
  return hit;
}

export function runScript(scriptText, { page = DEFAULT_PAGE, waitMs = 15000 } = {}) {
  const src = fs.readFileSync(page, "utf8");
  const i = src.lastIndexOf("</body>");
  if (i < 0) throw new Error("No </body> in " + page);
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "cheatsheet-run-"));
  try {
    const test = path.join(work, "page.html");
    fs.writeFileSync(test, src.slice(0, i) + "<script>" + scriptText + "</script>" + src.slice(i), "utf8");
    const args = [
      "--headless=new", "--disable-gpu", "--window-size=1600,1000", "--user-data-dir=" + path.join(work, "profile"),
      "--no-first-run", "--no-default-browser-check", "--disable-extensions", "--disable-dev-shm-usage",
      "--host-resolver-rules=MAP * ~NOTFOUND",
      "--virtual-time-budget=" + waitMs, "--dump-dom", pathToFileURL(test).href,
    ];
    // GitHub's Ubuntu 24.04 runners block the Chrome sandbox (AppArmor userns); the page is our own file.
    if (process.env.CI === "true") args.unshift("--no-sandbox");
    const html = execFileSync(findChrome(), args, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, stdio: ["ignore", "pipe", "ignore"], timeout: 120000 });
    const title = (html.match(/<title>([^<]*)<\/title>/) || [, ""])[1];
    const all = [...html.matchAll(/<pre id="out">([\s\S]*?)<\/pre>/g)];
    if (!all.length) throw new Error(`No <pre id="out"> in the result (page title: '${title}'), the script failed before writing output.`);
    const b64 = all[all.length - 1][1].replace(/[^A-Za-z0-9+/=]/g, "");
    return { title, text: Buffer.from(b64, "base64").toString("utf8") };
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
}

export function checkUxtest(text) {
  const lines = text.split("\n").filter(Boolean);
  const pass = lines.filter(l => l.startsWith("PASS ")).length;
  const bad = lines.filter(l => !l.startsWith("PASS "));
  return { ok: pass === UXTEST_COUNT && bad.length === 0, pass, bad };
}

export function checkAudit(text) {
  const findings = text.split("\n").filter(Boolean).filter(l => !/^(CMD-IN-\d+-SECTIONS|PLACEHOLDERS) \|/.test(l));
  const unexpected = findings.filter(l => !KNOWN_AUDIT_FP.some(fp => l.startsWith(fp)));
  const missing = KNOWN_AUDIT_FP.filter(fp => !findings.some(l => l.startsWith(fp)));
  return { ok: unexpected.length === 0 && findings.length === KNOWN_AUDIT_FP.length, findings, unexpected, missing };
}

export function splice(pageFile, newData) {
  const src = fs.readFileSync(pageFile, "utf8");
  const nd = newData.split("/*REPORT*/")[0];
  const [dataPart, renamed] = nd.split("/*RENAMED*/");
  const data = dataPart.trimEnd();
  if (!data.startsWith("const DATA = [") || !data.endsWith("];")) throw new Error("NewData does not look like a DATA block");
  const b = src.indexOf("/*DATA-BEGIN*/"), e = src.indexOf("/*DATA-END*/");
  if (b < 0 || e < b) throw new Error("DATA markers not found in " + pageFile);
  let out = src.slice(0, b) + "/*DATA-BEGIN*/\n" + data + "\n" + src.slice(e);
  if (renamed !== undefined) {
    const re = /^const RENAMED = .*;$/m;
    if (!re.test(out)) throw new Error("RENAMED line not found");
    out = out.replace(re, () => "const RENAMED = " + renamed.trim() + ";");
  }
  fs.writeFileSync(pageFile, out, "utf8");
  return out.length;
}

function arg(argv, name) { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : undefined; }

function main(argv) {
  const [cmd, target] = argv;
  const page = path.resolve(arg(argv, "--page") || DEFAULT_PAGE);
  if (cmd === "run" && target) {
    const r = runScript(fs.readFileSync(target, "utf8"), { page });
    const outFile = arg(argv, "--out");
    if (outFile) { fs.writeFileSync(outFile, r.text, "utf8"); console.log(`Saved result to ${outFile} (${r.text.length} chars). Page title: ${r.title}`); }
    else { console.log("Page title: " + r.title); console.log(r.text); }
    return 0;
  }
  if (cmd === "check") {
    const ux = checkUxtest(runScript(fs.readFileSync(path.join(HERE, "uxtest.js"), "utf8"), { page }).text);
    console.log(`uxtest: ${ux.pass} PASS (expected ${UXTEST_COUNT}), ${ux.bad.length} other lines`);
    ux.bad.forEach(l => console.log("  " + l));
    const au = checkAudit(runScript(fs.readFileSync(path.join(HERE, "audit.js"), "utf8"), { page }).text);
    console.log(`audit: ${au.findings.length} findings (expected the ${KNOWN_AUDIT_FP.length} known false positives)`);
    au.unexpected.forEach(l => console.log("  UNEXPECTED " + l));
    au.missing.forEach(l => console.log("  MISSING    " + l + " (update KNOWN_AUDIT_FP if the row was fixed or renamed)"));
    return ux.ok && au.ok ? 0 : 1;
  }
  if (cmd === "splice" && target) {
    console.log(`Spliced DATA into ${page} (${splice(page, fs.readFileSync(target, "utf8"))} chars)`);
    return 0;
  }
  if (cmd === "merge-verif" && target) {
    const json = fs.readFileSync(target, "utf8");
    JSON.parse(json); // fail early on a broken file
    const r = runScript("const VERIF = " + json + ";\n" + fs.readFileSync(path.join(HERE, "merge-verif.js"), "utf8"), { page });
    if (r.text.startsWith("ERROR")) throw new Error(r.text);
    const [data, report] = r.text.split("\n/*REPORT*/\n");
    console.log(report);
    const work = fs.mkdtempSync(path.join(os.tmpdir(), "cheatsheet-merge-"));
    const dataFile = path.join(work, "merged-data.js");
    fs.writeFileSync(dataFile, data, "utf8");
    console.log("New DATA block saved to " + dataFile);
    if (argv.includes("--apply")) {
      const dir = arg(argv, "--snapshot-dir");
      if (!dir) throw new Error("--apply needs --snapshot-dir <dir> (outside the repo)");
      const stamp = new Date().toISOString().slice(0, 16).replace(/[-:]/g, "").replace("T", "_");
      const snap = path.join(dir, `Cisco_CLI_Cheat_Sheet_${stamp}_pre-verif-merge.html`);
      fs.copyFileSync(page, snap, fs.constants.COPYFILE_EXCL);
      splice(page, data);
      console.log(`Applied. Snapshot: ${snap}. Now run: node tools/cheatsheet/run.mjs check`);
    }
    return 0;
  }
  console.error("Usage: run.mjs run <script.js> [--out f] | check | splice <newdata.js> | merge-verif <export.json> [--apply --snapshot-dir d]  [--page p]");
  return 2;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { process.exitCode = main(process.argv.slice(2)); }
  catch (e) { console.error("ERROR " + (e && e.message || e)); process.exitCode = 1; }
}
