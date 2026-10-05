// -----------------------------
// Gated Tools - Email Gate System (public beta, BETA-A)
// Free tools: no email required
// Gated tools: one-time email → localStorage → permanent access
// -----------------------------

const GATE_EMAIL_KEY = "netdevops_email";
const GATE_UNLOCKED_KEY = "netdevops_unlocked";
// Public beta (BETA-A): signed tester token from /api/subscribe or the backfill
const GATE_TOKEN_KEY = "netdevops_beta_token";
const GATE_BACKFILL_KEY = "netdevops_beta_backfill_day";
const PRIVACY_URL = "https://netdevops.thebackroom.ai/legal/privacy.html";

// Tool paths that carry X-Beta-Token (mirror of api/beta.py TOOL_PREFIXES).
// Tools live at the root, not under /api. Page-load fetches are excluded.
const BETA_TOOL_PREFIXES = ["/generate/", "/analyze/", "/tools/", "/mitigate/", "/export/", "/profiles/", "/api/kev/"];
const BETA_PASSIVE_PATHS = ["/analyze/advisories", "/analyze/critical-feed", "/profiles/list"];
const BETA_DEV_API_ORIGIN = "http://127.0.0.1:8000";

// Tools that are FREE (no email required)
// Threat Feed is on home page, always visible. KEV Watch (KW-01) is free like it.
const FREE_TOOLS = ["home", "iperf", "subnet", "mtu", "timezone", "kev-watch"];


// -----------------------------
// Storage helpers (private windows can throw)
// -----------------------------
function gateGet(key) {
  try { return localStorage.getItem(key); } catch (e) { return null; }
}

function gateSet(key, value) {
  try { localStorage.setItem(key, value); } catch (e) { /* ignore */ }
}

// -----------------------------
// Beta token: only same-origin requests to tool paths get it.
// Never the feedback widget (AWS), never Google, never any other origin.
// -----------------------------
function betaTokenApplies(rawUrl, loc) {
  loc = loc || window.location;
  let u;
  try { u = new URL(rawUrl, loc.href); } catch (e) { return false; }
  if (u.origin === "null") return false;
  const allowed = [loc.origin];
  if (loc.protocol === "file:" || loc.hostname === "localhost" || loc.hostname === "127.0.0.1") {
    allowed.push(BETA_DEV_API_ORIGIN);  // local dev: page and API on different ports
  }
  if (!allowed.includes(u.origin)) return false;
  if (BETA_PASSIVE_PATHS.includes(u.pathname)) return false;
  return BETA_TOOL_PREFIXES.some(p => u.pathname.startsWith(p));
}

(function installBetaFetch() {
  if (typeof window === "undefined" || typeof window.fetch !== "function" || window.__betaFetchInstalled) return;
  window.__betaFetchInstalled = true;
  const nativeFetch = window.fetch.bind(window);
  window.fetch = function (input, init) {
    try {
      const token = gateGet(GATE_TOKEN_KEY);
      const isRequest = input && typeof input === "object" && "url" in input;
      const url = isRequest ? input.url : String(input);
      if (token && betaTokenApplies(url)) {
        const base = (init && init.headers) || (isRequest ? input.headers : undefined);
        const headers = new Headers(base);
        headers.set("X-Beta-Token", token);
        init = Object.assign({}, init || {}, { headers: headers });
      }
    } catch (e) { /* never break a tool call over the token */ }
    return nativeFetch(input, init);
  };
})();

// -----------------------------
// Check if user has unlocked gated tools
// -----------------------------
function isGateUnlocked() {
  return gateGet(GATE_UNLOCKED_KEY) === "true";
}

function isFreeTool(tabName) {
  return FREE_TOOLS.includes(tabName);
}

function shouldGate(tabName) {
  return !isFreeTool(tabName) && !isGateUnlocked();
}

// -----------------------------
// Unlock - save email + set flag
// -----------------------------
function unlockGate(email) {
  gateSet(GATE_EMAIL_KEY, email);
  gateSet(GATE_UNLOCKED_KEY, "true");

  // Remove all lock badges from sidebar and home grid
  document.querySelectorAll(".gate-lock").forEach(el => el.remove());

  // Hide the gate banner on home page
  const banner = document.getElementById("gate-notice");
  if (banner) banner.style.display = "none";

  // Show success toast
  if (typeof showToast === "function") {
    showToast("All tools unlocked. Thanks for testing. Tell us what broke.");
  }
}

// -----------------------------
// Submit email via backend → MailerLite
// API key stays server-side (never exposed to frontend)
// -----------------------------
async function submitEmail(email) {
  try {
    const baseUrl = (typeof API_BASE_URL !== "undefined") ? API_BASE_URL : "";
    const resp = await fetch(`${baseUrl}/api/subscribe`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: email })
    });
    const data = await resp.json();
    if (data && typeof data.token === "string" && data.token) {
      gateSet(GATE_TOKEN_KEY, data.token);
    }
    return data.success !== false;
  } catch (err) {
    // Non-blocking - even if backend fails, unlock locally
    console.warn("Subscribe failed (non-blocking):", err);
    return true;
  }
}

// -----------------------------
// Backfill: unlocked before tokens existed -> ask once a day, silently.
// Read-only on the server: it never subscribes anyone.
// -----------------------------
async function backfillBetaToken() {
  if (!isGateUnlocked() || gateGet(GATE_TOKEN_KEY)) return;
  const email = gateGet(GATE_EMAIL_KEY);
  if (!email) return;
  const today = new Date().toISOString().slice(0, 10);
  if (gateGet(GATE_BACKFILL_KEY) === today) return;
  gateSet(GATE_BACKFILL_KEY, today);
  try {
    const baseUrl = (typeof API_BASE_URL !== "undefined") ? API_BASE_URL : "";
    const resp = await fetch(`${baseUrl}/api/beta/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: email })
    });
    if (!resp.ok) return;
    const data = await resp.json();
    if (data && typeof data.token === "string" && data.token) {
      gateSet(GATE_TOKEN_KEY, data.token);
    }
  } catch (err) {
    /* silent: the tools work without a token */
  }
}

// -----------------------------
// Gate Modal
// -----------------------------
function showGateModal(targetTab) {
  const existing = document.getElementById("gate-modal-overlay");
  if (existing) existing.remove();

  const overlay = document.createElement("div");
  overlay.id = "gate-modal-overlay";
  overlay.className = "gate-modal-overlay";

  overlay.innerHTML = `
    <div class="gate-modal">
      <button class="gate-modal-close" id="gate-modal-close" title="Close">&times;</button>
      <div class="gate-modal-icon">🔓</div>
      <h2>Join the public beta</h2>
      <p>Every tool is free while we test them on real networks. Enter your email to unlock the 15 tools behind this gate.</p>
      <form id="gate-email-form" class="gate-email-form">
        <input type="email" id="gate-email-input" placeholder="your@email.com" required autocomplete="email" />
        <button type="submit" class="btn-primary gate-submit-btn">Unlock all tools</button>
      </form>
      <p class="gate-modal-note">We will email you about the beta (unsubscribe in any email) and use your address to recognise you as a tester. Run at least one tool, confirm your email when the beta ends, and every beta tool stays free for you after it. No account, no card. <a href="${PRIVACY_URL}" target="_blank" rel="noopener">Privacy policy</a></p>
    </div>
  `;

  document.body.appendChild(overlay);

  // Focus email input
  setTimeout(() => {
    const input = document.getElementById("gate-email-input");
    if (input) input.focus();
  }, 100);

  // Close button
  document.getElementById("gate-modal-close").addEventListener("click", () => {
    overlay.remove();
  });

  // Close on overlay click (outside modal)
  overlay.addEventListener("click", (e) => {
    if (e.target === overlay) overlay.remove();
  });

  // Close on Escape
  const escHandler = (e) => {
    if (e.key === "Escape") {
      overlay.remove();
      document.removeEventListener("keydown", escHandler);
    }
  };
  document.addEventListener("keydown", escHandler);

  // Form submit
  document.getElementById("gate-email-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const email = document.getElementById("gate-email-input").value.trim();
    if (!email) return;

    const btn = overlay.querySelector(".gate-submit-btn");
    btn.textContent = "Unlocking...";
    btn.disabled = true;

    // Submit to backend → MailerLite (non-blocking)
    await submitEmail(email);

    // Unlock locally
    unlockGate(email);

    // Remove modal
    overlay.remove();

    // Navigate to the tool they wanted
    if (targetTab) {
      const tabBtn = document.querySelector(`.tab-button[data-tab="${targetTab}"]`);
      if (tabBtn) tabBtn.click();
    }
  });
}

// -----------------------------
// Add lock badges to gated tools
// -----------------------------
function addLockBadges() {
  if (isGateUnlocked()) return;

  // Sidebar tab buttons
  document.querySelectorAll(".tab-button").forEach(btn => {
    const tab = btn.dataset.tab;
    if (!isFreeTool(tab) && !btn.querySelector(".gate-lock")) {
      const lock = document.createElement("span");
      lock.className = "gate-lock";
      lock.textContent = "🔒";
      lock.title = "Enter email to unlock";
      btn.appendChild(lock);
    }
  });

  // Home tool cards
  document.querySelectorAll(".home-tool-card").forEach(card => {
    const tab = card.dataset.tab;
    if (!isFreeTool(tab) && !card.querySelector(".gate-lock")) {
      const lock = document.createElement("span");
      lock.className = "gate-lock";
      lock.textContent = "🔒";
      lock.title = "Enter email to unlock";
      card.appendChild(lock);
    }
  });
}

// -----------------------------
// Home page gate banner
// -----------------------------
function addGateBanner() {
  if (isGateUnlocked()) return;

  const homeFooter = document.querySelector(".home-footer");
  if (!homeFooter) return;

  const banner = document.createElement("div");
  banner.id = "gate-notice";
  banner.className = "gate-notice";
  banner.innerHTML = `
    <div class="gate-notice-content">
      <span class="gate-notice-icon">🔓</span>
      <div class="gate-notice-text">
        <strong>Public beta: every tool is free.</strong>
        <span>6 tools are open now. Enter your email to unlock the other 15.</span>
      </div>
      <button class="btn-primary gate-notice-btn" id="gate-notice-btn">Unlock beta tools</button>
    </div>
  `;

  // Insert before the footer text
  homeFooter.parentNode.insertBefore(banner, homeFooter);

  document.getElementById("gate-notice-btn").addEventListener("click", () => {
    showGateModal(null);
  });
}

// -----------------------------
// Update home footer text
// -----------------------------
function updateHomeFooter() {
  const footer = document.querySelector(".home-footer p");
  if (!footer) return;

  if (isGateUnlocked()) {
    footer.textContent = "All tools unlocked. Thanks for testing.";
  } else {
    footer.textContent = "Public beta. 6 tools open, 15 more with your email.";
  }
}

// -----------------------------
// Initialize gate system
// -----------------------------
function initGate() {
  addLockBadges();
  addGateBanner();
  updateHomeFooter();
  backfillBetaToken();
}

// Run on DOM ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initGate);
} else {
  initGate();
}
