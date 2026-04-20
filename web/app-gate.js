// -----------------------------
// Gated Tools — Email Gate System
// Free tools: no email required
// Gated tools: one-time email → localStorage → permanent access
// -----------------------------

const GATE_EMAIL_KEY = "netdevops_email";
const GATE_UNLOCKED_KEY = "netdevops_unlocked";

// Tools that are FREE (no email required)
// Threat Feed is on home page, always visible
const FREE_TOOLS = ["home", "iperf", "subnet", "mtu", "timezone"];


// -----------------------------
// Check if user has unlocked gated tools
// -----------------------------
function isGateUnlocked() {
  return localStorage.getItem(GATE_UNLOCKED_KEY) === "true";
}

function isFreeTool(tabName) {
  return FREE_TOOLS.includes(tabName);
}

function shouldGate(tabName) {
  return !isFreeTool(tabName) && !isGateUnlocked();
}

// -----------------------------
// Unlock — save email + set flag
// -----------------------------
function unlockGate(email) {
  localStorage.setItem(GATE_EMAIL_KEY, email);
  localStorage.setItem(GATE_UNLOCKED_KEY, "true");

  // Remove all lock badges from sidebar and home grid
  document.querySelectorAll(".gate-lock").forEach(el => el.remove());

  // Hide the gate banner on home page
  const banner = document.getElementById("gate-notice");
  if (banner) banner.style.display = "none";

  // Show success toast
  if (typeof showToast === "function") {
    showToast("All tools unlocked! Happy automating.");
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
    return data.success !== false;
  } catch (err) {
    // Non-blocking — even if backend fails, unlock locally
    console.warn("Subscribe failed (non-blocking):", err);
    return true;
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
      <h2>Unlock 15 Pro Tools</h2>
      <p>Enter your email to get instant access to all config generators, security audits, and advanced network tools.</p>
      <form id="gate-email-form" class="gate-email-form">
        <input type="email" id="gate-email-input" placeholder="your@email.com" required autocomplete="email" />
        <button type="submit" class="btn-primary gate-submit-btn">Unlock All Tools</button>
      </form>
      <p class="gate-modal-note">One-time only. No spam. No account needed.</p>
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
        <strong>5 tools free. 15 pro tools — just enter your email.</strong>
        <span>One-time. No spam. No account needed.</span>
      </div>
      <button class="btn-primary gate-notice-btn" id="gate-notice-btn">Unlock Pro Tools</button>
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
    const email = localStorage.getItem(GATE_EMAIL_KEY) || "";
    footer.textContent = "All tools unlocked. Happy automating.";
  } else {
    footer.textContent = "5 free tools. Enter email to unlock all 20.";
  }
}

// -----------------------------
// Initialize gate system
// -----------------------------
function initGate() {
  addLockBadges();
  addGateBanner();
  updateHomeFooter();
}

// Run on DOM ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initGate);
} else {
  initGate();
}
