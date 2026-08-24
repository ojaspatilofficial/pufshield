"use strict";

/* ============================================================
   PUFShield Public Site + Demo + Login
   ============================================================ */

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

/* ---------- Navbar ---------- */

(function initNavbar() {
  const navbar = $("#navbar");
  if (!navbar) return;
  let lastScroll = 0;
  window.addEventListener("scroll", () => {
    const y = window.scrollY;
    navbar.classList.toggle("scrolled", y > 20);
    lastScroll = y;
  }, { passive: true });

  const toggle = $("#nav-toggle");
  const links = $("#nav-links");
  if (toggle && links) {
    toggle.addEventListener("click", () => links.classList.toggle("open"));
    $$("a", links).forEach((a) => a.addEventListener("click", () => links.classList.remove("open")));
  }
})();

/* ---------- Scroll animations ---------- */

(function initScrollAnimations() {
  const els = $$(".animate-on-scroll");
  if (!els.length) return;
  const obs = new IntersectionObserver((entries) => {
    entries.forEach((e) => { if (e.isIntersecting) { e.target.classList.add("visible"); obs.unobserve(e.target); } });
  }, { threshold: 0.1 });
  els.forEach((el) => obs.observe(el));
})();

/* ---------- API helper ---------- */

async function api(path, options = {}) {
  const res = await fetch(path, { headers: { "Content-Type": "application/json" }, ...options });
  let data = {};
  try { data = await res.json(); } catch { data = {}; }
  if (!res.ok) {
    const msg = typeof data.detail === "string" ? data.detail : `Request failed (${res.status})`;
    throw new Error(msg);
  }
  return data;
}

function esc(v) {
  return String(v ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

/* ============================================================
   LOGIN PAGE
   ============================================================ */

(function initLogin() {
  const form = $("#login-form");
  if (!form) return;
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = $("#login-btn");
    const errBox = $("#login-error");
    btn.textContent = "Signing in\u2026";
    btn.disabled = true;
    errBox.style.display = "none";
    try {
      const fd = new FormData(form);
      const res = await fetch("/api/auth/login", { method: "POST", body: fd });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Login failed");
      const params = new URLSearchParams(window.location.search);
      const redirect = params.get("redirect") || "/dashboard";
      window.location.href = redirect;
    } catch (err) {
      errBox.textContent = err.message;
      errBox.style.display = "block";
    } finally {
      btn.textContent = "Sign In";
      btn.disabled = false;
    }
  });
})();

/* ============================================================
   REGISTER PAGE
   ============================================================ */

(function initRegister() {
  const form = $("#register-form");
  if (!form) return;
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = $("#register-btn");
    const errBox = $("#register-error");
    btn.textContent = "Creating account\u2026";
    btn.disabled = true;
    errBox.style.display = "none";
    try {
      const fd = new FormData(form);
      const res = await fetch("/api/auth/register", { method: "POST", body: fd });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Registration failed");
      window.location.href = "/dashboard";
    } catch (err) {
      errBox.textContent = err.message;
      errBox.style.display = "block";
    } finally {
      btn.textContent = "Create Account";
      btn.disabled = false;
    }
  });
})();

/* ============================================================
   AUTH-AWARE OPEN CONSOLE BUTTON
   ============================================================ */

(async function initAuthButton() {
  const btn = $("#open-console-btn");
  if (!btn) return;
  try {
    const res = await fetch("/api/auth/status");
    const data = await res.json();
    if (data.authenticated) {
      btn.href = "/dashboard";
      btn.textContent = "Open Console";
    }
  } catch {
    // Keep default login redirect
  }
})();

/* ============================================================
   INTERACTIVE DEMO PAGE
   ============================================================ */

const DEMO_STAGES = [
  { id: "demo-stage-init", label: "Initializing Device" },
  { id: "demo-stage-puf", label: "Reading SRAM PUF" },
  { id: "demo-stage-identity", label: "Recovering Identity" },
  { id: "demo-stage-cert", label: "Verifying Certificate" },
  { id: "demo-stage-challenge", label: "Challenge-Response" },
  { id: "demo-stage-hash", label: "Firmware Hash" },
  { id: "demo-stage-sig", label: "Signature Verification" },
  { id: "demo-stage-pqc", label: "PQC Verification" },
  { id: "demo-stage-tl", label: "Transparency Check" },
  { id: "demo-stage-ai", label: "AI Anomaly Detection" },
  { id: "demo-stage-risk", label: "Risk Assessment" },
  { id: "demo-stage-decision", label: "Boot Decision" },
];

const STAGE_MAP = {
  "demo-stage-puf": "puf_recovery",
  "demo-stage-identity": "puf_pki_binding",
  "demo-stage-cert": "certificate_verification",
  "demo-stage-challenge": "challenge_response",
  "demo-stage-hash": "firmware_hash",
  "demo-stage-sig": "firmware_signature",
  "demo-stage-pqc": "pqc_verification",
  "demo-stage-tl": "transparency_check",
  "demo-stage-ai": "anomaly_detection",
  "demo-stage-risk": "risk_assessment",
};

function setDemoStage(id, state, detail) {
  const el = document.getElementById(id);
  if (!el) return;
  el.classList.remove("pending", "active", "pass", "fail");
  el.classList.add(state);
  const detailEl = el.querySelector(".demo-stage-detail");
  if (detailEl && detail) detailEl.textContent = detail;
}

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

async function runPublicDemo() {
  const btn = $("#demo-run-btn");
  if (!btn) return;
  btn.disabled = true;
  btn.textContent = "Running…";

  const deviceId = ($("#demo-device-input") || {}).value || "demo-device";
  const pipeline = $("#demo-pipeline");
  const resultBox = $("#demo-result");
  const deviceInfo = $("#demo-device-info");

  if (resultBox) resultBox.style.display = "none";

  // Reset all stages
  for (const s of DEMO_STAGES) setDemoStage(s.id, "pending", "waiting");

  // Ensure device exists
  try {
    await api("/api/devices", { method: "POST", body: JSON.stringify({ device_id: deviceId, bit_size: 256 }) });
  } catch { /* already exists */ }

  // Ensure firmware exists
  try {
    await api("/api/firmware", { method: "POST", body: JSON.stringify({ version: "1.0.0", device_id: deviceId }) });
  } catch { /* already exists */ }

  // Record firmware in transparency log
  try {
    const fw = await api("/api/firmware");
    const devFw = fw.find((f) => f.device_id === deviceId && f.bundle?.payload_sha256);
    if (devFw) {
      await api("/api/transparency/record", {
        method: "POST",
        body: JSON.stringify({
          firmware_id: `fw-${devFw.version}`, version: devFw.version,
          device_id: deviceId, payload_sha256: devFw.bundle.payload_sha256,
        }),
      });
    }
  } catch { /* ok */ }

  // Set min version
  try {
    await api(`/api/devices/${encodeURIComponent(deviceId)}/minimum-version`, {
      method: "PUT", body: JSON.stringify({ version: "1.0.0" }),
    });
  } catch { /* ok */ }

  // Run through stages with animation
  for (const s of DEMO_STAGES) {
    setDemoStage(s.id, "active", "verifying…");
    await sleep(350);
  }

  // Actually run the boot
  let bootData;
  try {
    bootData = await api("/api/boot", {
      method: "POST", body: JSON.stringify({ device_id: deviceId }),
    });
  } catch (err) {
    for (const s of DEMO_STAGES) setDemoStage(s.id, "fail", "error");
    if (resultBox) {
      resultBox.style.display = "";
      resultBox.className = "demo-result blocked";
      resultBox.innerHTML = `<div class="demo-result-icon">✕</div><div class="demo-result-title">System Error</div><div class="demo-result-desc">${esc(err.message)}</div>`;
    }
    btn.disabled = false;
    btn.textContent = "Run Security Demo";
    return;
  }

  const stages = bootData.stages || {};
  const allowed = bootData.decision === "BOOT_ALLOWED";

  // Update init + puf stages
  setDemoStage("demo-stage-init", "pass", "power rails nominal");
  await sleep(200);

  // Map backend stages to demo stages
  for (const s of DEMO_STAGES) {
    const backendKey = STAGE_MAP[s.id];
    if (!backendKey) {
      if (s.id === "demo-stage-init") continue;
      if (s.id === "demo-stage-decision") {
        setDemoStage(s.id, allowed ? "pass" : "fail", allowed ? "BOOT ALLOWED" : "BOOT BLOCKED");
      }
      continue;
    }
    const stage = stages[backendKey];
    if (stage) {
      const pass = Boolean(stage.passed);
      let detail = pass ? "verified" : "failed";
      const d = stage.details || {};
      if (d.bit_error_rate != null) detail = `BER ${(d.bit_error_rate * 100).toFixed(1)}%`;
      if (d.hash_valid != null) detail = d.hash_valid ? "SHA-256 match" : "SHA-256 mismatch";
      if (d.signature_valid != null) detail = d.signature_valid ? "signatures valid" : "signature invalid";
      if (d.certificate_valid != null) detail = d.certificate_valid ? "chain trusted" : "chain invalid";
      if (d.auth_signature_valid != null) detail = d.auth_signature_valid ? "challenge verified" : "challenge failed";
      if (d.version_allowed != null) detail = d.version_allowed ? `v${d.image_version} allowed` : `v${d.image_version} blocked`;
      if (d.puf_binding_match != null) detail = d.puf_binding_match ? "identity verified" : "identity broken";
      if (d.pqc_key_registered !== undefined) detail = d.pqc_key_registered ? "ML-DSA-65 verified" : "no PQC key";
      setDemoStage(s.id, pass ? "pass" : "fail", detail);
    } else {
      setDemoStage(s.id, "fail", "not reached");
    }
    await sleep(150);
  }

  // Update device info
  if (deviceInfo) {
    deviceInfo.innerHTML = `
      <span style="font-family:var(--mono);font-size:13px;color:var(--text);">Device: ${esc(deviceId)}</span>
      <span style="font-family:var(--mono);font-size:13px;color:var(--text-muted);margin-left:12px;">Stages: ${bootData.passed_stages || 0}/${bootData.total_stages || 0} passed</span>
    `;
  }

  // Show result
  await sleep(300);
  if (resultBox) {
    resultBox.style.display = "";
    if (allowed) {
      resultBox.className = "demo-result allowed";
      resultBox.innerHTML = `
        <div class="demo-result-icon">✓</div>
        <div class="demo-result-title">SECURE BOOT ALLOWED</div>
        <div class="demo-result-desc">${esc(bootData.message || "All security checks passed.")}</div>
        <div style="margin-top:12px;font-family:var(--mono);font-size:12px;color:var(--text-muted);">
          Device: ${esc(deviceId)} · Decision: ${esc(bootData.decision)} · Status: ${esc(bootData.status)}
        </div>`;
    } else {
      resultBox.className = "demo-result blocked";
      resultBox.innerHTML = `
        <div class="demo-result-icon">✕</div>
        <div class="demo-result-title">SECURE BOOT BLOCKED</div>
        <div class="demo-result-desc">${esc(bootData.message || "A security check failed.")}</div>
        <div style="margin-top:12px;font-family:var(--mono);font-size:12px;color:var(--text-muted);">
          Device: ${esc(deviceId)} · Decision: ${esc(bootData.decision)} · Status: ${esc(bootData.status)}
        </div>`;
    }
  }

  btn.disabled = false;
  btn.textContent = "Run Security Demo";
}

/* ============================================================
   ATTACK SIMULATION (Demo page)
   ============================================================ */

const ATTACK_MAP = {
  clone_device: { name: "Device Clone", desc: "Attempt to replicate a device's PUF identity" },
  tamper_firmware: { name: "Firmware Tampering", desc: "Modify firmware payload to bypass integrity checks" },
  replay_challenge: { name: "Replay Attack", desc: "Reuse a captured authentication challenge" },
  firmware_rollback: { name: "Firmware Rollback", desc: "Downgrade to an older, vulnerable firmware version" },
  certificate_forgery: { name: "Certificate Forgery", desc: "Present an invalid certificate chain" },
  wrong_signer: { name: "Wrong Signer", desc: "Sign firmware with an unauthorized key" },
};

async function runAttackDemo(attackName) {
  const resultBox = $("#demo-attack-result");
  const deviceId = ($("#demo-device-input") || {}).value || "demo-device";

  if (resultBox) {
    resultBox.style.display = "";
    resultBox.className = "demo-result";
    resultBox.innerHTML = `<div style="text-align:center;padding:24px;color:var(--text-muted);">Executing attack simulation…</div>`;
  }

  // Ensure device and firmware exist
  try { await api("/api/devices", { method: "POST", body: JSON.stringify({ device_id: deviceId, bit_size: 256 }) }); } catch {}
  try { await api("/api/firmware", { method: "POST", body: JSON.stringify({ version: "1.0.0", device_id: deviceId }) }); } catch {}
  try {
    const fw = await api("/api/firmware");
    const devFw = fw.find((f) => f.device_id === deviceId && f.bundle?.payload_sha256);
    if (devFw) await api("/api/transparency/record", { method: "POST", body: JSON.stringify({ firmware_id: `fw-${devFw.version}`, version: devFw.version, device_id: deviceId, payload_sha256: devFw.bundle.payload_sha256 }) });
  } catch {}

  let data;
  try {
    const body = { device_id: deviceId };
    if (attackName === "firmware_rollback") body.firmware_version = "1.0.0";
    data = await api(`/api/attacks/${attackName}`, { method: "POST", body: JSON.stringify(body) });
  } catch (err) {
    if (resultBox) {
      resultBox.className = "demo-result blocked";
      resultBox.innerHTML = `<div class="demo-result-icon">✕</div><div class="demo-result-title">System Error</div><div class="demo-result-desc">${esc(err.message)}</div>`;
    }
    return;
  }

  const blocked = data.decision === "BOOT_BLOCKED";
  const attackInfo = ATTACK_MAP[attackName] || { name: attackName, desc: "" };

  if (resultBox) {
    resultBox.className = "demo-result " + (blocked ? "allowed" : "blocked");
    resultBox.innerHTML = `
      <div class="demo-result-icon">${blocked ? "✓" : "✕"}</div>
      <div class="demo-result-title">${blocked ? "ATTACK DETECTED — SECURITY TEST PASSED" : "ATTACK NOT DETECTED"}</div>
      <div class="demo-result-desc" style="margin-bottom:8px;">
        <strong style="color:var(--red);">Attack:</strong> ${esc(attackInfo.name)} — ${esc(attackInfo.desc)}
      </div>
      <div class="demo-result-desc">
        <strong style="color:var(--green);">Detection:</strong> ${data.detection_point ? esc(data.detection_point.replace(/_/g, " ")) : "Not detected at any stage"}<br>
        <strong>Result:</strong> ${esc(data.decision)} — ${esc(data.status)}<br>
        <strong>Reason:</strong> ${esc(data.reason || data.message || "—")}
      </div>
      <div style="margin-top:12px;font-family:var(--mono);font-size:12px;color:var(--text-muted);">
        ${blocked ? "The security system successfully identified and blocked the attack. This is expected behavior." : "The attack was not detected. This may indicate a gap in the security pipeline."}
      </div>`;
  }
}

/* ============================================================
   INIT
   ============================================================ */

(function initDemoPage() {
  const demoBtn = $("#demo-run-btn");
  if (demoBtn) demoBtn.addEventListener("click", runPublicDemo);

  $$(".demo-attack-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const attack = btn.dataset.attack;
      if (attack) runAttackDemo(attack);
    });
  });
})();
