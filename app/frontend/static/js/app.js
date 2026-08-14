"use strict";

/* ============================================================
   PUFShield Secure Boot Console - frontend logic
   All data is fetched live from the FastAPI backend; there is
   no mock or fake data anywhere in this file.
   ============================================================ */

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

/* ---------- API client ---------- */

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  let data = {};
  try {
    data = await res.json();
  } catch {
    data = {};
  }
  if (!res.ok) {
    const msg = typeof data.detail === "string" ? data.detail : `Request failed (${res.status})`;
    throw new Error(msg);
  }
  return data;
}

/* ---------- helpers ---------- */

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function fmtTime(value) {
  if (!value) return "—";
  const t = String(value).includes("T") ? new Date(value) : new Date(String(value).replace(" ", "T") + "Z");
  if (Number.isNaN(t.getTime())) return String(value);
  return t.toLocaleString(undefined, {
    year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

function shortHash(hash, n = 10) {
  return hash ? `${hash.slice(0, n)}…` : "—";
}

function severityClass(severity) {
  return `badge-sev-${String(severity || "info").toLowerCase()}`;
}

function bootStatusBadge(status) {
  const ok = ["success", "auth_success", "BOOT_ALLOWED", "allowed"];
  const bad = ["auth_failed", "BOOT_BLOCKED"];
  let kind = "badge-warn";
  if (ok.includes(status)) kind = "badge-ok";
  else if (bad.includes(status)) kind = "badge-err";
  return `<span class="badge ${kind}">${esc(status)}</span>`;
}

function boolBadge(value, trueLabel = "yes", falseLabel = "no") {
  return value
    ? `<span class="badge badge-ok">${esc(trueLabel)}</span>`
    : `<span class="badge badge-err">${esc(falseLabel)}</span>`;
}

function toast(message, kind = "info", ms = 3800) {
  const box = $("#toasts");
  const t = document.createElement("div");
  t.className = `toast ${kind === "info" ? "" : kind}`;
  t.textContent = message;
  box.appendChild(t);
  setTimeout(() => t.remove(), ms);
}

function setBusy(btn, busy, text) {
  if (!btn) return;
  if (busy) {
    btn.dataset.orig = btn.textContent;
    btn.textContent = text || "Working…";
    btn.disabled = true;
  } else {
    btn.textContent = btn.dataset.orig || btn.textContent;
    btn.disabled = false;
  }
}

/* ---------- SVG charts (real backend data) ---------- */

function hbarChart(el, items) {
  if (!items.length) {
    el.innerHTML = '<div class="empty">No data yet.</div>';
    return;
  }
  const max = Math.max(...items.map((i) => i.value), 1);
  el.innerHTML = `<div class="hbars">${items.map((i) => `
    <div class="hbar">
      <div class="hbar-label" title="${esc(i.label)}">${esc(i.label)}</div>
      <div class="bar ${i.kind || ""}"><span style="width:${(i.value / max) * 100}%"></span></div>
      <div class="hbar-val">${esc(i.fmt ? i.fmt(i.value) : i.value)}</div>
    </div>`).join("")}</div>`;
}

/* ---------- navigation ---------- */

const VIEWS = {
  dashboard: { title: "Dashboard", refresh: refreshDashboard },
  devices: { title: "Devices", refresh: refreshDevices },
  puf: { title: "SRAM PUF Analysis", refresh: refreshPuf },
  pki: { title: "PKI / Certificates", refresh: refreshPki },
  firmware: { title: "Firmware", refresh: refreshFirmware },
  boot: { title: "Secure Boot", refresh: refreshBoot },
  attacks: { title: "Attack Center", refresh: refreshAttacks },
  logs: { title: "Security Logs", refresh: refreshLogs },
};

let currentView = "dashboard";

function safe(fn) {
  Promise.resolve().then(fn).catch((err) => {
    toast(err.message || "Request failed", "err");
  });
}

function navigate(view, push = true) {
  if (!VIEWS[view]) return;
  currentView = view;
  $$(".view").forEach((el) => el.classList.toggle("active", el.id === `view-${view}`));
  $$(".nav-item").forEach((el) => el.classList.toggle("active", el.dataset.view === view));
  $("#page-title").textContent = VIEWS[view].title;
  closeSidebar();
  safe(() => VIEWS[view].refresh());
  if (push && location.hash !== `#${view}`) history.replaceState(null, "", `#${view}`);
}

$$(".nav-item").forEach((el) => el.addEventListener("click", () => navigate(el.dataset.view)));
$$("[data-nav]").forEach((el) => el.addEventListener("click", (e) => {
  e.preventDefault();
  navigate(el.dataset.nav);
}));

function closeSidebar() {
  $("#sidebar").classList.remove("open");
  $("#backdrop").classList.remove("show");
}
$("#hamburger").addEventListener("click", () => {
  $("#sidebar").classList.add("open");
  $("#backdrop").classList.add("show");
});
$("#backdrop").addEventListener("click", closeSidebar);
$("#refresh-all").addEventListener("click", () => {
  safe(() => VIEWS[currentView].refresh());
  updateBackendStatus();
  toast("Refreshed from backend", "ok");
});

/* ---------- backend status + clock ---------- */

async function updateBackendStatus() {
  try {
    const data = await api("/api/health");
    $("#backend-dot").classList.toggle("online", data.status === "ok");
    $("#backend-status").textContent = `${data.service} · ${data.status}`;
  } catch {
    $("#backend-dot").classList.remove("online");
    $("#backend-status").textContent = "offline";
  }
}

function tickClock() {
  $("#clock").textContent = new Date().toLocaleTimeString();
}
setInterval(tickClock, 1000);
setInterval(updateBackendStatus, 5000);

/* ============================================================
   DASHBOARD
   ============================================================ */

async function refreshDashboard() {
  const stats = await api("/api/dashboard/stats");
  const events = await api("/api/security/events?limit=8");

  const boots = stats.boots || {};
  const attacks = stats.attacks || {};
  const puf = stats.puf || {};
  const rel = puf.mean_reliability;

  const statCards = [
    ["", "Registered Devices", stats.devices?.total ?? 0, "devices enrolled in the PUF fleet"],
    ["ok", "Successful Boots", boots.allowed ?? 0, `${boots.total ?? 0} total boot attempts`],
    ["err", "Blocked Boots", boots.blocked ?? 0, boots.total ? `${Math.round(((boots.blocked ?? 0) / boots.total) * 100)}% of attempts blocked` : "no attempts yet"],
    ["err", "Attacks Detected", attacks.total ?? 0, attacks.blocked_rate == null ? "no attacks simulated" : `${Math.round(attacks.blocked_rate * 100)}% caught by defences`],
    ["accent", "Firmware Versions", stats.firmware?.total_images ?? 0, `${stats.firmware?.devices_with_firmware ?? 0} devices have firmware`],
    ["purple", "Avg PUF Reliability", rel == null ? "—" : (rel * 100).toFixed(2) + "%", "fleet-wide mean"],
  ];
  $("#dash-stats").innerHTML = statCards.map(([tone, text, value, sub]) => `
    <div class="stat-card ${tone}">
      <div class="stat-label">${text}</div>
      <div class="stat-value">${esc(value)}</div>
      <div class="stat-sub">${esc(sub)}</div>
    </div>`).join("");

  const timeline = $("#dash-events");
  if (!events.length) {
    timeline.innerHTML = '<div class="empty">No security events recorded yet.</div>';
  } else {
    timeline.innerHTML = events.map((e) => `
      <div class="timeline-item ${severityClass(e.severity)}">
        <div class="timeline-top">
          <span class="badge badge-neutral">${esc(e.event_type)}</span>
          <span class="timeline-title">${esc(e.device_id)}</span>
          <span class="badge ${severityClass(e.severity)}">${esc(e.severity)}</span>
          <span class="timeline-time">${esc(fmtTime(e.timestamp))}</span>
        </div>
        <div class="timeline-summary">${esc(e.summary || e.result || "")}</div>
      </div>`).join("");
  }
}

setInterval(() => { if (currentView === "dashboard") safe(refreshDashboard); }, 10000);

/* ============================================================
   LIVE SECURE BOOT PIPELINE (dashboard)
   Every stage below maps to a real stage of the backend boot
   engine (app/secureboot/verify.py) and displays its real
   verification outcome and details.
   ============================================================ */

const PIPELINE = [
  { key: "power", label: "POWER ON", stage: null, detail: () => "" },
  { key: "puf", label: "PUF", stage: "puf_recovery",
    detail: (d) => `response ${d.puf_match ? "matches" : "mismatch"} enrollment · Hamming distance ${d.hamming_distance ?? "—"}` },
  { key: "puf_recovery", label: "PUF Recovery", stage: "puf_recovery",
    detail: (d) => `fuzzy secret ${d.fuzzy_recovered ? "recovered" : "failed"} · BER ${d.bit_error_rate != null ? (d.bit_error_rate * 100).toFixed(2) + "%" : "—"} · reliability ${d.reliability != null ? (d.reliability * 100).toFixed(2) + "%" : "—"}` },
  { key: "identity", label: "Device Identity", stage: "puf_pki_binding",
    detail: (d) => `key binding ${d.puf_binding_match ? "holds — identity verified" : "broken — key copied to different hardware"}` },
  { key: "pki", label: "PKI", stage: "certificate_verification",
    detail: (d) => `chain ${d.certificate_valid ? "trusted" : "invalid"} · serial ${d.certificate_serial != null ? String(d.certificate_serial).slice(-8) : "—"}` },
  { key: "challenge", label: "Challenge", stage: "challenge_response",
    detail: (d) => `signature ${d.auth_signature_valid ? "valid" : "invalid"} · challenge ${d.challenge_verified ? "fresh" : "missing / replayed"}` },
  { key: "hash", label: "Firmware Hash", stage: "firmware_hash",
    detail: (d) => `sha-256 ${d.hash_valid ? "match" : "mismatch"}` },
  { key: "signature", label: "Signature", stage: "firmware_signature",
    detail: (d) => `device ${d.signature_valid ? "ok" : "bad"} · manufacturer ${d.manufacturer_signature_valid ? "ok" : "bad"}` },
  { key: "rollback", label: "Anti-Rollback", stage: "anti_rollback",
    detail: (d) => `v${d.image_version ?? "?"} ${d.version_allowed ? "≥" : "<"} floor ${d.minimum_version || "none"}` },
  { key: "boot", label: "BOOT", stage: null, detail: () => "" },
];

function sleep(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }

function buildPipeline() {
  $("#boot-pipeline").innerHTML = PIPELINE.map((node) => `
    <div class="pnode pending" id="pnode-${node.key}">
      <div class="rail"><span class="pnode-dot"></span><span class="rail-line"></span></div>
      <div class="pnode-body">
        <div class="pnode-name">${esc(node.label)}</div>
        <div class="pnode-detail">waiting</div>
      </div>
    </div>`).join("");
}

function setNode(key, state, detail) {
  const el = $(`#pnode-${key}`);
  if (!el) return;
  el.classList.remove("pending", "active", "pass", "fail", "skipped");
  el.classList.add(state);
  if (detail) $(".pnode-detail", el).textContent = detail;
}

async function runLiveBoot() {
  const deviceId = $("#pipe-device").value.trim();
  if (!deviceId) {
    toast("Enter a device ID to run a boot", "warn");
    return;
  }
  const version = $("#pipe-version").value.trim();
  const btn = $("#pipe-run");
  setBusy(btn, true, "Booting…");
  $("#pipe-message").innerHTML = "Running boot verification against the backend…";
  buildPipeline();

  const body = { device_id: deviceId };
  if (version) body.firmware_version = version;

  let data;
  try {
    data = await api("/api/boot", { method: "POST", body: JSON.stringify(body) });
  } catch (err) {
    $("#pipe-message").textContent = `Boot failed: ${err.message}`;
    setNode("power", "fail", "boot could not start");
    for (const node of PIPELINE) {
      if (node.key !== "power") setNode(node.key, "skipped", "boot could not start");
    }
    toast(err.message, "err");
    setBusy(btn, false);
    return;
  }

  const stages = data.stages || {};
  const allowed = data.decision === "BOOT_ALLOWED";
  let prevStage = null;

  for (const node of PIPELINE) {
    if (node.key === "power") {
      setNode("power", "active");
      await sleep(320);
      setNode("power", "pass", "power rails nominal · boot triggered");
      continue;
    }
    if (node.key === "boot") {
      setNode("boot", "active");
      await sleep(360);
      setNode("boot", allowed ? "pass" : "fail", `${data.decision} · ${data.status}`);
      continue;
    }
    const stage = stages[node.stage];
    if (stage === undefined) {
      if (node.stage !== prevStage) await sleep(130);
      setNode(node.key, "skipped", "not reached — an earlier check blocked boot");
      continue;
    }
    if (node.stage !== prevStage) {
      setNode(node.key, "active");
      await sleep(320);
    }
    setNode(node.key, stage.passed ? "pass" : "fail", node.detail(stage.details || {}));
    prevStage = node.stage;
  }

  $("#pipe-message").innerHTML = `
    <span class="badge ${allowed ? "badge-ok" : "badge-err"}">${allowed ? "BOOT ALLOWED" : "BOOT BLOCKED"}</span>
    <span>${esc(data.message)}</span>`;
  setBusy(btn, false);

  if (allowed) toast(`Boot allowed for ${deviceId} — all checks passed`, "ok");
  else toast(`Boot blocked for ${deviceId}: ${data.status}`, "warn");

  safe(refreshDashboard);
}

$("#pipe-run").addEventListener("click", runLiveBoot);
buildPipeline();

/* ============================================================
   DEVICES
   ============================================================ */

async function refreshDevices() {
  const devices = await api("/api/devices");
  $("#device-count").textContent = devices.length;
  const tbody = $("#devices-table tbody");
  if (!devices.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty">No devices provisioned yet.</td></tr>';
    return;
  }
  tbody.innerHTML = devices.map((d) => {
    const e = d.enrollment;
    const rel = e ? Math.round(e.reliability * 100) : 0;
    return `<tr class="clickable" data-device="${esc(d.device_id)}">
      <td class="mono">${esc(d.device_id)}</td>
      <td>${d.bit_size} bits</td>
      <td>${e ? `${e.stable_bit_count} / ${e.unstable_bit_count}` : "—"}</td>
      <td>${e ? `<div class="meter-row"><div class="bar ok"><span style="width:${rel}%"></span></div><span class="meter-val">${rel}%</span></div>` : "—"}</td>
      <td class="mono">${esc(d.min_firmware_version || "any")}</td>
      <td class="mono">${esc(fmtTime(d.created_at))}</td>
    </tr>`;
  }).join("");

  $$("#devices-table tbody tr").forEach((tr) => tr.addEventListener("click", () => {
    $$("#devices-table tbody tr").forEach((r) => r.classList.remove("selected"));
    tr.classList.add("selected");
    showDeviceDetail(tr.dataset.device);
  }));
}

async function showDeviceDetail(deviceId) {
  const box = $("#device-detail");
  box.innerHTML = '<div class="empty">Loading device…</div>';
  try {
    const [device, cert, minver] = await Promise.all([
      api(`/api/devices/${encodeURIComponent(deviceId)}`),
      api(`/api/devices/${encodeURIComponent(deviceId)}/certificate`),
      api(`/api/devices/${encodeURIComponent(deviceId)}/minimum-version`),
    ]);
    const e = device.enrollment || {};
    box.innerHTML = `
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px;flex-wrap:wrap">
        <span class="badge badge-accent">${esc(deviceId)}</span>
        ${cert.chain_valid ? '<span class="badge badge-ok">chain trusted</span>' : '<span class="badge badge-err">chain invalid</span>'}
        <span class="badge badge-neutral">${device.bit_size} bits</span>
      </div>
      <div class="kv"><span class="k">Registered</span><span class="v">${esc(fmtTime(device.created_at))}</span></div>
      <div class="kv"><span class="k">Stable / unstable bits</span><span class="v">${esc(e.stable_bit_count ?? "—")} / ${esc(e.unstable_bit_count ?? "—")}</span></div>
      <div class="kv"><span class="k">Reliability</span><span class="v">${e.reliability != null ? (e.reliability * 100).toFixed(2) + "%" : "—"}</span></div>
      <div class="kv"><span class="k">Bit error rate</span><span class="v">${e.bit_error_rate != null ? (e.bit_error_rate * 100).toFixed(3) + "%" : "—"}</span></div>
      <div class="kv"><span class="k">Uniqueness</span><span class="v">${e.uniqueness != null ? (e.uniqueness * 100).toFixed(2) + "%" : "—"}</span></div>
      <div class="kv"><span class="k">Certificate serial</span><span class="v mono">${esc(cert.serial_number)}</span></div>
      <div class="kv"><span class="k">Min firmware version</span><span class="v mono">${esc(minver.min_firmware_version || "any")}</span></div>
      <div style="margin-top:12px">
        <label style="font-size:12px;color:var(--muted);font-weight:600">Anti-rollback floor (dotted numeric, empty clears)</label>
        <div style="display:flex;gap:8px;margin-top:6px">
          <input id="minver-input" type="text" value="${esc(minver.min_firmware_version)}" placeholder="e.g. 2.0.0" />
          <button class="btn btn-ghost" id="minver-save">Save</button>
        </div>
      </div>
      <div style="margin-top:16px;padding-top:14px;border-top:1px solid var(--border)">
        <button class="btn btn-danger" id="device-remove">Remove device (re-provision)</button>
      </div>`;
    $("#minver-save").addEventListener("click", async (e) => {
      const btn = e.currentTarget;
      setBusy(btn, true, "Saving…");
      try {
        await api(`/api/devices/${encodeURIComponent(deviceId)}/minimum-version`, {
          method: "PUT",
          body: JSON.stringify({ version: $("#minver-input").value.trim() }),
        });
        toast(`Anti-rollback floor updated for ${deviceId}`, "ok");
        await showDeviceDetail(deviceId);
        await refreshDevices();
      } catch (err) {
        toast(err.message, "err");
      } finally {
        setBusy(btn, false);
      }
    });
    $("#device-remove").addEventListener("click", async (e) => {
      const btn = e.currentTarget;
      if (!confirm(`Remove ${deviceId}? Its PUF enrollment, certificate, firmware and one-time challenges are deleted (audit logs are kept). The device can then be re-provisioned.`)) return;
      setBusy(btn, true, "Removing…");
      try {
        await api(`/api/devices/${encodeURIComponent(deviceId)}`, { method: "DELETE" });
        toast(`Device ${deviceId} removed; re-provision to re-enroll`, "ok");
        box.innerHTML = '<div class="empty">Device removed. Provision it again to re-enroll.</div>';
        await refreshDevices();
      } catch (err) {
        toast(err.message, "err");
      } finally {
        setBusy(btn, false);
      }
    });
  } catch (err) {
    box.innerHTML = `<div class="empty">${esc(err.message)}</div>`;
  }
}

$("#provision-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = e.currentTarget.querySelector("button");
  const deviceId = $("#device-id").value.trim();
  setBusy(btn, true, "Provisioning…");
  try {
    const data = await api("/api/devices", {
      method: "POST",
      body: JSON.stringify({ device_id: deviceId, bit_size: parseInt($("#bit-size").value, 10) }),
    });
    toast(`Device ${deviceId} provisioned (PUF ${data.bit_size} bits, ${data.stable_bit_count} stable bits)`, "ok");
    await refreshDevices();
    await showDeviceDetail(deviceId);
  } catch (err) {
    toast(err.message, "err");
  } finally {
    setBusy(btn, false);
  }
});

$("#refresh-devices").addEventListener("click", () => refreshDevices());

/* ============================================================
   SRAM PUF ANALYSIS
   ============================================================ */

function hexToBytes(hex) {
  if (!hex) return [];
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

let pufDevices = [];
let pufSelected = null;

function renderPufViz(dev) {
  const box = $("#puf-response-viz");
  if (!dev) {
    box.innerHTML = '<div class="empty">No devices enrolled.</div>';
    $("#puf-viz-caption").textContent = "";
    return;
  }
  const mask = hexToBytes(dev.stability_mask);
  const ref = hexToBytes(dev.reference);
  const bitSize = dev.bit_size || mask.length * 8;
  const cols = Math.min(64, 2 ** Math.ceil(Math.log2(Math.sqrt(bitSize))));
  const cells = [];
  for (let b = 0; b < bitSize; b++) {
    const byteIndex = b >> 3;
    const bitIndex = b & 7;
    const maskBit = (mask[byteIndex] >> bitIndex) & 1;
    const refBit = (ref[byteIndex] >> bitIndex) & 1;
    const cls = !maskBit ? "unstable" : refBit ? "stable1" : "stable0";
    cells.push(`<span class="cell ${cls}" title="cell ${b}"></span>`);
  }
  box.style.gridTemplateColumns = `repeat(${cols}, 9px)`;
  box.innerHTML = cells.join("");
  $("#puf-viz-caption").textContent = `${dev.device_id} · ${bitSize} bits · ${dev.num_captures} samples`;
}

function renderPufMetrics(dev) {
  const box = $("#puf-device-metrics");
  if (!dev) {
    box.innerHTML = '<div class="empty">Select a device to inspect its real PUF characteristics.</div>';
    return;
  }
  const stablePct = dev.bit_size ? (dev.stable_bit_count / dev.bit_size) * 100 : 0;
  box.innerHTML = `
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;flex-wrap:wrap">
      <span class="badge badge-accent">${esc(dev.device_id)}</span>
      <span class="badge badge-neutral">${dev.bit_size} bits</span>
      <span class="badge badge-info">${dev.num_captures} samples</span>
    </div>
    <div class="kv"><span class="k">Stable bits</span><span class="v mono">${dev.stable_bit_count} (${stablePct.toFixed(1)}%)</span></div>
    <div class="kv"><span class="k">Unstable bits</span><span class="v mono">${dev.unstable_bit_count} (${(100 - stablePct).toFixed(1)}%)</span></div>
    <div class="stacked" style="margin:8px 0 12px">
      <div class="stacked-stable" style="width:${stablePct}%"></div>
      <div class="stacked-unstable" style="width:${100 - stablePct}%"></div>
    </div>
    <div class="kv"><span class="k">Reliability</span><span class="v mono">${(dev.reliability * 100).toFixed(2)}%</span></div>
    <div class="kv"><span class="k">Bit error rate</span><span class="v mono">${(dev.bit_error_rate * 100).toFixed(3)}%</span></div>
    <div class="kv"><span class="k">Intra-device Hamming distance</span><span class="v mono">${(dev.intra_device_hd * 100).toFixed(2)}%</span></div>
    <div class="kv"><span class="k">Inter-device HD (uniqueness)</span><span class="v mono">${dev.uniqueness == null ? "—" : (dev.uniqueness * 100).toFixed(2) + "%"}</span></div>
    <div class="kv"><span class="k">Samples (captures)</span><span class="v mono">${dev.num_captures}</span></div>`;
}

async function refreshPuf() {
  const analysis = await api("/api/puf/analysis");
  pufDevices = analysis.devices || [];

  const cards = [
    ["", "Devices enrolled", analysis.device_count, "active PUF identities"],
    ["accent", "PUF samples", analysis.total_captures, "captures used for enrollment"],
    ["ok", "Mean reliability", analysis.mean_reliability == null ? "—" : (analysis.mean_reliability * 100).toFixed(2) + "%", "stable bit reproduction"],
    ["warn", "Mean bit error rate", analysis.mean_bit_error_rate == null ? "—" : (analysis.mean_bit_error_rate * 100).toFixed(3) + "%", "per re-read, error corrected"],
    ["purple", "Mean intra-device HD", analysis.mean_intra_device_hd == null ? "—" : (analysis.mean_intra_device_hd * 100).toFixed(2) + "%", "mean pairwise per device"],
    ["blue", "Mean inter-device HD", analysis.mean_inter_device_hd == null ? "—" : (analysis.mean_inter_device_hd * 100).toFixed(2) + "%", "mean pairwise across fleet (uniqueness)"],
  ];
  $("#puf-stats").innerHTML = cards.map(([tone, text, value, sub]) => `
    <div class="stat-card ${tone}"><div class="stat-label">${text}</div><div class="stat-value">${esc(value)}</div><div class="stat-sub">${esc(sub)}</div></div>`).join("");

  const select = $("#puf-viz-device");
  const current = pufSelected && pufDevices.some((d) => d.device_id === pufSelected)
    ? pufSelected
    : pufDevices.length ? pufDevices[0].device_id : null;
  select.innerHTML = pufDevices.map((d) =>
    `<option value="${esc(d.device_id)}">${esc(d.device_id)}</option>`).join("");
  if (current) select.value = current;
  pufSelected = current;

  if (!pufDevices.length) {
    $("#puf-reliability-chart").innerHTML = '<div class="empty">Provision devices to populate PUF metrics.</div>';
    $("#puf-uniqueness-chart").innerHTML = '<div class="empty">Provision at least two devices to compute uniqueness.</div>';
    renderPufViz(null);
    renderPufMetrics(null);
    return;
  }

  const selected = pufDevices.find((d) => d.device_id === pufSelected) || pufDevices[0];
  renderPufViz(selected);
  renderPufMetrics(selected);

  hbarChart($("#puf-reliability-chart"), pufDevices.map((d) => ({
    label: d.device_id, value: d.reliability ?? 0, kind: "ok", fmt: (v) => (v * 100).toFixed(2) + "%",
  })));
  hbarChart($("#puf-uniqueness-chart"), pufDevices.map((d) => ({
    label: d.device_id, value: d.uniqueness ?? 0, kind: "accent", fmt: (v) => (v * 100).toFixed(2) + "%",
  })));
}

$("#puf-viz-device").addEventListener("change", (e) => {
  pufSelected = e.target.value;
  const dev = pufDevices.find((d) => d.device_id === pufSelected);
  renderPufViz(dev);
  renderPufMetrics(dev);
});

$("#puf-test-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = e.currentTarget.querySelector("button");
  const deviceId = $("#puf-test-device").value.trim();
  const box = $("#puf-test-result");
  setBusy(btn, true, "Testing…");
  try {
    const data = await api("/api/puf/test", {
      method: "POST",
      body: JSON.stringify({
        device_id: deviceId,
        num_captures: parseInt($("#puf-test-captures").value, 10),
      }),
    });
    const matched = Boolean(data.matched);
    const bound = Boolean(data.puf_binding_match);
    box.innerHTML = `
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px">
        <span class="badge ${matched ? "badge-ok" : "badge-err"}">${matched ? "credential reproduced" : "credential mismatch"}</span>
        <span class="badge ${bound ? "badge-ok" : "badge-err"}">PUF→key binding ${bound ? "holds" : "broken"}</span>
      </div>
      <div class="kv"><span class="k">Samples</span><span class="v mono">${data.num_captures ?? "—"}</span></div>
      <div class="kv"><span class="k">Stable bits checked</span><span class="v mono">${data.stable_bits_checked ?? "—"}</span></div>
      <div class="kv"><span class="k">Hamming distance (masked)</span><span class="v mono">${data.hamming_distance ?? "—"}</span></div>
      <div class="kv"><span class="k">Intra-device Hamming distance</span><span class="v mono">${data.intra_device_hd != null ? (data.intra_device_hd * 100).toFixed(2) + "%" : "—"}</span></div>
      <div class="kv"><span class="k">Bit error rate</span><span class="v mono">${data.bit_error_rate != null ? (data.bit_error_rate * 100).toFixed(3) + "%" : "—"}</span></div>
      <div class="kv"><span class="k">Reliability</span><span class="v mono">${data.reliability != null ? (data.reliability * 100).toFixed(2) + "%" : "—"}</span></div>
      <div class="kv"><span class="k">Fuzzy secret recovered</span><span class="v">${boolBadge(data.fuzzy_recovered)}</span></div>`;
  } catch (err) {
    box.innerHTML = `<div class="empty">${esc(err.message)}</div>`;
  } finally {
    setBusy(btn, false);
  }
});

/* ============================================================
   PKI / CERTIFICATES
   ============================================================ */

async function refreshPki() {
  const [mk, devices] = await Promise.all([api("/api/manufacturer/key"), api("/api/devices")]);
  $("#manufacturer-key").innerHTML = `
    <div class="kv"><span class="k">Algorithm</span><span class="v mono">ECDSA · ${esc(mk.curve)}</span></div>
    <div class="kv"><span class="k">Purpose</span><span class="v">manufacturer manifest signatures</span></div>
    <div class="kv"><span class="k">Public key</span><span class="v mono">${esc(shortHash(mk.public_key_b64, 44))}</span></div>
    <div class="chip-list" style="margin-top:8px"><span class="chip">private key never exposed</span></div>`;

  const tbody = $("#certs-table tbody");
  if (!devices.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty">No device certificates issued yet.</td></tr>';
    return;
  }
  const certs = await Promise.all(devices.map((d) =>
    api(`/api/devices/${encodeURIComponent(d.device_id)}/certificate`).catch(() => null)));
  tbody.innerHTML = certs.filter(Boolean).map((c) => `
    <tr class="clickable" data-cert-device="${esc(c.device_id)}">
      <td class="mono">${esc(c.device_id)}</td>
      <td class="mono">${esc(c.subject)}</td>
      <td class="mono">${esc(c.issuer)}</td>
      <td class="mono">${esc(shortHash(c.serial_number, 14))}</td>
      <td>${boolBadge(new Date(c.not_valid_before) <= new Date() && new Date() <= new Date(c.not_valid_after))}</td>
      <td>${c.chain_valid ? '<span class="badge badge-ok">trusted</span>' : '<span class="badge badge-err">invalid</span>'}</td>
    </tr>`).join("");

  $$("#certs-table tbody tr").forEach((tr) => tr.addEventListener("click", () => {
    $$("#certs-table tbody tr").forEach((r) => r.classList.remove("selected"));
    tr.classList.add("selected");
    showCertDetail(tr.dataset.certDevice);
  }));
}

async function showCertDetail(deviceId) {
  const box = $("#cert-detail");
  box.innerHTML = '<div class="empty">Loading certificate…</div>';
  try {
    const c = await api(`/api/devices/${encodeURIComponent(deviceId)}/certificate`);
    const valid = new Date(c.not_valid_before) <= new Date() && new Date() <= new Date(c.not_valid_after);
    const chainErrors = c.chain_errors && c.chain_errors.length ? c.chain_errors : null;
    box.innerHTML = `
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px">
        <span class="badge badge-accent">${esc(deviceId)}</span>
        ${c.chain_valid ? '<span class="badge badge-ok">chain trusted</span>' : '<span class="badge badge-err">chain invalid</span>'}
        <span class="badge ${valid ? "badge-ok" : "badge-err"}">${valid ? "valid now" : "outside validity"}</span>
      </div>
      <div class="kv"><span class="k">Subject</span><span class="v mono">${esc(c.subject)}</span></div>
      <div class="kv"><span class="k">Issuer</span><span class="v mono">${esc(c.issuer)}</span></div>
      <div class="kv"><span class="k">Serial</span><span class="v mono">${esc(c.serial_number)}</span></div>
      <div class="kv"><span class="k">Valid</span><span class="v mono">${esc(fmtTime(c.not_valid_before))} → ${esc(fmtTime(c.not_valid_after))}</span></div>
      <div class="kv"><span class="k">CA</span><span class="v">${boolBadge(c.is_ca)}</span></div>
      <div class="kv"><span class="k">Key usage</span><span class="v">${c.key_usage && c.key_usage.length ? c.key_usage.map((u) => `<span class="chip">${esc(u)}</span>`).join(" ") : "—"}</span></div>
      <div class="kv"><span class="k">Public key</span><span class="v mono">${esc(c.public_key.algorithm)} · ${esc(c.public_key.curve)}</span></div>
      <div class="kv"><span class="k">SHA-256 fingerprint</span><span class="v mono">${esc(c.public_key.fingerprint_sha256)}</span></div>
      ${chainErrors ? `<div style="margin-top:10px"><h3>Chain verification errors</h3>${chainErrors.map((e) => `<div class="stage fail"><span class="stage-icon">!</span><span class="stage-name">RFC 5280</span><span class="stage-detail">${esc(e)}</span></div>`).join("")}</div>` : ""}
      <div style="margin-top:12px"><h3>PEM</h3><pre class="result-box" style="max-height:200px">${esc(c.pem)}</pre></div>`;
  } catch (err) {
    box.innerHTML = `<div class="empty">${esc(err.message)}</div>`;
  }
}

$("#refresh-certs").addEventListener("click", () => refreshPki());

/* ============================================================
   FIRMWARE
   ============================================================ */

async function refreshFirmware() {
  const images = await api("/api/firmware");
  const tbody = $("#firmware-table tbody");
  if (!images.length) {
    tbody.innerHTML = '<tr><td colspan="4" class="empty">No firmware images signed yet.</td></tr>';
    return;
  }
  tbody.innerHTML = images.map((f) => `
    <tr>
      <td class="mono">v${esc(f.version)}</td>
      <td class="mono">${esc(f.device_id)}</td>
      <td class="mono">${esc(shortHash(f.bundle && f.bundle.payload_sha256, 18))}</td>
      <td class="mono">${esc(fmtTime(f.created_at))}</td>
    </tr>`).join("");
}

function renderVerifyResult(box, v) {
  const checks = [
    ["Hash match", v.hash_valid],
    ["Device signature", v.device_signature_valid],
    ["Manufacturer signature", v.manufacturer_signature_valid],
    ["Version allowed", v.version_allowed],
  ];
  box.style.display = "";
  box.innerHTML = `
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px">
      <span class="badge ${v.verified ? "badge-ok" : "badge-err"}">${v.verified ? "verified" : "not verified"}</span>
      <span class="badge badge-neutral">v${esc(v.version)}</span>
      ${v.minimum_version ? `<span class="badge badge-warn">floor v${esc(v.minimum_version)}</span>` : ""}
    </div>
    ${checks.map(([label, ok]) => `
      <div class="kv"><span class="k">${label}</span><span class="v">${boolBadge(ok)}</span></div>`).join("")}`;
}

$("#firmware-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = e.currentTarget.querySelector("button");
  setBusy(btn, true, "Signing…");
  try {
    const data = await api("/api/firmware", {
      method: "POST",
      body: JSON.stringify({
        version: $("#fw-version").value.trim(),
        device_id: $("#fw-device").value.trim(),
        payload_b64: $("#fw-payload").value.trim() || null,
      }),
    });
    toast(`Firmware v${data.version} signed and stored for ${data.device_id}`, "ok");
    await refreshFirmware();
  } catch (err) {
    toast(err.message, "err");
  } finally {
    setBusy(btn, false);
  }
});

$("#sign-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = e.currentTarget.querySelector("button");
  setBusy(btn, true, "Signing…");
  try {
    const data = await api("/api/firmware/sign", {
      method: "POST",
      body: JSON.stringify({
        version: $("#sign-version").value.trim(),
        device_id: $("#sign-device").value.trim(),
        store: $("#sign-store").checked,
      }),
    });
    toast(`Firmware v${data.version} signed${data.stored ? " and stored" : " (not stored)"}`, "ok");
    await refreshFirmware();
  } catch (err) {
    toast(err.message, "err");
  } finally {
    setBusy(btn, false);
  }
});

$("#verify-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = e.currentTarget.querySelector("button");
  setBusy(btn, true, "Verifying…");
  try {
    const data = await api("/api/firmware/verify", {
      method: "POST",
      body: JSON.stringify({
        device_id: $("#verify-device").value.trim(),
        firmware_version: $("#verify-version").value.trim(),
      }),
    });
    renderVerifyResult($("#verify-result"), data);
  } catch (err) {
    const box = $("#verify-result");
    box.style.display = "";
    box.innerHTML = `<div class="empty">${esc(err.message)}</div>`;
  } finally {
    setBusy(btn, false);
  }
});

$("#refresh-firmware").addEventListener("click", () => refreshFirmware());

/* ============================================================
   SECURE BOOT
   ============================================================ */

const STAGE_LABELS = {
  puf_recovery: "SRAM PUF recovery",
  puf_pki_binding: "PUF → key binding",
  certificate_verification: "Certificate chain",
  challenge_response: "Challenge-response",
  firmware_hash: "Firmware SHA-256",
  firmware_signature: "Firmware signatures",
  anti_rollback: "Anti-rollback",
};

function stageDetail(stage) {
  const d = stage.details || {};
  if (d.bit_error_rate != null) return `BER ${(d.bit_error_rate * 100).toFixed(2)}% · rel ${(d.reliability * 100).toFixed(1)}%`;
  if (d.auth_signature_valid != null) return `sig ${d.auth_signature_valid ? "ok" : "invalid"}`;
  if (d.hash_valid != null) return d.hash_valid ? "hash ok" : "hash mismatch";
  if (d.signature_valid != null) return d.signature_valid ? "signatures ok" : "signature invalid";
  if (d.version_allowed != null) return `v${d.image_version} vs floor ${d.minimum_version || "any"}`;
  if (d.certificate_valid != null) return d.certificate_valid ? "chained to root" : "not chained";
  if (d.puf_binding_match != null) return d.puf_binding_match ? "binding holds" : "binding broken";
  return "";
}

function renderBootResult(box, data) {
  const blocked = data.decision === "BOOT_BLOCKED";
  box.innerHTML = `
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:12px">
      <span class="badge ${blocked ? "badge-err" : "badge-ok"}">${esc(data.decision)}</span>
      <span class="badge badge-neutral">${esc(data.status)}</span>
      <span class="badge badge-accent">${esc(data.booted ? "booted" : "halted")}</span>
    </div>
    <div class="stage-list">${Object.entries(data.stages || {}).map(([name, stage]) => {
      const pass = Boolean(stage.passed);
      const label = STAGE_LABELS[name] || name;
      const detail = stageDetail(stage);
      return `<div class="stage ${pass ? "pass" : "fail"}">
        <span class="stage-icon">${pass ? "✓" : "✗"}</span>
        <span class="stage-name">${esc(label)}</span>
        <span class="stage-detail">${esc(detail)}</span>
      </div>`;
    }).join("")}</div>
    <div style="margin-top:12px" class="muted">${esc(data.message)}</div>`;
}

async function refreshBoot() {
  const logs = await api("/api/boot/logs?limit=25");
  const tbody = $("#boot-logs-table tbody");
  if (!logs.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty">No boot attempts yet.</td></tr>';
    return;
  }
  tbody.innerHTML = logs.map((l) => `
    <tr>
      <td>${bootStatusBadge(l.status)}</td>
      <td class="mono">${esc(l.device_id)}</td>
      <td class="mono">${esc(l.image_version || "—")}</td>
      <td>${esc(l.message)}</td>
      <td class="mono">${esc(fmtTime(l.created_at))}</td>
    </tr>`).join("");
}

$("#boot-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = e.currentTarget.querySelector("button");
  const box = $("#boot-result");
  const body = { device_id: $("#boot-device").value.trim() };
  const version = $("#boot-version").value.trim();
  if (version) body.firmware_version = version;
  setBusy(btn, true, "Booting…");
  try {
    const data = await api("/api/boot", { method: "POST", body: JSON.stringify(body) });
    renderBootResult(box, data);
    await refreshBoot();
  } catch (err) {
    box.innerHTML = `<div class="empty">${esc(err.message)}</div>`;
  } finally {
    setBusy(btn, false);
  }
});

$("#refresh-bootlogs").addEventListener("click", () => refreshBoot());

/* ============================================================
   ATTACK CENTER
   ============================================================ */

const ATTACK_MENU = [
  { name: "clone_device", label: "Device Clone" },
  { name: "tamper_firmware", label: "Firmware Tampering" },
  { name: "wrong_signer", label: "Wrong Signer" },
  { name: "replay_challenge", label: "Replay Attack" },
  { name: "certificate_forgery", label: "Certificate Forgery" },
  { name: "firmware_rollback", label: "Firmware Rollback" },
];

let selectedAttack = null;
let attackScenarios = [];

function attackLabel(name) {
  const hit = ATTACK_MENU.find((a) => a.name === name);
  return hit ? hit.label : name.replace(/_/g, " ");
}

async function refreshAttacks() {
  const scenarios = await api("/api/attacks");
  const logs = await api("/api/attacks/logs?limit=25");
  attackScenarios = scenarios;

  if (!selectedAttack && scenarios.length) {
    const first = ATTACK_MENU.find((a) => scenarios.some((s) => s.name === a.name));
    selectedAttack = first ? first.name : scenarios[0].name;
  }

  const buttons = ATTACK_MENU
    .map((menu) => {
      const scenario = scenarios.find((s) => s.name === menu.name);
      return { ...menu, description: scenario ? scenario.description : "scenario unavailable" };
    });
  $("#attack-buttons").innerHTML = buttons.map((b) => `
    <button type="button" class="attack-btn ${selectedAttack === b.name ? "selected" : ""}" data-attack="${esc(b.name)}">
      <span class="attack-btn-name">${esc(b.label)}</span>
      <span class="attack-btn-desc">${esc(b.description)}</span>
      <span class="attack-btn-tag">simulated attack · ${esc(b.name)}</span>
    </button>`).join("");

  $$("#attack-buttons .attack-btn").forEach((el) => el.addEventListener("click", () => {
    selectedAttack = el.dataset.attack;
    $$("#attack-buttons .attack-btn").forEach((c) => c.classList.toggle("selected", c.dataset.attack === selectedAttack));
    updateAttackNote();
  }));
  updateAttackNote();

  try {
    const devices = await api("/api/devices");
    $("#device-list").innerHTML = devices.map((d) => `<option value="${esc(d.device_id)}"></option>`).join("");
  } catch { /* device list is a convenience only */ }

  const tbody = $("#attack-logs-table tbody");
  if (!logs.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty">No attacks run yet.</td></tr>';
    return;
  }
  tbody.innerHTML = logs.map((l) => `
    <tr>
      <td class="mono">${esc(attackLabel(l.attack))}</td>
      <td class="mono">${esc(l.target)}</td>
      <td class="mono">${l.detection_point ? esc(STAGE_LABELS[l.detection_point] || l.detection_point) : '<span class="badge badge-err">not detected</span>'}</td>
      <td>${bootStatusBadge(l.result)}</td>
      <td>${esc(l.reason)}</td>
      <td class="mono">${esc(fmtTime(l.timestamp))}</td>
    </tr>`).join("");
}

function updateAttackNote() {
  $("#attack-selected-label").textContent = selectedAttack ? attackLabel(selectedAttack) : "none selected";
  $("#attack-target-note").textContent = selectedAttack
    ? `Selected attack: ${attackLabel(selectedAttack)}. Set a target device (and a version for rollback) then run.`
    : "Select an attack scenario first.";
}

function renderAttackReport(data) {
  const box = $("#attack-result");
  const blocked = data.decision === "BOOT_BLOCKED";
  const stages = data.stages || {};
  const stepList = Object.keys(stages).map((name, i) => {
    const st = stages[name];
    const pass = Boolean(st.passed);
    const caught = data.detection_point === name;
    return `<div class="stage ${pass ? "pass" : "fail"}">
      <span class="stage-icon">${pass ? "✓" : "✗"}</span>
      <span class="stage-name">${i + 1}. ${esc(STAGE_LABELS[name] || name)}</span>
      ${caught ? '<span class="badge badge-err">CAUGHT HERE</span>' : ""}
      <span class="stage-detail">${esc(stageDetail(st))}</span>
    </div>`;
  }).join("");
  const pills = Object.keys(stages).map((name) => {
    const pass = Boolean(stages[name].passed);
    return `<span class="check-pill ${pass ? "ok" : "fail"}">${pass ? "✓" : "✗"} ${esc(STAGE_LABELS[name] || name)}</span>`;
  }).join("");

  box.innerHTML = `
    <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:12px">
      <span class="badge badge-accent">${esc(attackLabel(data.attack))}</span>
      <span class="badge badge-neutral">target ${esc(data.target)}</span>
      <span class="badge ${blocked ? "badge-ok" : "badge-err"}">${blocked ? "Defended" : "Not detected"}</span>
      <span class="badge ${blocked ? "badge-err" : "badge-warn"}">${esc(data.decision)}</span>
      <span class="timeline-time">${esc(fmtTime(data.timestamp))}</span>
    </div>
    <div class="kv-grid">
      <div class="kv"><span class="k">Attack type</span><span class="v">${esc(attackLabel(data.attack))}</span></div>
      <div class="kv"><span class="k">Target</span><span class="v mono">${esc(data.target)}</span></div>
      <div class="kv"><span class="k">Detection point</span><span class="v">${data.detection_point ? esc(STAGE_LABELS[data.detection_point] || data.detection_point) : '<span class="badge badge-err">not detected</span>'}</span></div>
      <div class="kv"><span class="k">Final result</span><span class="v mono">${esc(data.decision)} · ${esc(data.status)}</span></div>
      <div class="kv"><span class="k">Reason</span><span class="v">${esc(data.reason || data.message)}</span></div>
      <div class="kv"><span class="k">Timestamp</span><span class="v mono">${esc(fmtTime(data.timestamp))}</span></div>
    </div>
    ${stepList ? `<h3 style="margin:14px 0 8px">Attack steps</h3><div class="stage-list">${stepList}</div>` : ""}
    ${pills ? `<h3 style="margin:14px 0 8px">Security checks</h3><div class="check-pills">${pills}</div>` : ""}`;
}

$("#attack-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!selectedAttack) {
    toast("Select an attack scenario first", "warn");
    return;
  }
  const btn = e.currentTarget.querySelector("button");
  const box = $("#attack-result");
  const body = { device_id: $("#attack-device").value.trim() };
  const version = $("#attack-version").value.trim();
  if (version) body.firmware_version = version;
  setBusy(btn, true, "Running attack…");
  box.innerHTML = '<div class="empty">Executing attack through the real boot pipeline…</div>';
  try {
    const data = await api(`/api/attacks/${encodeURIComponent(selectedAttack)}`, {
      method: "POST",
      body: JSON.stringify(body),
    });
    renderAttackReport(data);
    await refreshAttacks();
    toast(`Attack executed: ${attackLabel(data.attack)} → ${data.decision}`, data.decision === "BOOT_BLOCKED" ? "ok" : "warn");
  } catch (err) {
    box.innerHTML = `<div class="empty">${esc(err.message)}</div>`;
  } finally {
    setBusy(btn, false);
  }
});

$("#refresh-attacklogs").addEventListener("click", () => refreshAttacks());

/* ============================================================
   SECURITY LOGS
   ============================================================ */

async function refreshLogs() {
  const eventType = $("#log-event-type").value;
  const deviceId = $("#log-device-id").value.trim();
  const params = new URLSearchParams({ limit: "50" });
  if (eventType) params.set("event_type", eventType);
  if (deviceId) params.set("device_id", deviceId);

  const [events, boot, auth, attack] = await Promise.all([
    api(`/api/security/events?${params}`),
    api("/api/boot/logs?limit=50"),
    api("/api/auth/logs?limit=50"),
    api("/api/attacks/logs?limit=50"),
  ]);

  const timeline = $("#security-timeline");
  if (!events.length) {
    timeline.innerHTML = '<div class="empty">No security events match the current filters.</div>';
  } else {
    timeline.innerHTML = events.map((e) => `
      <div class="timeline-item ${severityClass(e.severity)}">
        <div class="timeline-top">
          <span class="badge badge-neutral">${esc(e.event_type)}</span>
          <span class="timeline-title mono">${esc(e.device_id)}</span>
          <span class="badge ${severityClass(e.severity)}">${esc(e.severity)}</span>
          <span class="badge badge-neutral">${esc(e.result)}</span>
          ${e.attack ? `<span class="badge badge-accent">${esc(e.attack.replace(/_/g, " "))}</span>` : ""}
          <span class="timeline-time">${esc(fmtTime(e.timestamp))}</span>
        </div>
        <div class="timeline-summary">${esc(e.summary || "")}</div>
      </div>`).join("");
  }

  renderLogTable($("#logs-table-boot"), boot, (l) => `
    <td>${bootStatusBadge(l.status)}</td>
    <td class="mono">${esc(l.device_id)}</td>
    <td class="mono">${esc(l.image_version || "—")}</td>
    <td>${esc(l.message)}</td>
    <td class="mono">${esc(fmtTime(l.created_at))}</td>`);

  renderLogTable($("#logs-table-auth"), auth, (l) => `
    <td>${l.success ? '<span class="badge badge-ok">success</span>' : '<span class="badge badge-err">failed</span>'}</td>
    <td class="mono">${esc(l.device_id)}</td>
    <td>${esc(l.reason)}</td>
    <td class="mono">${esc(fmtTime(l.timestamp))}</td>`);

  renderLogTable($("#logs-table-attack"), attack, (l) => `
    <td class="mono">${esc(l.attack.replace(/_/g, " "))}</td>
    <td class="mono">${esc(l.target)}</td>
    <td class="mono">${esc(l.detection_point || "not detected")}</td>
    <td>${bootStatusBadge(l.result)}</td>
    <td class="mono">${esc(fmtTime(l.timestamp))}</td>`);
}

function renderLogTable(table, rows, rowRenderer) {
  const tbody = table.querySelector("tbody");
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="5" class="empty">No entries yet.</td></tr>`;
    return;
  }
  tbody.innerHTML = rows.map((r) => `<tr>${rowRenderer(r)}</tr>`).join("");
}

$("#log-refresh").addEventListener("click", () => safe(refreshLogs));
$("#log-event-type").addEventListener("change", () => safe(refreshLogs));
$("#log-device-id").addEventListener("keydown", (e) => {
  if (e.key === "Enter") safe(refreshLogs);
});

$$(".tab").forEach((tab) => tab.addEventListener("click", () => {
  $$(".tab").forEach((t) => t.classList.toggle("active", t === tab));
  $$("#view-logs .table").forEach((t) => { t.style.display = "none"; });
  $(`#logs-table-${tab.dataset.tab}`).style.display = "";
}));

/* ============================================================
   boot / init
   ============================================================ */

const initialHash = location.hash.replace("#", "");
if (VIEWS[initialHash]) navigate(initialHash, false);
else navigate("dashboard", false);
tickClock();
updateBackendStatus();
