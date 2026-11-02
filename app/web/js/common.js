/* Adaptive Honeypot - shared front-end helpers (no external libraries, works offline) */
(function () {
  "use strict";
  const AHP = (window.AHP = {});

  // ---------------------------------------------------------------- icons
  const I = {
    logo: '<svg viewBox="0 0 32 32" fill="none"><path d="M16 2.5 4.5 7v8.2c0 7.1 4.9 12.4 11.5 14.3 6.6-1.9 11.5-7.2 11.5-14.3V7L16 2.5Z" fill="var(--accent)"/><path d="M10.5 15.5c0-3 2.5-5.4 5.5-5.4s5.5 2.4 5.5 5.4c0 2.5-1.6 3.4-1.6 5.3h-7.8c0-1.9-1.6-2.8-1.6-5.3Z" fill="var(--accent-ink)" opacity=".95"/><path d="M13 23h6" stroke="var(--accent-ink)" stroke-width="1.8" stroke-linecap="round"/><circle cx="16" cy="15.5" r="1.8" fill="var(--accent)"/></svg>',
    sun: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>',
    moon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z"/></svg>',
    monitor: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg>',
    menu: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M3 6h18M3 12h18M3 18h18"/></svg>',
    out: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/></svg>',
    download: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/></svg>',
    play: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M7 4v16l13-8z"/></svg>',
    stop: '<svg viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="6" width="12" height="12" rx="2"/></svg>',
    refresh: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M21 12a9 9 0 1 1-3-6.7L21 8M21 3v5h-5"/></svg>',
    shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"><path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Z"/></svg>',
  };
  AHP.icons = I;

  // ---------------------------------------------------------------- theme
  AHP.getTheme = () => { try { return localStorage.getItem("ahp-theme") || "system"; } catch (e) { return "system"; } };
  AHP.setTheme = (t) => {
    try { localStorage.setItem("ahp-theme", t); } catch (e) { /* ignore */ }
    if (t === "system") delete document.documentElement.dataset.theme;
    else document.documentElement.dataset.theme = t;
    document.querySelectorAll(".theme-switch button").forEach((b) => b.classList.toggle("on", b.dataset.t === t));
    document.dispatchEvent(new CustomEvent("themechange"));
  };

  // ---------------------------------------------------------------- utils
  AHP.esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  AHP.$ = (sel, root) => (root || document).querySelector(sel);
  AHP.$$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));
  AHP.fmtTime = (ts) => { const d = new Date(ts * 1000); return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }); };
  AHP.fmtDate = (ts) => ts ? new Date(ts * 1000).toLocaleString([], { year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "-";
  AHP.ago = (ts) => {
    const s = Math.max(0, Date.now() / 1000 - ts);
    if (s < 60) return Math.round(s) + "s ago"; if (s < 3600) return Math.round(s / 60) + "m ago";
    if (s < 86400) return Math.round(s / 3600) + "h ago"; return Math.round(s / 86400) + "d ago";
  };
  AHP.dur = (s) => { s = Math.round(s || 0); if (s < 60) return s + "s"; if (s < 3600) return Math.floor(s / 60) + "m " + (s % 60) + "s"; return Math.floor(s / 3600) + "h " + Math.floor((s % 3600) / 60) + "m"; };
  AHP.num = (n) => (n == null ? "-" : Number(n).toLocaleString());
  AHP.threat = (t) => `<span class="threat ${t >= 70 ? "h" : t >= 40 ? "m" : "l"}">${t}</span>`;
  AHP.PROFILE = { scanner: ["Scanner", "info"], bot: ["Automated bot", "warn"], script_kiddie: ["Script kiddie", "accent"], skilled: ["Skilled attacker", "bad"], unknown: ["Unknown", ""] };
  AHP.profile = (p) => { const x = AHP.PROFILE[p] || [p, ""]; return `<span class="badge ${x[1]}">${AHP.esc(x[0])}</span>`; };
  AHP.STRAT = { static: "Static baseline", breadcrumbs: "Breadcrumbs", tarpit: "Tarpit", rich: "Rich / LLM" };
  AHP.strategy = (s) => `<span class="badge accent">${AHP.esc(AHP.STRAT[s] || s)}</span>`;
  AHP.sev = (s) => `<span class="badge ${s === "critical" || s === "high" ? "bad" : s === "medium" ? "warn" : "info"}">${AHP.esc(s)}</span>`;

  AHP.toast = (msg, kind) => {
    let box = document.getElementById("toasts");
    if (!box) { box = document.createElement("div"); box.id = "toasts"; document.body.appendChild(box); }
    const t = document.createElement("div"); t.className = "toast " + (kind || ""); t.textContent = msg; box.appendChild(t);
    setTimeout(() => t.remove(), 4200);
  };

  AHP.api = async (path, opts) => {
    opts = opts || {};
    const init = { method: opts.method || (opts.body ? "POST" : "GET"), credentials: "same-origin", headers: {} };
    if (opts.body !== undefined) { init.body = JSON.stringify(opts.body); init.headers["Content-Type"] = "application/json"; }
    const r = await fetch(path, init);
    let data = null;
    try { data = await r.json(); } catch (e) { data = null; }
    if (r.status === 401 && !opts.noRedirect) { location.href = "/login.html?next=" + encodeURIComponent(location.pathname); throw new Error("auth"); }
    if (!r.ok) { const m = (data && data.error) || r.statusText; if (!opts.quiet) AHP.toast(m, "bad"); throw new Error(m); }
    return data;
  };
  AHP.post = (path, body, opts) => AHP.api(path, Object.assign({ method: "POST", body: body || {} }, opts || {}));

  // ---------------------------------------------------------------- shell (nav, footer)
  const NAV = [
    ["about", "/index.html", "About"], ["dashboard", "/dashboard.html", "Dashboard"], ["areas", "/areas.html", "Nine Areas"],
    ["lab", "/lab.html", "Attack Lab"], ["toolkit", "/toolkit.html", "Toolkit & APIs"], ["history", "/history.html", "History"],
    ["reports", "/reports.html", "Reports"], ["games", "/games.html", "Learn & Play"],
  ];

  function topbar(page, user) {
    const nav = NAV.map(([k, h, l]) => `<a href="${h}" class="${k === page ? "active" : ""}">${l}</a>`).join("");
    const t = AHP.getTheme();
    const tb = [["light", I.sun, "Light"], ["dark", I.moon, "Dark"], ["system", I.monitor, "System"]]
      .map(([k, ic, l]) => `<button data-t="${k}" class="${t === k ? "on" : ""}" title="${l} theme" aria-label="${l} theme">${ic}</button>`).join("");
    const who = user
      ? `<div class="user-chip"><div class="avatar">${AHP.esc(user.username[0].toUpperCase())}</div><div class="who"><div style="font-size:13px;font-weight:600">${AHP.esc(user.username)}</div><div class="role">${AHP.esc(user.role)}</div></div><button class="btn sm" id="logoutBtn" title="Sign out">${I.out}</button></div>`
      : `<a class="btn primary sm" href="/login.html">Sign in</a>`;
    return `<div class="topbar-in"><a class="brand" href="/index.html">${I.logo}<span>Adaptive Honeypot<small>Cyber-deception console</small></span></a>
      <button class="btn sm menu-btn" id="menuBtn" aria-label="Menu">${I.menu}</button>
      <nav class="nav" id="nav">${nav}</nav><div class="top-actions"><div class="theme-switch">${tb}</div>${who}</div></div>`;
  }

  AHP.user = null;
  AHP.init = async function (page, needAuth) {
    AHP.page = page;
    const hdr = document.createElement("header"); hdr.className = "topbar"; document.body.prepend(hdr);
    let user = null;
    try { user = (await AHP.api("/api/whoami", { noRedirect: true, quiet: true })).user; } catch (e) { user = null; }
    if (needAuth && !user) { location.href = "/login.html?next=" + encodeURIComponent(location.pathname); return null; }
    AHP.user = user;
    hdr.innerHTML = topbar(page, user);
    hdr.querySelectorAll(".theme-switch button").forEach((b) => b.addEventListener("click", () => AHP.setTheme(b.dataset.t)));
    const mb = document.getElementById("menuBtn"); if (mb) mb.onclick = () => document.getElementById("nav").classList.toggle("open");
    const lo = document.getElementById("logoutBtn");
    if (lo) lo.onclick = async () => { await AHP.post("/api/auth/logout"); location.href = "/login.html"; };
    const f = document.createElement("footer"); f.className = "foot";
    f.innerHTML = `Adaptive Cybersecurity Honeypot &middot; v1.0.0 &middot; Lab traffic uses reserved range 198.18.0.0/15 &middot; Decoys never execute attacker commands`;
    document.body.appendChild(f);
    if (user) trackTime(page);
    return user;
  };

  function trackTime(page) {
    let start = Date.now(), active = 0, visible = !document.hidden;
    const flush = () => {
      if (visible) active += (Date.now() - start) / 1000;
      start = Date.now();
      if (active < 1) return;
      const body = JSON.stringify({ page, seconds: Math.round(active) });
      active = 0;
      try { navigator.sendBeacon("/api/track", new Blob([body], { type: "application/json" })); } catch (e) { /* ignore */ }
    };
    document.addEventListener("visibilitychange", () => { if (document.hidden) { flush(); visible = false; } else { visible = true; start = Date.now(); } });
    window.addEventListener("pagehide", flush);
    setInterval(flush, 60000);
    AHP.post("/api/track", { page, seconds: 0 }, { quiet: true }).catch(() => {});
  }

  // ---------------------------------------------------------------- drawer / modal
  AHP.drawer = (html) => {
    let ov = document.getElementById("ov"), dr = document.getElementById("drawer");
    if (!ov) { ov = document.createElement("div"); ov.id = "ov"; ov.className = "overlay"; document.body.appendChild(ov); }
    if (!dr) { dr = document.createElement("aside"); dr.id = "drawer"; dr.className = "drawer"; document.body.appendChild(dr); }
    dr.innerHTML = `<div class="row" style="justify-content:flex-end"><button class="btn sm" id="drClose">Close</button></div>` + html;
    requestAnimationFrame(() => { ov.classList.add("on"); dr.classList.add("on"); });
    const close = () => { ov.classList.remove("on"); dr.classList.remove("on"); };
    ov.onclick = close; dr.querySelector("#drClose").onclick = close;
    document.onkeydown = (e) => { if (e.key === "Escape") close(); };
    return dr;
  };
  AHP.modal = (html, opts) => {
    let ov = document.getElementById("mov"), m = document.getElementById("modal");
    if (!ov) { ov = document.createElement("div"); ov.id = "mov"; ov.className = "overlay"; document.body.appendChild(ov); }
    if (!m) { m = document.createElement("div"); m.id = "modal"; m.className = "modal"; document.body.appendChild(m); }
    m.innerHTML = html; ov.classList.add("on"); m.classList.add("on");
    const close = () => { ov.classList.remove("on"); m.classList.remove("on"); };
    if (!(opts && opts.sticky)) ov.onclick = close;
    m.querySelectorAll("[data-close]").forEach((b) => (b.onclick = close));
    return { el: m, close };
  };

  // ---------------------------------------------------------------- charts (SVG)
  const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
  AHP.palette = () => ["--c1", "--c2", "--c3", "--c4", "--c5", "--c6", "--c7"].map(css);

  AHP.lineChart = (el, labels, series, opts) => {
    opts = opts || {};
    const W = el.clientWidth || 600, H = opts.height || 220, P = { l: 34, r: 10, t: 10, b: 24 };
    const max = Math.max(1, ...series.flatMap((s) => s.values));
    const n = labels.length, x = (i) => P.l + (i * (W - P.l - P.r)) / Math.max(1, n - 1), y = (v) => H - P.b - (v / max) * (H - P.t - P.b);
    let g = "";
    for (let k = 0; k <= 4; k++) { const v = (max * k) / 4, yy = y(v); g += `<line class="grid-line" x1="${P.l}" x2="${W - P.r}" y1="${yy}" y2="${yy}"/><text x="${P.l - 6}" y="${yy + 4}" text-anchor="end">${Math.round(v)}</text>`; }
    const step = Math.ceil(n / 8);
    labels.forEach((l, i) => { if (i % step === 0 || i === n - 1) g += `<text x="${x(i)}" y="${H - 6}" text-anchor="${i === n - 1 ? "end" : i === 0 ? "start" : "middle"}">${AHP.esc(l)}</text>`; });
    const pal = AHP.palette();
    series.forEach((s, si) => {
      const c = s.color || pal[si % pal.length];
      const pts = s.values.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
      if (si === 0) g += `<polygon points="${P.l},${H - P.b} ${pts} ${x(n - 1)},${H - P.b}" fill="${c}" opacity=".12"/>`;
      g += `<polyline points="${pts}" fill="none" stroke="${c}" stroke-width="2.2" stroke-linejoin="round" stroke-linecap="round"/>`;
      s.values.forEach((v, i) => { if (v) g += `<circle cx="${x(i)}" cy="${y(v)}" r="2.6" fill="${c}"><title>${AHP.esc(labels[i])}: ${v} ${AHP.esc(s.name || "")}</title></circle>`; });
    });
    el.innerHTML = `<svg class="chart" viewBox="0 0 ${W} ${H}" width="100%" height="${H}" role="img">${g}</svg>` +
      (series.length > 1 ? `<div class="legend">${series.map((s, i) => `<span><i style="background:${s.color || pal[i % pal.length]}"></i>${AHP.esc(s.name)}</span>`).join("")}</div>` : "");
  };

  AHP.donut = (el, items, opts) => {
    opts = opts || {};
    const total = items.reduce((a, b) => a + b.value, 0);
    const pal = AHP.palette(), R = 62, C = 2 * Math.PI * R;
    if (!total) { el.innerHTML = `<div class="empty">No data yet</div>`; return; }
    let off = 0, arcs = "";
    items.forEach((it, i) => {
      const len = (it.value / total) * C;
      arcs += `<circle r="${R}" cx="80" cy="80" fill="none" stroke="${it.color || pal[i % pal.length]}" stroke-width="22" stroke-dasharray="${len} ${C - len}" stroke-dashoffset="${-off}" transform="rotate(-90 80 80)"><title>${AHP.esc(it.label)}: ${it.value}</title></circle>`;
      off += len;
    });
    const legend = items.map((it, i) => `<span><i style="background:${it.color || pal[i % pal.length]}"></i>${AHP.esc(it.label)} <b>${opts.pct ? Math.round((100 * it.value) / total) + "%" : it.value}</b></span>`).join("");
    el.innerHTML = `<div class="row" style="gap:18px;align-items:center;flex-wrap:nowrap"><svg viewBox="0 0 160 160" width="150" height="150" style="flex:none">${arcs}<text x="80" y="78" text-anchor="middle" style="font:700 22px var(--sans);fill:var(--text)">${AHP.num(opts.center != null ? opts.center : total)}</text><text x="80" y="96" text-anchor="middle" style="font:11px var(--sans);fill:var(--muted)">${AHP.esc(opts.label || "total")}</text></svg><div class="legend" style="flex-direction:column;gap:6px">${legend}</div></div>`;
  };

  AHP.hbars = (el, items, opts) => {
    opts = opts || {};
    if (!items.length) { el.innerHTML = `<div class="empty">${opts.empty || "No data yet"}</div>`; return; }
    const max = Math.max(1, ...items.map((i) => i.value));
    el.innerHTML = items.map((i) => `<div class="hbar" title="${AHP.esc(i.title || i.label)}"><div class="lbl">${i.html || AHP.esc(i.label)}</div><div class="track"><div class="fill" style="width:${(100 * i.value) / max}%"></div></div><div class="v">${AHP.num(i.value)}${opts.suffix || ""}</div></div>`).join("");
  };

  AHP.downloadUrl = (url) => { const a = document.createElement("a"); a.href = url; a.download = ""; document.body.appendChild(a); a.click(); a.remove(); };
})();

/* ---------------------------------------------------------------- shared session drawer */
AHP.showSession = async function (id) {
  const s = await AHP.api("/api/sessions/" + id);
  const E = AHP.esc;
  const techs = {};
  s.events.forEach((e) => e.techniques.forEach((t) => (techs[t.id] = t)));
  const tl = s.events.map((e) => `<div class="feed-item"><div class="t">${AHP.fmtTime(e.ts)}</div><div><span class="badge">${E(e.type)}</span>
      <div class="mono" style="margin-top:4px;white-space:pre-wrap;word-break:break-word">${E(e.data)}</div>
      ${e.response ? `<details class="small"><summary class="muted">decoy response</summary><pre class="mono" style="white-space:pre-wrap;margin:4px 0">${E(e.response)}</pre></details>` : ""}
      ${e.techniques.length ? `<div class="row" style="margin-top:4px;gap:4px">${e.techniques.map((t) => `<span class="badge info" title="${E(t.name)}">${E(t.id)}</span>`).join("")}</div>` : ""}</div></div>`).join("");
  AHP.drawer(`<h2>Session <span class="mono">${E(s.id)}</span></h2>
    <div class="row" style="margin-bottom:12px">${AHP.profile(s.profile)} ${AHP.strategy(s.strategy)} <span class="badge">${E(s.sensor)}</span> ${s.simulated ? '<span class="badge">simulated</span>' : '<span class="badge bad">real</span>'} ${s.detected ? '<span class="badge warn">suspected detection</span>' : ""} Threat ${AHP.threat(s.threat)}</div>
    <div class="grid g2"><div class="card"><dl class="kv">
      <dt>Source</dt><dd class="mono">${E(s.src_ip)} (${E(s.country)})</dd><dt>ASN / ISP</dt><dd>${E(s.asn || "-")}</dd>
      <dt>Started</dt><dd>${AHP.fmtDate(s.started)}</dd><dt>Duration</dt><dd>${AHP.dur(s.duration)}</dd>
      <dt>Commands</dt><dd>${s.commands}</dd><dt>Persona</dt><dd>${E(s.persona)}</dd><dt>Interaction</dt><dd>${E(s.interaction)}</dd>
      <dt>Client</dt><dd class="mono small">${E(s.client || "-")}</dd><dt>Login</dt><dd>${s.login_ok ? "succeeded" : "none / failed"}</dd>
      ${s.abuse_score >= 0 ? `<dt>AbuseIPDB score</dt><dd>${s.abuse_score}%</dd>` : ""}</dl></div>
    <div class="card"><h4>ATT&amp;CK techniques</h4>${Object.values(techs).map((t) => `<div class="small" style="margin:4px 0"><span class="badge info">${E(t.id)}</span> ${E(t.name)} <span class="faint">· ${E(t.tactic)}</span></div>`).join("") || '<div class="empty">None</div>'}
    ${s.reasons && s.reasons.length ? `<h4 style="margin-top:10px">Why this profile</h4><ul class="small muted">${s.reasons.map((r) => `<li>${E(r)}</li>`).join("")}</ul>` : ""}
    ${s.decisions && s.decisions.length ? `<h4 style="margin-top:10px">Adaptive decisions</h4>${s.decisions.map((d) => `<div class="small">${AHP.fmtTime(d.ts)} → ${AHP.strategy(d.arm)} <span class="faint">(${E(d.why)})</span></div>`).join("")}` : ""}</div></div>
    <h3 style="margin-top:18px">Timeline (${s.events.length} events)</h3><div class="card">${tl || '<div class="empty">No events</div>'}</div>`);
};
