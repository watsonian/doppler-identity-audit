"use strict";

// Every value from the server is placed with textContent, never innerHTML, so names
// and claims from Doppler can't inject markup.
//
// Built for thousands of identities: everything derived from an identity is computed
// once per report, decisions are kept in memory, the list draws rows in batches as you
// scroll, and a decision redraws only its own row.

const SEVERITIES = ["high", "medium", "low", "info"];
const REVIEW_KEY = "identity-audit:reviewed";
const THEME_KEY = "identity-audit:theme";
const GUIDE_KEY = "identity-audit:guide-open";
const SETTING_DEFAULTS = { stale_days: 90, max_ttl_seconds: 3600, concurrency: 4 };
const BATCH = 150; // list rows drawn at a time

// Severity → pill variant and icon.
const SEVERITY_PILLS = {
  high: { variant: "red", icon: "high", label: "High" },
  medium: { variant: "yellow", icon: "medium", label: "Medium" },
  low: { variant: "blue", icon: "low", label: "Low" },
  info: { variant: "", icon: "low", label: "Info" },
  none: { variant: "green", icon: "check", label: "None" },
};

// Decision → Pill. Orange keeps "flagged" (a person's call) apart from red "High" (an automated finding).
const DECISION_PILLS = {
  approved: { variant: "green", icon: "approve", label: "Approved" },
  flagged: { variant: "orange", icon: "flag", label: "Flagged" },
  none: { variant: "", icon: "review", label: "Not reviewed" },
};

// Known OIDC providers, matched by issuer URL; anything else is shown as a custom issuer.
const PROVIDERS = [
  { title: "GitHub", logo: "github.svg", matches: (url) => url === "https://token.actions.githubusercontent.com" },
  { title: "Circle CI", logo: "circle_ci.svg", matches: (url) => url.startsWith("https://oidc.circleci.com/org/") },
  { title: "Gitlab", logo: "gitlab.svg", matches: (url) => url.startsWith("https://gitlab.") },
];

const ui = {
  state: null, // the last /api/state
  report: null, // the last /api/report
  reportVersion: null,
  items: [], // one prepared entry per identity, in display order
  byWorkplace: new Map(),
  filtered: [], // items that pass the filters, in display order
  reviews: loadReviews(),
  severity: "all",
  collapsed: new Set(), // workplace slugs collapsed in the list
  open: new Set(), // identity slugs expanded in the list
  entries: [], // list rows waiting to be drawn: {group}, {empty} or {item}
  drawn: 0,
  rowNodes: new Map(),
  groupNodes: new Map(),
  polling: null,
  settingsShown: null, // the server settings last copied into the form
  guideOpen: readStored(GUIDE_KEY) === "1",
};

const $ = (id) => document.getElementById(id);

// #region DOM helpers

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") node.className = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? "" : value);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function icon(name, extraClass = "") {
  const [viewBox, d] = ICONS[name];
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", viewBox);
  svg.setAttribute("class", `icon ${extraClass}`.trim());
  svg.setAttribute("aria-hidden", "true");
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d", d);
  svg.append(path);
  return svg;
}

function expandIcons(root = document) {
  for (const span of root.querySelectorAll("[data-icon]")) {
    const svg = icon(span.dataset.icon, span.className);
    if (span.id) svg.id = span.id;
    span.replaceWith(svg);
  }
}

function pill(severity, text) {
  const spec = SEVERITY_PILLS[severity];
  return el("span", { class: `pill ${spec.variant}` }, icon(spec.icon), text ?? spec.label);
}

function decisionPill(verdict, text) {
  const spec = DECISION_PILLS[verdict || "none"];
  return el("span", { class: `pill ${spec.variant}` }, icon(spec.icon), text ?? spec.label);
}

function debounce(fn, ms) {
  let timer;
  return (...args) => { clearTimeout(timer); timer = setTimeout(() => fn(...args), ms); };
}

function readStored(key) {
  try { return localStorage.getItem(key); } catch { return null; }
}

function writeStored(key, value) {
  try { localStorage.setItem(key, value); } catch { /* storage unavailable */ }
}

// #endregion

// #region Server calls

async function api(path, body) {
  const options = body === undefined ? {} : {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Identity-Audit": "1" },
    body: JSON.stringify(body),
  };
  const response = await fetch(path, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}

// Polls the small /api/state; the report itself is fetched only when its version changes.
async function refresh() {
  ui.state = await api("/api/state");
  if (ui.state.report_version !== ui.reportVersion) {
    ui.report = ui.state.report_version ? await api("/api/report") : null;
    ui.reportVersion = ui.state.report_version;
    if (ui.report) prepare(ui.report);
    renderChrome();
    if (ui.report) renderResults();
  } else {
    renderChrome();
  }
  const busy = ui.state.busy;
  if (busy && !ui.polling) ui.polling = setInterval(refresh, 800);
  if (!busy && ui.polling) { clearInterval(ui.polling); ui.polling = null; }
}

function isRunning() {
  const run = ui.state && ui.state.run;
  return Boolean(run && !run.finished_at);
}

function setError(id, text) {
  $(id).textContent = text;
  const input = $(id).closest(".field")?.querySelector("textarea");
  if (input) input.setAttribute("aria-invalid", text ? "true" : "false");
}

// The setup view adds tokens and starts the audit in one step.
async function startFromSetup() {
  const text = $("setup-input").value;
  if (!text.trim()) return setError("setup-error", "Paste at least one token.");
  try {
    await api("/api/tokens", { text, source: "pasted" });
  } catch (error) {
    return setError("setup-error", error.message);
  }
  $("setup-input").value = "";
  setError("setup-error", "");
  await api("/api/audit", {}).catch(() => {});
  refresh();
}

async function addTokens(text) {
  if (!text.trim()) return setError("token-error", "Paste at least one token.");
  try {
    await api("/api/tokens", { text, source: "pasted" });
    $("token-input").value = "";
    setError("token-error", "");
    $("add-form").hidden = true;
    await refresh();
  } catch (error) {
    setError("token-error", error.message);
  }
}

async function runAudit() {
  try {
    await api("/api/audit", {});
  } catch (error) {
    $("waiting-text").textContent = error.message;
  }
  refresh();
}

// #endregion

// #region Decisions
// Kept in this browser only, in memory while the page is open. Each is
// {verdict: "approved" | "flagged" | null, note, at}. The key includes the identity's
// configuration, so editing an identity in Doppler clears its decision.

function loadReviews() {
  let reviews = {};
  try { reviews = JSON.parse(localStorage.getItem(REVIEW_KEY)) || {}; } catch { /* storage unavailable */ }
  // Earlier versions stored only a timestamp per reviewed identity; read those as approvals.
  for (const [key, value] of Object.entries(reviews)) {
    if (typeof value === "string") reviews[key] = { verdict: "approved", note: "", at: value };
  }
  return reviews;
}

const saveReviews = debounce(() => writeStored(REVIEW_KEY, JSON.stringify(ui.reviews)), 250);

function reviewKey(row) {
  return `${row.identity_slug}:${JSON.stringify([row.discovery_url, row.claims_type, row.claims, row.ttl_seconds, row.service_account_role])}`;
}

const NO_DECISION = Object.freeze({ verdict: null, note: "", at: null });

function decisionOf(item) {
  return ui.reviews[item.key] || NO_DECISION;
}

function updateDecision(item, changes) {
  const next = { ...decisionOf(item), ...changes, at: new Date().toISOString() };
  if (next.verdict || next.note) ui.reviews[item.key] = next;
  else delete ui.reviews[item.key];
  saveReviews();
}

// #endregion

// #region Theme: a theme-light or theme-dark class on <html>

function currentTheme() {
  return document.documentElement.classList.contains("theme-dark") ? "dark" : "light";
}

function setTheme(theme) {
  document.documentElement.classList.remove("theme-light", "theme-dark");
  document.documentElement.classList.add(`theme-${theme}`);
  document.documentElement.dataset.systemTheme = "false";
  writeStored(THEME_KEY, theme);
  renderThemeToggle();
}

function renderThemeToggle() {
  const dark = currentTheme() === "dark";
  const button = $("theme-toggle");
  button.replaceChildren(icon(dark ? "sun" : "moon"));
  button.setAttribute("aria-label", dark ? "Switch to light theme" : "Switch to dark theme");
  button.title = button.getAttribute("aria-label");
}

window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", (event) => {
  if (document.documentElement.dataset.systemTheme !== "true") return;
  document.documentElement.classList.remove("theme-light", "theme-dark");
  document.documentElement.classList.add(event.matches ? "theme-dark" : "theme-light");
  renderThemeToggle();
});

// #endregion

// #region Formatting

function highestSeverity(row) {
  return SEVERITIES.find((s) => row.findings.some((f) => f.severity === s)) || null;
}

function providerFor(url) {
  return PROVIDERS.find((p) => p.matches(url || "")) || { title: hostOf(url) || "Custom", logo: "custom.svg", custom: true };
}

function hostOf(url) {
  try { return new URL(url).host; } catch { return url || ""; }
}

function duration(seconds) {
  if (seconds % 3600 === 0) return `${seconds / 3600}h`;
  if (seconds % 60 === 0) return `${seconds / 60}m`;
  return `${seconds}s`;
}

function daysSince(iso) {
  return Math.floor((Date.now() - new Date(iso)) / 86400000);
}

function relative(iso) {
  const days = daysSince(iso);
  if (days < 1) return "Today";
  if (days < 2) return "Yesterday";
  if (days < 60) return `${days} days ago`;
  if (days < 730) return `${Math.floor(days / 30)} months ago`;
  return `${Math.floor(days / 365)} years ago`;
}

function date(iso) {
  return iso ? new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "Never";
}

function safeHref(url) {
  try { return ["https:", "http:"].includes(new URL(url).protocol) ? url : null; } catch { return null; }
}

function plural(n, one, many = `${one}s`) {
  return `${n.toLocaleString()} ${n === 1 ? one : many}`;
}

function sourceLabel(source) {
  return { environment: "Environment", pasted: "Pasted" }[source] || source;
}

// Claim values with wildcards marked, so a broad pattern stands out while scanning.
function claimValue(value, wildcard) {
  if (!wildcard || !/[*?]/.test(value)) return el("span", {}, value);
  if (!value.replace(/[*?]/g, "")) return el("span", {}, el("mark", { class: "any", title: "Accepts any value" }, value));
  return el("span", {}, value.split(/([*?])/).filter(Boolean).map((part) =>
    part === "*" || part === "?" ? el("mark", { class: "wild", title: "Wildcard" }, part) : part));
}

// #endregion

// #region Preparing a report: everything derived from an identity, computed once

function prepare(report) {
  const position = new Map(report.workplaces.map((w, i) => [(w.workplace || {}).slug, i]));
  ui.items = report.identities.map((row) => {
    const severity = highestSeverity(row);
    const provider = providerFor(row.discovery_url);
    // Most serious finding first, and the most serious severity for each field it names.
    const findings = [...row.findings].sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));
    const flags = {};
    for (const f of findings) if (!flags[f.field]) flags[f.field] = f.severity;
    return {
      row,
      key: reviewKey(row),
      severity,
      findings,
      flags,
      rank: severity ? SEVERITIES.indexOf(severity) : SEVERITIES.length,
      provider,
      workplaceIndex: position.get(row.workplace_slug) ?? 0,
      text: [row.workplace_name, row.service_account_name, row.service_account_role, row.identity_name, row.discovery_url,
        provider.title, ...Object.entries(row.claims).flat(2), ...row.findings.map((f) => f.message)].join("\n").toLowerCase(),
    };
  });
  // Grouped by workplace, then the most serious automated finding first.
  ui.items.sort((a, b) => a.workplaceIndex - b.workplaceIndex || a.rank - b.rank
    || a.row.service_account_name.localeCompare(b.row.service_account_name) || a.row.identity_name.localeCompare(b.row.identity_name));
  ui.byWorkplace = new Map();
  for (const item of ui.items) {
    if (!ui.byWorkplace.has(item.row.workplace_slug)) ui.byWorkplace.set(item.row.workplace_slug, []);
    ui.byWorkplace.get(item.row.workplace_slug).push(item);
  }
}

// #endregion

// #region Page chrome: views, tokens, run button

function renderChrome() {
  const { state } = ui;
  const hasTokens = state.tokens.length > 0;
  $("setup-view").hidden = hasTokens;
  $("app-view").hidden = !hasTokens;
  if (!hasTokens) return;

  $("api-host").textContent = `Reading from ${state.api_host.replace("https://", "")}`;
  renderRunButton(state);
  renderTokens(state);
  renderSettings(state.settings);
  const hasReport = Boolean(ui.report);
  $("export-review").hidden = $("export-json").hidden = !hasReport;
  $("summary").hidden = $("results").hidden = !hasReport;
  if (!hasReport) $("errors").hidden = true;
  renderWaiting(state);
}

function renderRunButton(state) {
  const button = $("run-audit");
  if (isRunning()) {
    button.disabled = true;
    button.replaceChildren(icon("spinner", "spin"), `Auditing ${state.run.done} of ${state.run.total}`);
    button.title = `${plural(state.run.service_accounts || 0, "service account")} checked so far`;
  } else {
    button.disabled = false;
    button.title = "";
    button.replaceChildren(icon("sync"), ui.report ? "Run Again" : "Run Audit");
  }
}

// Before the first report exists, a callout stands in for the results.
function renderWaiting(state) {
  $("waiting").hidden = Boolean(ui.report);
  if (ui.report) return;
  const running = isRunning();
  $("waiting-icon").classList.toggle("spin", running);
  if (running) {
    $("waiting-title").textContent = "Auditing Workplaces";
    $("waiting-text").textContent = `Finished ${state.run.done} of ${plural(state.run.total, "workplace")}, `
      + `${plural(state.run.service_accounts || 0, "service account")} checked so far. Large workplaces can take a few `
      + "minutes, because Doppler limits how many API requests a token can make each minute.";
  } else if (state.run && state.run.error) {
    $("waiting-title").textContent = "The Audit Failed";
    $("waiting-text").textContent = state.run.error;
  } else {
    $("waiting-title").textContent = "Ready to Audit";
    $("waiting-text").textContent = `Run the audit to list every identity across ${plural(state.tokens.length, "workplace")}.`;
  }
}

// #region Settings: the CLI's flags, kept on the server

// Copies the server's settings into the form, unless you're part-way through editing it.
function renderSettings(settings) {
  const shown = JSON.stringify(settings);
  if (shown === ui.settingsShown || $("settings").contains(document.activeElement)) return;
  ui.settingsShown = shown;
  $("set-stale-days").value = settings.stale_days;
  $("set-max-ttl").value = settings.max_ttl_seconds / 60;
  $("set-concurrency").value = settings.concurrency;
  $("set-api-host").textContent = settings.api_host;
  $("set-dashboard-host").textContent = settings.dashboard_host;
  $("set-env-prefix").textContent = `${settings.env_prefix}<NAME>`;
}

async function saveSettings(values) {
  const message = $("settings-message");
  try {
    await api("/api/settings", values);
    message.classList.remove("error");
    message.textContent = ui.report ? "Saved. Findings were updated for the current results." : "Saved. They'll apply when the audit runs.";
    ui.settingsShown = null;
    document.activeElement?.blur();
    await refresh();
  } catch (error) {
    message.classList.add("error");
    message.textContent = error.message;
  }
}

function settingsFromForm() {
  return {
    stale_days: $("set-stale-days").value,
    max_ttl_seconds: $("set-max-ttl").value === "" ? "" : Math.round(Number($("set-max-ttl").value) * 60),
    concurrency: $("set-concurrency").value,
  };
}

// #endregion

// Token status → pill. "checking" and "ready" come from /v3/me when the token is added;
// "audited" and "failed" from the last audit.
const TOKEN_STATUS = {
  checking: () => el("span", { class: "pill" }, icon("spinner", "spin"), "Checking"),
  ready: () => pill("none", "Connected"),
  audited: () => pill("none", "Audited"),
  invalid: () => pill("high", "Invalid"),
  failed: () => pill("high", "Failed"),
  duplicate: () => pill("medium", "Duplicate"),
};

function renderTokens(state) {
  const tokens = state.tokens;
  $("token-count").textContent = tokens.length;
  $("token-rows").replaceChildren(...tokens.map((t) => el("div", { class: "tr body", role: "row" },
    el("div", { class: "td stack", role: "cell" },
      t.workplace
        ? [el("span", { class: "primary truncate" }, t.workplace.name), el("span", { class: "sub" }, t.workplace.slug)]
        : el("span", { class: "text-600" }, t.status === "checking" ? "Looking up workplace..." : "Unknown workplace")),
    el("div", { class: "td", role: "cell" }, t.label ? el("span", { class: "truncate" }, t.label) : el("span", { class: "text-600" }, "None")),
    el("div", { class: "td", role: "cell" }, el("span", { class: "typo-rxs" }, t.preview)),
    el("div", { class: "td", role: "cell" }, el("span", { class: "truncate" }, sourceLabel(t.source))),
    el("div", { class: t.error ? "td stack" : "td", role: "cell" },
      TOKEN_STATUS[t.status](),
      t.error ? el("span", { class: "sub break" }, t.error) : null),
    el("div", { class: "td end", role: "cell" }, el("button", {
      class: "btn ghost xs icon-only", type: "button", title: `Remove ${t.name}`, "aria-label": `Remove the token for ${t.name}`,
      onclick: async () => { await api("/api/tokens/remove", { id: t.id }); refresh(); },
    }, icon("times"))),
  )));
}

// #endregion

// #region Results: summary, filters, and whichever view is showing

function renderResults() {
  renderSummary();
  renderGuide();
  renderTabs();
  renderWorkplaceFilter();
  applyFilters();
  $("match-count").textContent = filtering()
    ? `${ui.filtered.length.toLocaleString()} of ${plural(ui.items.length, "identity", "identities")}`
    : plural(ui.items.length, "identity", "identities");
  $("list-view").hidden = !ui.filtered.length && filtering();
  $("no-matches").hidden = ui.filtered.length > 0 || !filtering();
  renderList();
}

function renderSummary() {
  const report = ui.report;
  const s = report.summary;
  let approved = 0;
  let flagged = 0;
  for (const item of ui.items) {
    const verdict = decisionOf(item).verdict;
    if (verdict === "approved") approved++;
    else if (verdict === "flagged") flagged++;
  }
  const total = ui.items.length;

  $("summary-subtitle").textContent = `Last run ${date(report.generated_at)}.`;
  const stat = (label, value, sub, cls = "", iconName = null) => el("div", { class: `stat ${cls}` },
    el("div", { class: "stat-label" }, iconName ? icon(iconName) : null, label),
    el("div", { class: "stat-value" }, value.toLocaleString()),
    el("div", { class: "stat-sub" }, sub));
  $("stats").replaceChildren(
    stat("Workplaces", s.workplaces - s.workplaces_failed, s.workplaces_failed ? `${s.workplaces_failed} failed` : `of ${s.workplaces} added`),
    stat("Identities", s.identities, `in ${plural(s.service_accounts_with_identities, "service account")}`),
    stat("Not reviewed", total - approved - flagged, total ? `${Math.floor((100 * (approved + flagged)) / total)}% done` : "Nothing to review", "", "review"),
    stat("Approved", approved, "Set up correctly", "approved", "approve"),
    stat("Flagged", flagged, "Need follow-up", "flagged", "flag"),
    stat("Automated findings", s.findings.high + s.findings.medium + s.findings.low,
      `${s.findings.high} high · ${s.findings.medium} medium · ${s.findings.low} low`, "", "high"),
  );

  const failed = report.workplaces.filter((w) => w.error);
  $("errors").hidden = failed.length === 0;
  $("errors-title").textContent = `${plural(failed.length, "workplace")} couldn't be audited.`;
  $("error-list").replaceChildren(...failed.map((w) =>
    el("li", {}, el("b", {}, w.workplace ? w.workplace.name : w.token_label || w.token_preview), ` (token ${w.token_label || w.token_preview}): ${w.error}`)));
}

// The guide to findings, from the rules the report was checked against.
function renderGuide() {
  const rules = ui.report.rules || [];
  $("guide").hidden = !rules.length;
  $("guide-body").hidden = !ui.guideOpen;
  $("guide-toggle").textContent = ui.guideOpen ? "Hide" : "Show";
  $("guide-toggle").setAttribute("aria-expanded", String(ui.guideOpen));
  $("rules-rows").replaceChildren(...rules.map((rule) => el("div", { class: "rules-row", role: "row" },
    el("span", { role: "cell" }, pill(rule.severity)),
    el("span", { role: "cell", class: "rule-title" }, rule.title),
    el("span", { role: "cell" }, rule.when),
    el("span", { role: "cell" }, rule.why))));
}

function setGuideOpen(open, scroll = false) {
  ui.guideOpen = open;
  writeStored(GUIDE_KEY, open ? "1" : "0");
  renderGuide();
  if (scroll) $("guide").scrollIntoView({ block: "start", behavior: "smooth" });
}

function renderTabs() {
  const counts = { all: ui.items.length, any: 0, none: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const item of ui.items) counts[item.severity || "none"]++;
  counts.any = counts.all - counts.none;
  const tabs = [["all", "All"], ["any", "With Findings"], ["high", "High"], ["medium", "Medium"], ["low", "Low"], ["none", "No Findings"]];
  if (counts.info) tabs.splice(4, 0, ["info", "Info"]);
  // Each tab: a rounded inner area holding the label and a count badge.
  $("severity-tabs").replaceChildren(...tabs.map(([key, label]) => el("button", {
    class: "tab", type: "button", role: "tab", "aria-selected": String(ui.severity === key),
    onclick: () => { ui.severity = key; renderResults(); },
  }, el("span", { class: "tab-inner" },
    el("span", { class: "tab-label", "data-label": label }, label),
    el("span", { class: "pill semibold tab-badge" }, counts[key].toLocaleString())))));
}

function renderWorkplaceFilter() {
  const select = $("workplace-filter");
  const current = select.value;
  const options = ui.report.workplaces.filter((w) => w.workplace && !w.error)
    .map((w) => el("option", { value: w.workplace.slug }, w.workplace.name));
  select.replaceChildren(el("option", { value: "" }, "All Workplaces"), ...options);
  select.value = options.some((o) => o.value === current) ? current : "";
}

function filtering() {
  return Boolean(ui.severity !== "all" || $("search").value.trim() || $("workplace-filter").value || $("decision-filter").value);
}

function applyFilters() {
  const severity = ui.severity;
  const workplace = $("workplace-filter").value;
  const decision = $("decision-filter").value;
  const query = $("search").value.trim().toLowerCase();
  ui.filtered = ui.items.filter((item) => {
    if (severity === "none" ? item.severity : severity === "any" ? !item.severity : severity !== "all" && item.severity !== severity) return false;
    if (workplace && item.row.workplace_slug !== workplace) return false;
    const d = decisionOf(item);
    if (decision && (d.verdict || "none") !== decision) return false;
    return !query || item.text.includes(query) || (d.note && d.note.toLowerCase().includes(query));
  });
}

// #endregion

// #region List view

const observer = new IntersectionObserver((entries) => {
  if (entries.some((e) => e.isIntersecting)) drawMore();
}, { root: $("grid-scroll"), rootMargin: "800px 0px" });

// Builds the row list for the current filters and draws the first batch. With
// keepPosition, enough rows are drawn to leave the scroll position where it was.
function renderList(keepPosition = false) {
  const target = keepPosition ? ui.drawn : 0;
  const showEmpty = !filtering();
  const visibleByWorkplace = new Map();
  for (const item of ui.filtered) {
    if (!visibleByWorkplace.has(item.row.workplace_slug)) visibleByWorkplace.set(item.row.workplace_slug, []);
    visibleByWorkplace.get(item.row.workplace_slug).push(item);
  }

  const entries = [];
  for (const workplace of ui.report.workplaces) {
    if (!workplace.workplace || workplace.error) continue;
    const slug = workplace.workplace.slug;
    if ($("workplace-filter").value && $("workplace-filter").value !== slug) continue;
    const visible = visibleByWorkplace.get(slug) || [];
    if (!visible.length && !showEmpty) continue;
    entries.push({ group: workplace, visible });
    if (ui.collapsed.has(slug)) continue;
    if (!(ui.byWorkplace.get(slug) || []).length) entries.push({ empty: true });
    for (const item of visible) entries.push({ item });
  }

  ui.entries = entries;
  ui.drawn = 0;
  ui.rowNodes.clear();
  ui.groupNodes.clear();
  $("grid-body").replaceChildren();
  if (!keepPosition) $("grid-scroll").scrollTop = 0;
  do drawMore(); while (ui.drawn < Math.min(target, ui.entries.length));
  const allCollapsed = ui.report.workplaces.every((w) => !w.workplace || w.error || ui.collapsed.has(w.workplace.slug));
  $("toggle-groups").textContent = allCollapsed ? "Expand All" : "Collapse All";
}

function drawMore() {
  const end = Math.min(ui.entries.length, ui.drawn + BATCH);
  if (ui.drawn >= end) return;
  const fragment = document.createDocumentFragment();
  for (; ui.drawn < end; ui.drawn++) {
    const entry = ui.entries[ui.drawn];
    if (entry.group) fragment.append(groupRow(entry.group, entry.visible));
    else if (entry.empty) fragment.append(el("div", { class: "grid-empty", role: "row" }, "No identities are configured in this workplace."));
    else {
      fragment.append(itemRow(entry.item));
      if (ui.open.has(entry.item.row.identity_slug)) fragment.append(detailRow(entry.item));
    }
  }
  $("grid-body").append(fragment);
  // Keep the sentinel observed only while there is more to draw.
  observer.disconnect();
  if (ui.drawn < ui.entries.length) observer.observe($("grid-sentinel"));
}

function groupRow(workplace, visible) {
  const slug = workplace.workplace.slug;
  const all = ui.byWorkplace.get(slug) || [];
  let approved = 0;
  let flagged = 0;
  for (const item of all) {
    const verdict = decisionOf(item).verdict;
    if (verdict === "approved") approved++;
    else if (verdict === "flagged") flagged++;
  }
  const collapsed = ui.collapsed.has(slug);
  const href = safeHref(`${ui.report.dashboard_host || "https://dashboard.doppler.com"}/workplace/${encodeURIComponent(slug)}/team/service_accounts`);
  const shown = filtering() ? ` · ${visible.length.toLocaleString()} shown` : "";
  const node = el("div", { class: `lgroup${collapsed ? " collapsed" : ""}`, role: "row" },
    el("button", {
      class: "toggle", type: "button", "aria-expanded": String(!collapsed),
      onclick: () => {
        if (collapsed) ui.collapsed.delete(slug); else ui.collapsed.add(slug);
        renderList(true);
      },
    }, icon("chevron"), workplace.workplace.name),
    el("span", { class: "pill outlined" }, slug),
    el("span", { class: "meta" }, `${plural(all.length, "identity", "identities")}${shown} · ${plural(workplace.service_accounts, "service account")}`),
    all.length ? el("span", { class: "counts" },
      decisionPill("approved", approved.toLocaleString()),
      decisionPill("flagged", flagged.toLocaleString()),
      decisionPill(null, `${(all.length - approved - flagged).toLocaleString()} not reviewed`)) : null,
    el("span", { class: "spacer" }),
    href ? el("a", { class: "btn ghost xs", href, target: "_blank", rel: "noopener noreferrer" }, icon("external"), "Open in Doppler") : null);
  ui.groupNodes.set(slug, { node, workplace, visible });
  return node;
}

// Approve and Flag toggle: choosing the current decision again clears it.
function decisionButtons(item, verdict) {
  const button = (value, iconName, label, color) => el("button", {
    class: `btn xs icon-only ${color} ${verdict === value ? "" : "outlined"}`, type: "button",
    "aria-pressed": String(verdict === value), "aria-label": `${label} ${item.row.identity_name}`,
    title: verdict === value ? `${label}: click again to clear` : label,
    onclick: (event) => { event.stopPropagation(); decide(item, value); },
  }, icon(iconName));
  return [button("approved", "approve", "Approve", ""), button("flagged", "flag", "Flag", "red")];
}

function itemRow(item) {
  const row = item.row;
  const decision = decisionOf(item);
  const options = ui.report.options || {};
  const wildcard = row.claims_type === "wildcard";
  const others = Object.entries(row.claims).filter(([k]) => k !== "aud" && k !== "sub");
  const elevated = ["Owner", "Admin"].includes(row.service_account_role);
  const longTtl = row.ttl_seconds > (options.max_ttl_seconds || 3600);
  const staleDays = options.stale_days || 90;
  const stale = row.last_seen_at ? daysSince(row.last_seen_at) > staleDays : daysSince(row.created_at) > staleDays;
  const isOpen = ui.open.has(row.identity_slug);
  const values = (list) => el("div", { class: "values" }, (list || []).map((v) => claimValue(v, wildcard)));

  const node = el("div", {
    class: `lrow item${isOpen ? " open" : ""}`, role: "row", "data-decision": decision.verdict || "none",
    onclick: (event) => { if (!event.target.closest("button, a")) toggleDetail(item); },
  },
    el("div", { role: "cell" }, el("div", { class: "decide" }, decisionButtons(item, decision.verdict))),
    el("div", { role: "cell" },
      el("span", { class: "name" }, row.identity_name),
      decision.note ? el("span", { class: "note-mark", title: decision.note }, icon("note")) : null,
      el("span", { class: "sub one-line", title: `${row.service_account_name} · ${row.service_account_role} role` },
        row.service_account_name, " · ", el("span", { class: elevated ? "warn-text" : "" }, row.service_account_role))),
    el("div", { role: "cell", title: row.discovery_url },
      el("span", { class: "provider" },
        el("span", { class: "provider-logo" }, el("img", { src: `/img/${item.provider.logo}`, alt: "" })),
        el("span", { class: "one-line" }, item.provider.title)),
      el("span", { class: "sub" }, wildcard ? "Wildcard match" : "Exact match")),
    el("div", { role: "cell" }, values(row.claims.aud)),
    el("div", { role: "cell" },
      values(row.claims.sub),
      others.length ? el("div", { class: "values other" }, others.map(([k, v]) => el("span", {},
        el("span", { class: "claim-key" }, `${k}: `), ...v.map((x, i) => [i ? ", " : "", claimValue(x, wildcard)])))) : null),
    el("div", { role: "cell", class: longTtl ? "warn-text" : "" }, duration(row.ttl_seconds)),
    el("div", { role: "cell", class: "nowrap", title: date(row.last_seen_at) },
      row.last_seen_at ? el("span", { class: stale ? "warn-text" : "" }, relative(row.last_seen_at))
        : el("span", { class: stale ? "warn-text" : "text-600" }, "Never")),
    el("div", { role: "cell", title: item.findings.map((f) => `${SEVERITY_PILLS[f.severity].label}: ${f.title}`).join("\n") },
      item.severity ? pill(item.severity) : el("span", { class: "text-600" }, "None"),
      item.findings.length ? el("span", { class: "finding-title" }, item.findings[0].title) : null,
      item.findings.length > 1 ? el("span", { class: "sub" }, `+${item.findings.length - 1} more`) : null),
    el("div", { role: "cell" }, el("button", {
      class: "btn ghost xs icon-only expand", type: "button", "aria-expanded": String(isOpen),
      "aria-label": `Details for ${row.identity_name}`, onclick: () => toggleDetail(item),
    }, icon("chevron"))),
  );
  ui.rowNodes.set(row.identity_slug, node);
  return node;
}

function detailRow(item) {
  const row = item.row;
  const decision = decisionOf(item);
  const href = safeHref(row.dashboard_url);
  return el("div", { class: "ldetail", role: "row", "data-detail": row.identity_slug },
    el("div", { role: "cell" },
      whyFlagged(item),
      el("div", { class: "ldetail-grid" },
        el("div", {},
          el("h4", { class: "detail-heading" }, "Details"),
          el("dl", { class: "info-list" },
            info("Issuer", row.discovery_url),
            info("Workplace", row.workplace_name),
            info("Token TTL", duration(row.ttl_seconds), item.flags.ttl),
            info("Created", date(row.created_at)),
            info("Last seen", date(row.last_seen_at), item.flags.last_seen),
            info("Identity ID", row.identity_slug, null, "typo-rxs")),
          href ? el("a", { class: "btn ghost xs open-link", href, target: "_blank", rel: "noopener noreferrer" }, icon("external"), "Open Service Account") : null),
        noteField(item, decision.note, `note-${row.identity_slug}`))));
}

// One label/value pair; a severity marks the value as the subject of a finding.
function info(label, value, severity = null, cls = "") {
  return [el("dt", {}, label), el("dd", { class: `${cls} ${severity ? `flagged ${severity}` : ""}`.trim() || null }, value)];
}

// Names each finding, says what triggered it and why it matters. Shown first in both
// detail views, so the reason an identity was flagged is the first thing you read.
function whyFlagged(item) {
  const rules = new Map((ui.report.rules || []).map((rule) => [rule.id, rule]));
  if (!item.findings.length) {
    return el("div", { class: "why" },
      el("h4", { class: "detail-heading" }, "Why It's Flagged"),
      el("div", { class: "why-none" }, icon("check"), "No automated findings. Still confirm the issuer and claims match the workload you expect."));
  }
  return el("div", { class: "why" },
    el("h4", { class: "detail-heading" }, `Why It's Flagged (${item.findings.length})`),
    item.findings.map((f) => el("div", { class: `why-item ${f.severity}` },
      pill(f.severity),
      el("div", {}, el("span", { class: "why-title" }, f.title), el("span", { class: "why-message" }, `: ${f.message}`)),
      rules.get(f.rule) ? el("p", { class: "why-reason" }, rules.get(f.rule).why) : null)));
}

function toggleDetail(item) {
  const slug = item.row.identity_slug;
  if (ui.open.has(slug)) {
    ui.open.delete(slug);
    $("grid-body").querySelector(`[data-detail="${CSS.escape(slug)}"]`)?.remove();
  } else {
    ui.open.add(slug);
    ui.rowNodes.get(slug)?.after(detailRow(item));
  }
  redrawItem(item);
}

// A decision redraws its own row, its workplace row and the summary, not the whole list.
function decide(item, verdict) {
  updateDecision(item, { verdict: decisionOf(item).verdict === verdict ? null : verdict });
  redrawItem(item);
  const group = ui.groupNodes.get(item.row.workplace_slug);
  if (group) group.node.replaceWith(groupRow(group.workplace, group.visible));
  renderSummary();
}

function redrawItem(item) {
  const node = ui.rowNodes.get(item.row.identity_slug);
  if (node) node.replaceWith(itemRow(item));
}

// Notes save as you type, without redrawing, so the cursor stays put.
function noteField(item, note, id) {
  return el("div", { class: "field" },
    el("label", { class: "field-label", for: id }, "Notes"),
    el("textarea", {
      class: "textarea prose", id, rows: "3", placeholder: "What you checked, or what needs to change",
      oninput: (event) => updateDecision(item, { note: event.target.value }),
      onchange: () => redrawItem(item),
    }, note));
}

// #endregion

// #region Review export: every identity with its decision and note, as CSV

function exportReview() {
  const columns = ["workplace", "workplace_slug", "service_account", "service_account_role", "identity", "identity_id",
    "issuer", "claim_matching", "claims", "token_ttl_seconds", "created_at", "last_seen_at", "automated_findings",
    "decision", "note", "updated_at", "dashboard_url"];
  const lines = [columns.join(",")];
  // Every identity, whatever the filters, so the file is a complete record.
  for (const item of ui.items) {
    const row = item.row;
    const decision = decisionOf(item);
    const values = [row.workplace_name, row.workplace_slug, row.service_account_name, row.service_account_role,
      row.identity_name, row.identity_slug, row.discovery_url, row.claims_type,
      Object.entries(row.claims).map(([k, v]) => `${k}=${v.join(" | ")}`).join("; "),
      row.ttl_seconds, row.created_at, row.last_seen_at || "",
      row.findings.map((f) => `[${f.severity}] ${f.message}`).join("; "),
      decision.verdict || "not reviewed", decision.note || "", decision.at || "", row.dashboard_url];
    lines.push(values.map(csvCell).join(","));
  }
  const blob = new Blob([`${lines.join("\r\n")}\r\n`], { type: "text/csv" });
  const link = el("a", { href: URL.createObjectURL(blob), download: `identity-review-${new Date().toISOString().slice(0, 10)}.csv` });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}

function csvCell(value) {
  let text = String(value ?? "");
  if (/^[=+\-@]/.test(text)) text = `'${text}`; // keep spreadsheets from running names as formulas
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

// #endregion

// #region Wiring

function wire() {
  expandIcons();
  renderThemeToggle();

  $("theme-toggle").addEventListener("click", () => setTheme(currentTheme() === "dark" ? "light" : "dark"));
  $("setup-start").addEventListener("click", startFromSetup);

  $("show-add").addEventListener("click", () => { $("add-form").hidden = false; $("token-input").focus(); });
  $("cancel-add").addEventListener("click", () => { $("add-form").hidden = true; setError("token-error", ""); });
  $("add-tokens").addEventListener("click", () => addTokens($("token-input").value));

  $("run-audit").addEventListener("click", runAudit);

  const clear = $("clear-tokens");
  clear.addEventListener("click", async () => {
    if (clear.dataset.confirm !== "1") {
      clear.dataset.confirm = "1";
      clear.textContent = "Click Again to Remove All";
      setTimeout(() => { clear.dataset.confirm = ""; clear.textContent = "Remove All Tokens"; }, 4000);
      return;
    }
    clear.dataset.confirm = "";
    clear.textContent = "Remove All Tokens";
    await api("/api/tokens/clear", {});
    refresh();
  });

  $("search").addEventListener("input", debounce(renderResults, 150));
  for (const id of ["workplace-filter", "decision-filter"]) {
    $(id).addEventListener("input", renderResults);
  }
  $("toggle-groups").addEventListener("click", () => {
    const slugs = ui.report.workplaces.filter((w) => w.workplace && !w.error).map((w) => w.workplace.slug);
    const collapseAll = slugs.some((slug) => !ui.collapsed.has(slug));
    ui.collapsed = new Set(collapseAll ? slugs : []);
    renderList();
  });
  $("export-review").addEventListener("click", exportReview);
  $("save-settings").addEventListener("click", () => saveSettings(settingsFromForm()));
  $("reset-settings").addEventListener("click", () => saveSettings(SETTING_DEFAULTS));
  for (const id of ["set-stale-days", "set-max-ttl", "set-concurrency"]) {
    $(id).addEventListener("keydown", (event) => { if (event.key === "Enter") saveSettings(settingsFromForm()); });
  }
  $("guide-toggle").addEventListener("click", () => setGuideOpen(!ui.guideOpen));
  $("show-guide").addEventListener("click", () => setGuideOpen(true, true));
  $("guide-settings-link").addEventListener("click", (event) => { event.preventDefault(); $("settings").scrollIntoView({ behavior: "smooth" }); $("set-stale-days").focus({ preventScroll: true }); });
  $("open-settings").addEventListener("click", (event) => { event.preventDefault(); $("settings").scrollIntoView({ behavior: "smooth" }); $("set-stale-days").focus({ preventScroll: true }); });
  // Flush a pending save if the page closes mid-debounce.
  window.addEventListener("pagehide", () => writeStored(REVIEW_KEY, JSON.stringify(ui.reviews)));

  refresh().catch((error) => {
    document.body.prepend(el("div", { class: "banner danger" }, icon("high"), `Can't reach the audit server: ${error.message}`));
  });
}

wire();

// #endregion
