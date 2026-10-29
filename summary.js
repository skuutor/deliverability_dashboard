"use strict";

const loadStatus = document.getElementById("load-status");
const portfolioSummary = document.getElementById("portfolio-summary");
const summaryEyebrow = document.getElementById("summary-eyebrow");
const summaryHeadline = document.getElementById("summary-headline");
const summaryBreakdown = document.getElementById("summary-breakdown");
const gridControls = document.getElementById("grid-controls");
const grid = document.getElementById("grid");
const gridBody = document.getElementById("grid-body");
const filterInput = document.getElementById("domain-filter");
const activeFilterEl = document.getElementById("active-filter");
const activeFilterText = document.getElementById("active-filter-text");
const clearFilterBtn = document.getElementById("clear-filter-btn");
const sortableHeaders = document.querySelectorAll("#grid thead th[data-sort-key]");

const STATUS_LABEL = {
  pass: "Pass",
  warning: "Warning",
  fail: "Fail",
  inconclusive: "Inconclusive",
};

const CHECK_LABEL = {
  spf: "SPF",
  dkim: "DKIM",
  dmarc: "DMARC",
  blocklist: "IP Blocklist",
  surbl: "SURBL Domain Blocklist",
};

const CHECK_COLUMNS = ["spf", "dkim", "dmarc", "blocklist", "surbl"];

// Sort order for check-result columns: things needing attention surface
// first. This is NOT a claim that Inconclusive is worse than Pass in a
// health sense — just that it's something worth looking at before a clean
// Pass, consistent with treating Inconclusive as a first-class honest
// result rather than a failure state.
const STATUS_ATTENTION_RANK = { fail: 0, warning: 1, inconclusive: 2, pass: 3 };

const BUCKET_LABEL = {
  fail: "have failures",
  warning: "have warnings",
  clean: "fully clean",
  inconclusive: "have inconclusive results",
};

let allResults = [];
let sortState = { key: null, dir: "asc" };

// filterState is exactly one of:
//   { type: "none" }
//   { type: "text", value: "<lowercased substring>" }
//   { type: "stat", kind: "domainBucket", bucket: "fail"|"warning"|"clean"|"inconclusive" }
//   { type: "stat", kind: "checkStatus", check: "<key>", status: "<status>" }
// Only one filter is ever active — clicking a summary stat overrides
// whatever text filter was typed, and typing overrides an active stat
// filter, rather than the two combining.
let filterState = { type: "none" };

init();

async function init() {
  let domainsConfig;
  try {
    const res = await fetch("domains.json");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    domainsConfig = await res.json();
  } catch (err) {
    loadStatus.textContent = "Failed to load domains.json: " + err.message;
    return;
  }

  const entries = domainsConfig.domains || [];
  if (entries.length === 0) {
    loadStatus.textContent = "domains.json has no domains listed.";
    return;
  }

  loadStatus.textContent = `Running checks for ${entries.length} domains…`;

  allResults = await Promise.all(
    entries.map((e) => runAllChecks(e.domain, e.dkimSelector))
  );

  loadStatus.hidden = true;
  portfolioSummary.hidden = false;
  gridControls.hidden = false;
  grid.hidden = false;

  renderPortfolioSummary();
  renderGrid();

  filterInput.addEventListener("input", () => {
    filterState = { type: "text", value: filterInput.value.trim().toLowerCase() };
    renderActiveFilterIndicator();
    renderPortfolioSummary();
    renderGrid();
  });

  clearFilterBtn.addEventListener("click", () => {
    filterState = { type: "none" };
    filterInput.value = "";
    renderActiveFilterIndicator();
    renderPortfolioSummary();
    renderGrid();
  });

  sortableHeaders.forEach((th) => {
    th.addEventListener("click", () => {
      const key = th.dataset.sortKey;
      if (sortState.key === key) {
        sortState.dir = sortState.dir === "asc" ? "desc" : "asc";
      } else {
        sortState = { key, dir: "asc" };
      }
      updateSortIndicators();
      renderGrid();
    });
  });
}

// --- Domain-level bucketing --------------------------------------------
// Each of the four stats is an independent "does this domain have at least
// one check in this state" predicate (same simple model the per-check
// breakdown stats already use) — not a mutually-exclusive "worst status"
// hierarchy. A domain with both a Fail and an Inconclusive result counts
// under both "have failures" and "have inconclusive results"; the four
// counts are not required to sum to the domain count. "Clean" is the one
// exception, since "every check passed" is inherently exclusive of the
// other three.
function domainHasStatus(result, status) {
  return CHECK_COLUMNS.some((key) => result.checks[key].status === status);
}

function domainIsFullyClean(result) {
  return CHECK_COLUMNS.every((key) => result.checks[key].status === "pass");
}

function matchesDomainBucket(result, bucket) {
  return bucket === "clean" ? domainIsFullyClean(result) : domainHasStatus(result, bucket);
}

function getCheckBreakdown() {
  const breakdown = {};
  CHECK_COLUMNS.forEach((key) => {
    breakdown[key] = { pass: 0, warning: 0, fail: 0, inconclusive: 0 };
  });
  allResults.forEach((r) => {
    CHECK_COLUMNS.forEach((key) => {
      breakdown[key][r.checks[key].status]++;
    });
  });
  return breakdown;
}

function statButton(text, className, onClick) {
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = className;
  btn.textContent = text;
  btn.addEventListener("click", onClick);
  return btn;
}

function isActiveDomainBucket(bucket) {
  return filterState.type === "stat" && filterState.kind === "domainBucket" && filterState.bucket === bucket;
}

function isActiveCheckStatus(check, status) {
  return filterState.type === "stat" && filterState.kind === "checkStatus" && filterState.check === check && filterState.status === status;
}

function onDomainBucketClick(bucket) {
  if (isActiveDomainBucket(bucket)) {
    filterState = { type: "none" };
  } else {
    filterState = { type: "stat", kind: "domainBucket", bucket };
  }
  filterInput.value = "";
  renderActiveFilterIndicator();
  renderPortfolioSummary();
  renderGrid();
}

function onCheckStatusClick(check, status) {
  if (isActiveCheckStatus(check, status)) {
    filterState = { type: "none" };
  } else {
    filterState = { type: "stat", kind: "checkStatus", check, status };
  }
  filterInput.value = "";
  renderActiveFilterIndicator();
  renderPortfolioSummary();
  renderGrid();
}

function renderPortfolioSummary() {
  const domainCount = allResults.length;
  const buckets = {
    fail: allResults.filter((r) => matchesDomainBucket(r, "fail")).length,
    warning: allResults.filter((r) => matchesDomainBucket(r, "warning")).length,
    clean: allResults.filter((r) => matchesDomainBucket(r, "clean")).length,
    inconclusive: allResults.filter((r) => matchesDomainBucket(r, "inconclusive")).length,
  };

  summaryEyebrow.textContent = `${domainCount} domains checked`;

  summaryHeadline.innerHTML = "";
  ["fail", "warning", "clean", "inconclusive"].forEach((bucket) => {
    const card = statButton(
      "",
      `headline-card headline-card-${bucket}${isActiveDomainBucket(bucket) ? " stat-btn-active" : ""}`,
      () => onDomainBucketClick(bucket)
    );
    const value = document.createElement("div");
    value.className = "headline-card-value";
    value.textContent = String(buckets[bucket]);
    const label = document.createElement("div");
    label.className = "headline-card-label";
    label.textContent = BUCKET_LABEL[bucket];
    card.appendChild(value);
    card.appendChild(label);
    summaryHeadline.appendChild(card);
  });

  const breakdown = getCheckBreakdown();
  summaryBreakdown.innerHTML = "";
  CHECK_COLUMNS.forEach((key) => {
    const line = document.createElement("div");
    line.className = "summary-breakdown-line";
    const label = document.createElement("span");
    label.className = "summary-breakdown-label";
    label.textContent = CHECK_LABEL[key];
    line.appendChild(label);

    ["pass", "warning", "fail", "inconclusive"].forEach((status) => {
      const btn = statButton(
        `${breakdown[key][status]} ${STATUS_LABEL[status]}`,
        `mini-stat mini-stat-${status}${isActiveCheckStatus(key, status) ? " stat-btn-active" : ""}`,
        () => onCheckStatusClick(key, status)
      );
      line.appendChild(btn);
    });

    summaryBreakdown.appendChild(line);
  });
}

function renderActiveFilterIndicator() {
  if (filterState.type === "stat") {
    const label = filterState.kind === "domainBucket"
      ? `Domains that ${BUCKET_LABEL[filterState.bucket]}`
      : `${CHECK_LABEL[filterState.check]}: ${STATUS_LABEL[filterState.status]}`;
    activeFilterText.textContent = `Filtered: ${label}`;
    activeFilterEl.hidden = false;
  } else {
    activeFilterEl.hidden = true;
  }
}

function updateSortIndicators() {
  sortableHeaders.forEach((th) => {
    const label = th.dataset.label;
    if (th.dataset.sortKey === sortState.key) {
      th.textContent = `${label} ${sortState.dir === "asc" ? "▲" : "▼"}`;
    } else {
      th.textContent = label;
    }
  });
}

function compareResults(a, b, key) {
  if (key === "domain") {
    return a.domain.localeCompare(b.domain);
  }
  if (key === "passCount") {
    return a.passCount - b.passCount;
  }
  return STATUS_ATTENTION_RANK[a.checks[key].status] - STATUS_ATTENTION_RANK[b.checks[key].status];
}

function getDisplayResults() {
  let list = allResults;

  if (filterState.type === "text" && filterState.value) {
    list = list.filter((r) => r.domain.toLowerCase().includes(filterState.value));
  } else if (filterState.type === "stat") {
    if (filterState.kind === "domainBucket") {
      list = list.filter((r) => matchesDomainBucket(r, filterState.bucket));
    } else {
      list = list.filter((r) => r.checks[filterState.check].status === filterState.status);
    }
  }

  if (sortState.key) {
    list = [...list].sort((a, b) => {
      const cmp = compareResults(a, b, sortState.key);
      return sortState.dir === "asc" ? cmp : -cmp;
    });
  }
  return list;
}

function renderGrid() {
  const results = getDisplayResults();
  gridBody.innerHTML = "";

  if (results.length === 0) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 7;
    td.textContent = "No domains match this filter.";
    tr.appendChild(td);
    gridBody.appendChild(tr);
    return;
  }

  for (const result of results) {
    const tr = document.createElement("tr");

    const domainTd = document.createElement("td");
    domainTd.className = "domain-cell";
    const link = document.createElement("a");
    const params = new URLSearchParams({ domain: result.domain });
    if (result.dkimSelector) params.set("selector", result.dkimSelector);
    link.href = `detail.html?${params.toString()}`;
    link.textContent = result.domain;
    domainTd.appendChild(link);
    tr.appendChild(domainTd);

    CHECK_COLUMNS.forEach((key) => {
      const td = document.createElement("td");
      td.className = "cell";
      const cellLink = document.createElement("a");
      cellLink.href = `detail.html?${params.toString()}`;
      const pill = document.createElement("span");
      pill.className = `pill pill-${result.checks[key].status}`;
      pill.textContent = STATUS_LABEL[result.checks[key].status] || result.checks[key].status;
      cellLink.appendChild(pill);
      td.appendChild(cellLink);
      tr.appendChild(td);
    });

    const countTd = document.createElement("td");
    countTd.className = "cell-count";
    const countLink = document.createElement("a");
    countLink.href = `detail.html?${params.toString()}`;
    const percent = Math.round((result.passCount / result.totalChecks) * 100);
    const percentSpan = document.createElement("span");
    percentSpan.className = "score-percent";
    percentSpan.textContent = `${percent}%`;
    const fractionSpan = document.createElement("span");
    fractionSpan.className = "score-fraction";
    fractionSpan.textContent = `(${result.passCount}/${result.totalChecks} passing)`;
    countLink.appendChild(percentSpan);
    countLink.appendChild(fractionSpan);
    countTd.appendChild(countLink);
    tr.appendChild(countTd);

    gridBody.appendChild(tr);
  }
}
