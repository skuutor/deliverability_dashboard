"use strict";

const domainTitle = document.getElementById("domain-title");
const passCountEl = document.getElementById("pass-count");
const detailBody = document.getElementById("detail-body");

const CHECK_LABELS = {
  spf: "SPF",
  dkim: "DKIM",
  dmarc: "DMARC",
  blocklist: "Sending IP reputation",
  surbl: "SURBL Domain Blocklist",
};

const STATUS_LABEL = {
  pass: "Pass",
  warning: "Warning",
  fail: "Fail",
  inconclusive: "Inconclusive",
};

init();

async function init() {
  const params = new URLSearchParams(window.location.search);
  const domain = params.get("domain");
  const selector = params.get("selector") || undefined;

  if (!domain) {
    domainTitle.textContent = "No domain specified";
    detailBody.innerHTML = '<p><a href="index.html">Return to the summary grid</a> and click a domain.</p>';
    return;
  }

  domainTitle.textContent = domain;
  detailBody.innerHTML = "<p>Running checks…</p>";

  const result = await runAllChecks(domain, selector);
  render(result);
}

function render(result) {
  const percent = Math.round((result.passCount / result.totalChecks) * 100);
  passCountEl.textContent = `${percent}% (${result.passCount}/${result.totalChecks} passing)`;

  detailBody.innerHTML = "";
  ["spf", "dkim", "dmarc", "blocklist", "surbl"].forEach((key) => {
    const check = result.checks[key];
    const section = document.createElement("section");
    section.className = `check-section check-${check.status}`;

    const heading = document.createElement("h2");
    const nameSpan = document.createElement("span");
    nameSpan.textContent = CHECK_LABELS[key];
    const pill = document.createElement("span");
    pill.className = `pill pill-${check.status}`;
    pill.textContent = STATUS_LABEL[check.status] || check.status;
    heading.appendChild(nameSpan);
    heading.appendChild(pill);
    section.appendChild(heading);

    if (check.notes && check.notes.length) {
      const ul = document.createElement("ul");
      check.notes.forEach((n) => {
        const li = document.createElement("li");
        li.textContent = n;
        ul.appendChild(li);
      });
      section.appendChild(ul);
    }

    if (check.raw && check.raw.length) {
      const label = document.createElement("div");
      label.className = "record-label";
      label.textContent = `Raw record${check.raw.length > 1 ? "s" : ""}`;
      section.appendChild(label);
      check.raw.forEach((r) => {
        const box = document.createElement("div");
        box.className = "record-box";
        box.textContent = r;
        section.appendChild(box);
      });
    }

    const fix = getFixSuggestion(check);
    if (fix) {
      const fixBox = document.createElement("div");
      fixBox.className = "fix-box";
      fixBox.innerHTML = "<strong>Suggested fix:</strong> " + escapeHtml(fix);
      section.appendChild(fixBox);
    }

    detailBody.appendChild(section);
  });
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}
