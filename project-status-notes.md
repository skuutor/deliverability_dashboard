# Domain Health Checker — Status Notes (paused, resume-ready)

**Paused as of:** Sept 7, 2026. Reason: focusing effort elsewhere for now; will resume if Apollo moves forward.

**Where the files live:** `C:\Users\epich\deliverability_dashboard\` — includes `index.html`, `summary.js`, `detail.html`, `detail.js`, `checks.js`, `style.css`, `domains.json`, and `serve.ps1` (local server, see below).

**Key reference docs, also in that folder:**
- `domain-health-checker-spec.md` — the full functional spec, current as of the last edit
- `visual-design-brief.md` — the visual polish brief, already implemented and verified

---

## What this project is, in one paragraph

A portfolio artifact demonstrating hands-on AI-assisted building, built for an application to a Principal PM (Deliverability & Connectivity) role at Apollo.io. Built with Claude Code. Originally scoped broader (domain + mailbox health) but deliberately narrowed to **domain-side authentication and reputation checks only** — SPF, DKIM, DMARC, and two distinct blocklist checks — because that's the most objective, verifiable, honestly-demoable slice, and matches Apollo's own stated interest in restoring trust through visibility.

**App name: "Domain Health Checker"** (renamed from "Deliverability Health Dashboard" mid-build to match actual scope).

## Current status: functionally complete and visually polished, verified live

Everything below has been built AND manually verified running in the browser (not just claimed by Claude Code) — that verification discipline was a deliberate, repeated theme throughout the build.

### What it does
- Reads a list of ~10 sample domains from `domains.json` (no manual entry, no backend — pure static page)
- For each domain, runs 5 checks via live DNS-over-HTTPS lookups (Google's public DoH API, since no Node/Python is installed on this machine):
  1. **SPF** — includes real recursive `include:` chain traversal for the >10-lookup PermError rule (a regex bug here was found and fixed: word-boundary issue was matching "a" inside "~all")
  2. **DKIM** — probes common selectors or a user-supplied one; distinguishes "no selector found" (Inconclusive) from a confirmed empty/revoked key (Fail) — a false-positive bug here (stray wildcard TXT records on hubspot.com) was found and fixed
  3. **DMARC** — validates policy strength (p=reject/quarantine=pass, p=none=warning, missing/invalid=fail)
  4. **IP-based blocklist** (Spamhaus ZEN, Barracuda, SORBS) — derives candidate sending IPs from the SPF record (NOT from MX — an earlier version incorrectly used MX-derived IPs, which is inbound mail routing, not outbound; this was a significant catch and fix). Full CIDR-range checking doesn't scale in a client-side/no-backend tool (e.g. Stripe's SPF resolves to 200k+ addresses) — checks up to a hard query cap, and honestly reports "Inconclusive — infrastructure too large to fully verify without backend infrastructure" rather than faking a Pass or silently truncating.
  5. **SURBL Domain Blocklist** — added because it checks the domain itself (not IPs), which is actually tractable client-side with one query. Answers a genuinely different question than #4 (domain used as spam link-target vs. IP reputation) — labeled distinctly in the UI, not presented as equivalent.
- **No composite/weighted health score anywhere** — deliberate design principle, since composite scores are the specific credibility failure this whole product category struggles with (dashboards showing green while real inbox placement is bad). Instead: a plain pass count shown as **percentage first, X/5 count in parens** (e.g. "80% (4/5 passing)") — a transparent restatement of the count, not an opaque weighting.
- **"Inconclusive" is a first-class, honest result, not an error state** — shows up deliberately in three places (no derivable sending IP, oversized CIDR range, no DKIM selector found) rather than defaulting to a false Pass.

### UI structure
- **Zone 1 — Portfolio summary** (top of page): card-based stats, domain-level headline (X have failures / Y warnings / Z clean) + check-level breakdown (pass/fail counts per check type) — both real counts, not scores. Cards are clickable and filter the grid below.
- **Zone 2 — Summary grid** (the hero): rows = domains, columns = 5 checks, color-coded pill-badge cells (light bg + dark text per status). Sortable by column (domain=alpha, score=numeric, check columns=Fail>Warning>Inconclusive>Pass attention-ordering) and filterable by domain name text search.
- **Zone 3 — Drill-in detail**: clicking a domain does a full-page navigation (not a modal) to `detail.html`, showing full record detail per check plus templated (not auto-generated) fix suggestions for anything not passing. Back button returns to the grid. Uses the Cross-Document View Transitions API for a smooth grid→detail animation (Chromium-only, gracefully falls back to instant navigation elsewhere — safe, not a regression risk).

### Visual design (implemented and verified)
Cool/technical palette (light cool-gray background, near-black text, deep blue accent) rather than generic warm-SaaS defaults. Semantic status colors used consistently: green/amber/red plus a genuinely distinct slate gray for Inconclusive (not a fourth "bad" shade — it's a different category of answer). Real webfont via CDN (Google Fonts or similar) chosen deliberately — reasoning: the app already depends on Google's DoH API being reachable, so one more external request isn't a new category of fragility.

### Local dev setup
No Node/Python on this machine. A local server is required because opening `index.html` directly (`file://`) blocks the `fetch()` call to `domains.json`. **To run: `powershell -ExecutionPolicy Bypass -File C:\Users\epich\deliverability_dashboard\serve.ps1`** (or `cd` into the folder, run `.\serve.ps1`), then open `http://localhost:8000/` in Chrome. Leave that PowerShell window open while testing; `Ctrl+C` to stop.

### Sample data
`domains.json` has ~10 real domains (google.com, microsoft.com, github.com, stripe.com, hubspot.com, mailchimp.com, salesforce.com, example.com, example.net) plus **`dshfu24542.org`** — a deliberately unregistered domain included as a reliable "fully broken, 0/5" case, confirmed to return clean NXDOMAIN results rather than crashing.

---

## Explicitly out of scope (decided, not just deferred)

- Mailbox-level health (bounce rate, complaint rate, sending volume, warmup/reputation scores) — considered early, deliberately dropped to keep the project finishable and honest; domain auth is the stronger, more verifiable story
- Any backend, database, or hosted data source beyond the local JSON file — Google Drive integration was considered and explicitly rejected as solving the wrong problem (it would just be a fancier file-upload mechanism, not real domain discovery)
- BIMI checks
- True inbox placement / seed-list testing
- Full exhaustive CIDR-range blocklist checking — explicitly named as needing real backend infrastructure (persistent service, caching, paid/authenticated DNSBL access) to do properly; noted as a real, well-understood next step, not a gap to apologize for

---

## Real bugs found and fixed along the way (good interview material)

These are strong "AI built something wrong, I caught it" stories — arguably more valuable for the Apollo interview than the finished product itself:

1. **SPF regex bug** — missing word boundary caused `~all` to be misread as containing an `a` mechanism, inflating lookup counts and silently misclassifying microsoft.com as "Warning" instead of "Pass." Found by hand-tracing the actual chain, not by trusting Claude Code's claim it worked.
2. **DKIM false positive** — hubspot.com has stray wildcard TXT records under `*._domainkey` that aren't real DKIM keys; original matcher treated any TXT presence as a "revoked key" fail. Fixed by requiring actual DKIM-shaped content (`v=DKIM1` or a `p=` tag).
3. **The big one: MX vs. outbound sending infrastructure.** Claude Code initially built blocklist IP-derivation using MX records. **You personally caught this** — MX identifies where inbound mail is delivered, not what server sends outbound mail, which are frequently different infrastructure entirely. This wasn't a code bug Claude Code could self-detect; it required real deliverability domain knowledge to catch, and led to the SPF-derived redesign plus the honest CIDR-range-cap-and-message approach.
4. **PowerShell encoding bug** — em-dash characters in `serve.ps1` without a UTF-8 BOM crashed the script with confusing errors; fixed by keeping the script plain-ASCII.

---

## Next steps when you resume

1. **Re-verify everything still runs** — start with `serve.ps1`, confirm the grid loads clean (no console errors), spot-check a couple of domains against the bug-fix list above to confirm nothing regressed.
2. **Decide on hosting** — this was flagged but never resolved. Currently the app only runs locally via the PowerShell server; there's no shareable link. GitHub Pages is a strong candidate (free, simple, matches the static-site architecture) if you want to send Apollo a live URL instead of walking someone through a local setup.
3. **Consider reading the actual code yourself** — you've verified behavior thoroughly but hadn't sat down to read `checks.js` line-by-line as of the pause. Worth doing at least once before an interview, so you can speak to implementation details directly, not just outcomes.
4. **Prep the demo narrative** — a draft flow exists in `domain-health-checker-spec.md` under "Demo narrative." Worth rehearsing once hosting is sorted, hitting: the portfolio summary → grid → drill-in flow, the no-composite-score reasoning, and at least one of the four bugs above as a concrete "AI got this wrong, here's how I caught it" story.
5. **Not yet started:** the earlier Regie.ai Codex-built domain/mailbox provisioning automation was mentioned as your other existing AI-building example for the Apollo application — worth deciding how these two examples complement each other in your actual application materials, separate from this project.

---

## The bigger-picture note worth remembering

Today's build was also a real exercise in *not* vibe-coding: catching Claude Code's unverified claims repeatedly (the garbled "already done" messages that turned out to need correction), pushing back on scope creep before it got expensive (the mailbox-health tangent, caught and reversed), and — the standout moment — catching a genuine domain-knowledge error (MX vs. outbound) that Claude Code's own testing couldn't have caught, because it required expertise Claude Code doesn't have and you do. That pattern, more than any single feature, is the actual proof point this project was built to generate.
