# Domain Health Checker — Spec

**App title (as of this revision): "Domain Health Checker"** — renamed from "Deliverability Health Dashboard" to accurately reflect scope: this tool checks domain-side authentication and reputation signals only (SPF/DKIM/DMARC + two blocklist checks). It does not cover mailbox-level health, sending volume, or reputation scoring — "Dashboard" implied broader scope than what's actually built, so the name was corrected to match reality rather than aspiration.

**Purpose:** Portfolio artifact demonstrating hands-on AI-assisted building, for an Apollo.io Principal PM (Deliverability & Connectivity) application. Not a production tool — a focused, honest, demoable prototype.

**Positioning:** Apollo's own job posting emphasizes restoring trust, partly through visibility. Domain authentication status is the most objective, verifiable expression of that — live DNS data, no ambiguity, no black-box scoring. This tool deliberately does ONE thing well rather than sprawling into mailbox health, warmup, or reputation scoring (see "Explicitly out of scope" below).

**Design principle: "Inconclusive" is a first-class, honest result — not an error or a fallback.** This shows up repeatedly across the checks below: no MX/no derivable sending IP, a DKIM selector that can't be found, a CIDR range too large to fully verify, a DNSBL that rate-limits public resolvers. In each case, the tool reports what it genuinely couldn't determine rather than defaulting to a false Pass or a confusing crash. This is the same instinct that motivated dropping a composite health score — false precision is the credibility failure mode this whole product category struggles with, and this tool is built to avoid it deliberately, at every layer.

## Product shape: multi-domain dashboard, not single lookup

Revised from the original single-domain-entry version. The experience is now:

1. **Summary view (first screen):** a grid — rows are domains (read from a local JSON file, not manually entered), columns are the four check types (SPF / DKIM / DMARC / Blocklist), cells show pass/warning/fail status color-coded. This gives a high-level view of issues across all domains and all check areas at a glance — matches the row-per-account, column-per-signal layout used by Smartlead/Instantly's own account health views.
2. **Drill-in view:** clicking any domain (or any failing cell) does a **full page swap** to that domain's detail view — the specific DNS records found, why each check passed/warned/failed, and a suggested fix for anything not passing. Includes a back button to return to the summary grid. (Not a modal/side panel — simpler state management, cleaner to build and demo.)

### Build sequencing

**Functional first, polish after.** Get the grid rendering real, correct data from all 10 domains — including the drill-in flow working end to end — before spending any time on visual design. The existing single-domain-lookup UI ("clean card-based UI, color-coded status badges") was built for the old flow and does not carry over structurally; this is a new page shape, not a restyle. Once the grid + drill-in are functionally solid, revisit visual polish using the Smartlead/Instantly reference patterns discussed earlier (color-coded status per row, aggregate view first, detail on demand) as the design touchstone — don't invent a layout from scratch.

### Domain source (settled)

A local JSON file, e.g. `domains.json`, sitting alongside `index.html` and fetched client-side on page load. No backend, no auth, no external service — consistent with the static-page architecture. Shape:

```json
{
  "domains": [
    { "domain": "example.com", "dkimSelector": "google" },
    { "domain": "another-example.com" }
  ]
}
```

`dkimSelector` is optional per-domain — if omitted, fall back to probing common selectors as already specced below.

Sample data: **8-10 domains**, enough to make the summary grid look like a real portfolio rather than a toy list, small enough to narrate individually in a demo. Mix healthy, warning, and failing domains deliberately so the grid isn't monotonous — this is demo data, so design it to tell a story (e.g., 1-2 fully clean, a few with one issue each, 1 clearly broken).

One domain (`dshfu24542.org`) is an intentionally unregistered/nonexistent domain, included as a reliable "fully broken" case rather than hoping a real domain happens to be misconfigured. **Important:** confirm this actually returns a clean NXDOMAIN / no-records result from the DoH lookups rather than an unhandled error — the UI must distinguish "confirmed no record" from "lookup failed," per the honesty requirement below. Don't assume it works; test it.

### Suggested fixes (settled: templated, not generated)

For any check that's a warning or fail, show templated guidance keyed to the specific failure type — not an attempt to generate a corrected DNS record. E.g.:

- SPF `~all` → "Your SPF record uses a soft fail (`~all`), which flags suspicious mail but doesn't block it. Consider `-all` once you've confirmed all legitimate senders are included."
- DMARC `p=none` → "Your DMARC policy is set to monitor-only (`p=none`). Violations are logged but not blocked. Consider moving to `p=quarantine` to start enforcing once you're confident in your reporting data."
- DKIM no selector found → "No DKIM record found under common selectors. This may mean DKIM isn't configured, or it's using a custom selector — check with your ESP for the correct selector name."
- Blocklist hit → "This domain is listed on [blocklist name]. Visit their delisting process to request removal after resolving the underlying issue."

One template per distinct failure state identified in the checks below — write these out explicitly as a lookup table/object in the code, not generated dynamically, so they're predictable and reviewable.

---

## What it checks

Given a domain (and optional DKIM selector), run five checks via live DNS-over-HTTPS lookups (`https://dns.google/resolve`):

1. **SPF**
   - Missing → fail
   - Multiple SPF records → fail (invalid per RFC 7208)
   - `+all` or bare `all` → fail (insecure — allows anyone to send)
   - `?all` → warning (neutral, effectively no protection)
   - `~all` → warning (soft fail — present but weak)
   - `-all` → pass (hard fail — correctly configured)
   - \>10 DNS lookups when recursively counting `include:` chains → warning (PermError risk per RFC 7208). **Must actually recurse into includes, not just count top-level mechanisms — verify this in the code, don't take it on faith.**

2. **DKIM**
   - No fixed DNS location exists for DKIM — it lives at `<selector>._domainkey.<domain>`, and the selector is arbitrary.
   - If the user supplies a selector, check that one directly.
   - If not, probe a list of common provider selectors (google, selector1, selector2, default, k1, s1, s2, etc.)
   - **Critical honesty requirement:** if no common selector resolves, the result must read as "No common selector found — DKIM may still be configured under a custom selector" (inconclusive), never "DKIM: Missing." Those are different findings and conflating them is a credibility risk with anyone deliverability-literate.
   - If a selector resolves but the key is empty/revoked, flag as misconfigured (this is a real, specific failure mode — not the same as "not found").

3. **DMARC**
   - Missing or invalid `p=` policy → fail
   - `p=none` → warning (monitoring-only, no enforcement)
   - `p=quarantine` or `p=reject` → pass
   - Missing `rua=` (aggregate reporting address) → note, not a hard fail

4. **Blocklist status — two distinct checks, not one**

   **4a. IP-based (Spamhaus ZEN, Barracuda, SORBS) — kept, with honest messaging about its real limitation**
   - DNSBLs list IP addresses, not domains, so checking requires an actual sending IP to query. **MX records are the wrong source for this** — MX identifies inbound mail servers, not outbound sending infrastructure, which is frequently different (e.g., inbound via Google Workspace, outbound via a separate ESP). An earlier build mistakenly used MX-derived IPs here; this was caught and corrected.
   - **Correct source: derive candidate IPs from the SPF record** (`ip4:`/`ip6:` entries, plus `include:` chains resolved recursively — reuse the SPF lookup-count traversal).
   - **Confirmed finding: full CIDR-range checking does not scale in this architecture.** Real ESP infrastructure can span enormous ranges (Stripe's SPF alone resolves to 200k+ addresses) — checking exhaustively would mean tens or hundreds of thousands of live DNS queries per page load, from a browser, with no backend, no caching, and DNSBLs that already rate-limit far smaller volumes. This is not a "raise the cap" problem; it is a correct recognition that exhaustive IP-level checking does not belong in a static, serverless, client-side tool. A production version would need a persistent backend service with caching and (likely paid/authenticated) DNSBL access, checking known ESP ranges periodically rather than live per request — call this out explicitly as a stated next step, not a gap to apologize for.
   - **Policy for the prototype:** check up to a hard query cap per domain (small — this will rarely fully clear real ESP ranges, and that's expected). If the cap is hit before the range is fully checked, the UI must say so explicitly and specifically — e.g. "Inconclusive — this domain's sending infrastructure is too large to fully verify without backend infrastructure (see note)" — not a generic "Inconclusive," and never a silent truncation or a false Pass.
   - No SPF record, or an SPF record with no resolvable IPs → also Inconclusive, but with different, accurate messaging (no sending IP found at all, distinct from range-too-large).

   **4b. Domain-based (SURBL) — new, added because it's actually tractable client-side**
   - Checks whether the domain itself appears in spam *content* (e.g., used as a spam link/redirect target) — a genuinely different signal from IP reputation, not a substitute for it. A domain can be SURBL-clean while its sending IPs are blocklisted, and vice versa.
   - One domain-based DNS query, not thousands of IP-based ones — this is what makes it practical in this architecture where 4a structurally isn't.
   - Spamhaus DBL was considered and rejected: it rejects public-resolver traffic the same way ZEN does. SURBL does not have this restriction and is confirmed usable here.
   - **UI must label this distinctly from 4a** — do not present SURBL results as if they mean the same thing as an IP blocklist pass/fail. Something like "Domain reputation (SURBL)" as a separate labeled row/section from "Sending IP reputation," so the two different questions being answered stay legible to the user.

## Overall status display

Show a simple pass count out of the actual number of checks (5: SPF, DKIM, DMARC, IP-based blocklist, SURBL domain reputation) as a **percentage first, with the X/5 count following in parentheses** — e.g. "80% (4/5 passing)." The percentage is a direct, transparent restatement of the same count, not a separately-weighted score — displaying it first is a presentation choice, not a signal that it's computed differently or carries independent meaning. Each individual check keeps its own clear status (pass / warning / fail / inconclusive), color-coded, fully visible in the grid — the percentage summarizes what's already shown, it doesn't replace or obscure it. Update the summary grid to 5 columns, not 4.

Rationale for the count/percentage (not a weighted composite): composite deliverability scores are the specific credibility failure mode of this entire product category — dashboards showing green while real inbox placement is bad. The distinction that keeps this honest: a weighted single number that hides how it was computed is the problem; a plain count (and its equivalent percentage) that sits next to fully visible per-check detail is not — nothing here obscures which checks passed or why. Be ready to explain this distinction if asked why there's a percentage but no "health score."

## Column: SURBL label

Label this column/section "SURBL Domain Blocklist" (not bare "SURBL") so it reads clearly to anyone unfamiliar with the term.

## Portfolio summary (top of page, above the grid)

Added for the same reason as sort/filter: at real scale (hundreds of domains), someone needs to gauge overall extent of issues at a glance, before scrolling or filtering.

**This must stay a count, not a composite score** — same principle as the per-domain percentage: aggregating hundreds of domains' worth of pass/fail/warning/inconclusive into one portfolio-wide percentage would require an opaque weighting judgment (whose failure counts more?) and reintroduces exactly the false-precision problem this tool has deliberately avoided everywhere else. Counts stay traceable back to the grid; a single blended score would not.

- **Domain-level headline:** count of domains by worst status present — e.g. "12 domains have failures, 34 have warnings, 8 fully clean, X inconclusive." (Decide the exact bucketing logic: likely "has ≥1 Fail" > "has ≥1 Warning, no Fail" > "fully Pass, no Warning/Fail/Inconclusive" > remaining Inconclusive-only cases — document whatever hierarchy is chosen so it's not ambiguous in the code.)
- **Check-level breakdown:** one line per check type (SPF, DKIM, DMARC, IP Blocklist, SURBL) with its own pass/warning/fail/inconclusive counts — this answers a different question than the headline (e.g. "DMARC is failing across many domains" is a distinct, useful finding from "12 domains have some failure somewhere").
- **Clickable:** clicking any summary stat (e.g. "12 domains have failures") applies the corresponding filter to the grid below, reusing the same filter mechanism specced under Sort and Filter — not a second, separate filtering system.

## Sort and filter (summary grid)

Added because a real version of this tool would have hundreds of domains, and an unsortable, unfilterable grid at that scale looks unscoped, not simple.

- **Filter:** a text input to find a specific domain by name (substring match against the domain column).
- **Column sort, click-to-sort on any column header:**
  - Domain column → alphabetical
  - Checks Passed / percentage column → numerical
  - All other (check-result) columns → sort by attention-worthiness, in this order: **Fail, Warning, Inconclusive, Pass.** Note: this ordering surfaces things that need attention first — it is not a claim that Inconclusive is "worse" than Pass in a health sense, just that it's something a user would want to look at before a clean Pass. Worth being able to explain this distinction if asked, consistent with treating Inconclusive as a first-class, honest result rather than a failure state.

## Explicitly out of scope for this build

Decided against, to keep this finishable and focused:

- Mailbox-level health (bounce rate, complaint rate, sending volume, warmup status, reputation score)
- Any backend, database, or hosted data source (Google Drive, published Sheet, API) — this stays a static page with no server
- BIMI checks
- Inbox placement / seed-list testing (would require real infrastructure this prototype doesn't have)
- Composite numeric health score

These can be named as "where I'd extend this next" in a demo narrative without being built.

## Architecture (already built, confirmed working)

- Pure static page: `index.html`, `style.css`, `app.js` — no build step, no dependencies, no server
- DNS lookups via Google's public DNS-over-HTTPS API, called directly from the browser (chosen because no Node.js/Python is installed on the build machine — a real constraint that shaped a real architecture decision, worth narrating as-is in an interview)
- Client-side only: no calculation of anything from raw event data (this tool has no raw event data — it only ever queries and displays live DNS state)

## Demo narrative (draft)

1. Open the page — summary grid loads immediately from the sample JSON, 8-10 domains × 5 checks, color-coded at a glance.
2. Point out the pattern: most domains clean or with isolated issues, one clearly broken — this is what "visibility across a portfolio" looks like.
3. Click into a failing domain — walk through the drill-in detail and the templated fix suggestion.
4. Explain the "X of 5 checks passing" + percentage choice per domain — a transparent restatement of the count, not a hidden weighted score — and why every underlying check stays fully visible rather than being collapsed into an opaque number.
5. Walk through the two-part blocklist story specifically: IP-based checking is real but architecturally capped (explain why — CIDR ranges too large for a client-side tool, e.g. Stripe's 200k+ addresses), and SURBL domain reputation is a different, tractable signal added alongside it. This is a good moment to explain the MX→SPF correction and the cap investigation as real problem-solving, not just describe finished features.
6. Mention the JSON-driven data source as a deliberate, honest choice for a prototype (not pretending to have a live client/API) while being clear about how this would connect to real infrastructure in production.
7. Name what's next (mailbox health, real backend with caching for full IP-range blocklist checks, live client data) as clear-eyed scoping, not a gap.

## Open verification items (from earlier build)

Carried over from the first build pass — confirm before considering this "done":
- Does the SPF check actually recurse into `include:` chains for the >10 lookup rule, or just count the top-level record?
- Confirm the DKIM "no common selector found" state is displayed distinctly from "DKIM missing."
- Confirm DoH failures (network/rate-limit) are distinguished from genuine "no record found" in the UI.
