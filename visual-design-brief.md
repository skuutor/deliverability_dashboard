# Domain Health Checker — Visual Design Brief

For the polish pass, now that functionality across all three page zones is verified complete: portfolio summary, summary grid, and drill-in detail.

## Reference mock (approved)

A visual mock of zones 1 and 2 together was reviewed and approved before this brief was finalized. Key concrete choices confirmed there, worth matching:

- **Summary cards use a left-border color accent (not a filled colored background)** — thin 3px colored left border on an otherwise neutral card, so status color is visible but doesn't dominate. This is the concrete version of "restraint" above.
- **Grid status cells are pill-shaped badges**: light status-tinted background + darker same-hue text (e.g. light green bg + dark green text for Pass), not solid-filled colored cells — keeps the grid legible and not visually loud row after row.
- **A small color-key legend belongs under the grid** (Pass/Warning/Fail/Inconclusive swatches + labels), since five columns of colored pills benefit from an explicit key rather than assuming the meaning is obvious.
- The mock did not include real sort/filter/click-to-filter interaction or the drill-in page — those remain to be built per the written spec and this brief; the mock was for layout/color/density reference only.

## Overall direction

Audience is B2B deliverability-technical (Apollo evaluators, ops people who assess domains for a living) — the visual identity should read as credible and precise, not playful or templated-SaaS. Avoid generic AI-tool defaults (warm cream + terracotta, near-black + acid accent, generic card-kit shadows).

- **Color:** cool, restrained base — near-white or very light cool gray (~`#F7F8FA`) background, near-black text (~`#1A1D23`, not pure black), one confident accent for interactive elements/links (deep blue, ~`#2251E0`, rather than a warm/terracotta default).
- **Status colors (semantic, used consistently across all three zones):** Pass = green, Warning = amber, Fail = red, **Inconclusive = a genuinely distinct slate gray** — not a muddy blend of the other three. Inconclusive is a different category of answer (couldn't determine), not "kind of bad," and the color should communicate that at a glance, not just look like a fourth traffic-light shade.
- **Type:** one technical-leaning sans (or sans+mono pairing, e.g. something like IBM Plex Sans/Mono) — signals "real infrastructure tool," not generic marketing SaaS. **Decision: use a real webfont via CDN (e.g. Google Fonts), not a system-font stack.** Rationale: this app already depends on Google's public DoH API being reachable for its core function (live DNS lookups) — it has no offline mode and no meaningful "no internet" fallback story already. A Google Fonts CDN link adds one more request to an architecture that already assumes internet access; it does not introduce a new category of fragility. Distinctive typography is worth that one additional request.
- **Motion:** minimal. Reserve any transition for the one moment that's earned — the grid→detail page swap on drill-in.

## Zone 1: Portfolio summary (top of page)

- **Layout: card-based** — each stat (domain-level headline items, and each check-level breakdown line) gets its own small card.
- **Restraint is critical here:** this zone is an orientation aid, glanced at for a couple of seconds, not the main event — the grid below is still the hero. Keep cards small, compact, low-chrome. Status color should show as a thin border, small icon, or accent — not a large filled-color card background — so this zone doesn't visually outcompete the grid.
- **Color:** use the same semantic status colors as the grid (green/amber/red/slate for Inconclusive) so the same color = same meaning everywhere on the page — but applied with a lighter touch here than in the grid cells themselves.
- All summary cards remain clickable (per spec) — style them so it's visually obvious they're interactive (e.g. subtle hover state), not just numbers sitting in boxes.

## Zone 2: Summary grid (the hero)

- Dense, legible, data-forward — think well-built internal ops tool, not marketing landing page.
- Status colors are the primary visual signal in this zone — full-strength here, more so than in the summary cards above.
- Avoid decorative shadows/borders around every cell competing with the actual status colors and sort/filter affordances for attention.
- Sort indicators (arrows/carets) on column headers should be clearly visible but not heavy-handed.

## Zone 3: Drill-in detail (full page swap)

- Same visual language as the grid (same status colors, same type) — this should feel like the same product, not a different page style pasted in.
- The grid→detail transition is the one place motion is earned — a clean, quick page-swap treatment (not elaborate) reinforces that this is a real state change, not a jarring reload.
- Back button should be clearly present and consistent in style with the rest of the app.

## Sequencing note

This is a visual pass only — no changes to underlying logic, data, or the features already verified (5 checks, portfolio summary, sort/filter, drill-in fix suggestions). If anything in this brief seems to require a structural/logic change to implement well, flag it rather than making the change silently.

## Resolved open items (from Claude Code's pre-build check)

- **No saved mock image exists** — the mock was only ever a rendered chat widget, never saved as a file. Use your own judgment for spacing/sizing/radius not covered by the four concrete bullets above (left-border cards, pill badges, legend, tinted-bg/dark-text status cells) — those four points captured the decisions that mattered; exact pixel values are not critical to match.
- **Cross-Document View Transitions for the grid→detail swap: approved.** Good diligence confirming this is additive (one `<meta>` tag + CSS, no JS/architecture change) before proposing it. Chromium-only with automatic instant-navigation fallback elsewhere is an acceptable tradeoff for this prototype — proceed.
- **Font: use a real webfont via CDN (Google Fonts or similar), not the system-font default** — see rationale in Overall direction above.
