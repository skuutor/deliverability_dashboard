"use strict";

// Shared DNS-authentication check logic, used by both the summary grid
// (summary.js) and the drill-in detail page (detail.js). No UI code here.

const DOH_ENDPOINT = "https://dns.google/resolve";

const STATUS = {
  PASS: "pass",
  WARNING: "warning",
  FAIL: "fail",
  INCONCLUSIVE: "inconclusive",
};

const COMMON_DKIM_SELECTORS = [
  "google", "selector1", "selector2", "default", "k1", "dkim",
  "mail", "smtp", "s1", "s2", "zoho", "mandrill", "sendgrid", "pm",
];

// Barracuda's zone was confirmed (via the RFC 5782 canary test IP 127.0.0.2,
// which every well-behaved DNSBL must list) to return real results through
// Google's public DoH resolver. Spamhaus ZEN and SORBS both returned NXDOMAIN
// for that same always-listed canary IP — meaning Spamhaus/SORBS are
// rejecting or rate-limiting queries that arrive via a public resolver, and
// any "not listed" result from them through this path is not trustworthy.
// This was verified empirically before writing this file, not assumed.
const BLOCKLIST_ZONES = [
  { name: "Spamhaus ZEN", zone: "zen.spamhaus.org", reliableViaPublicResolver: false },
  { name: "Barracuda", zone: "b.barracudacentral.org", reliableViaPublicResolver: true },
  { name: "SORBS", zone: "dnsbl.sorbs.net", reliableViaPublicResolver: false },
];

// Domain-based blocklist (checks the domain itself, not a sending IP) — a
// different signal from BLOCKLIST_ZONES above: whether this domain has been
// seen used as spam content (e.g. a link/redirect target), not whether its
// mail-sending infrastructure has a bad reputation. Also confirmed
// empirically: Spamhaus DBL (the domain-based counterpart to ZEN) was tried
// first and rejected — its own documented always-listed test domain
// ("dbltest.com") returns NXDOMAIN through this public resolver, same
// blocking behavior as ZEN. SURBL's test entry
// ("surbl-org-permanent-test-point.com") returns a real listed result here,
// so SURBL is the one actually usable in this architecture. And unlike the
// IP-based check, this needs exactly one DNS query per domain — no SPF
// derivation, no CIDR expansion, no cap — which is what makes it tractable
// client-side where the IP-based check structurally isn't.
const SURBL_ZONE = "multi.surbl.org";

// --- Templated fix suggestions ---------------------------------------------
// One entry per distinct failure state. Deliberately static/templated
// (params only fill in the specific fact, e.g. which selector or which
// blocklist) rather than generated per-result, so every message is
// predictable and reviewable in this file.
const FIX_TEMPLATES = {
  spf_missing: () =>
    "No SPF record was found. Anyone can send mail claiming to be from this domain with no SPF check to catch it. Publish a TXT record starting with \"v=spf1\" listing your legitimate sending sources, ending in \"-all\".",
  spf_multiple: (count) =>
    `Found ${count} SPF records. RFC 7208 permits only one — receivers may treat this as a PermError and fail SPF entirely. Merge them into a single record.`,
  spf_allow_all: () =>
    'Your SPF record ends in "all" with no qualifier (or "+all"), which explicitly allows ANY server to send mail as this domain. Change it to "-all" to reject unauthorized senders.',
  spf_neutral_all: () =>
    'Your SPF record uses "?all" (neutral), which provides no real enforcement — it neither passes nor fails unlisted senders in a meaningful way. Move to "-all" once your sender list is confirmed complete.',
  spf_softfail_all: () =>
    'Your SPF record uses a soft fail ("~all"), which flags suspicious mail but doesn\'t block it. Consider "-all" once you\'ve confirmed all legitimate senders are included.',
  spf_no_all_mechanism: () =>
    'No "all" mechanism (or redirect=) was found at the end of the record, so enforcement behavior is undefined for receivers. Add "-all" (or "~all" while testing) at the end.',
  spf_too_many_lookups: (count) =>
    `This record requires ${count} DNS lookups to fully evaluate (recursively counting include/a/mx/ptr/exists/redirect chains). SPF fails closed with a PermError above 10 lookups per RFC 7208 — flatten or trim your includes.`,

  dkim_no_common_selector: () =>
    "No DKIM record found under common selector names. This may mean DKIM isn't configured, or it's using a custom selector — check with your ESP for the correct selector name and re-check with it.",
  dkim_selector_missing: (selector) =>
    `No DKIM record found at the selector you specified ("${selector}"). Confirm the selector name with your ESP, or that DKIM signing is actually enabled.`,
  dkim_key_revoked: (selector) =>
    `The DKIM record at selector "${selector}" has an empty public key ("p="), meaning the key has been revoked or was never fully published. Mail signed with this selector will fail DKIM verification — republish a valid key or rotate to a new selector.`,

  dmarc_missing: () =>
    "No DMARC record was found. Without DMARC, receivers have no domain-owner instructions for what to do with mail that fails SPF/DKIM. Publish a TXT record at _dmarc.<domain> starting with \"v=DMARC1; p=none;\" as a starting point, then tighten the policy once you're monitoring reports.",
  dmarc_invalid_policy: (value) =>
    `Your DMARC record has an invalid or missing policy value ("p=${value}"). It must be one of "none", "quarantine", or "reject".`,
  dmarc_policy_none: () =>
    'Your DMARC policy is set to monitor-only ("p=none"). Violations are logged but not blocked. Consider moving to "p=quarantine" to start enforcing once you\'re confident in your reporting data.',
  dmarc_missing_rua: () =>
    'No "rua=" aggregate report address is set, so you won\'t receive visibility reports on authentication failures. Add "rua=mailto:you@yourdomain.com" to start collecting them.',

  blocklist_listed: (names) =>
    `This domain's mail server IP is listed on ${names.join(", ")}. Visit the relevant blocklist's delisting process to request removal after resolving the underlying issue (usually compromised sending infrastructure or spam complaints).`,
  blocklist_no_spf: () =>
    "This domain has no SPF record, so there's no published list of authorized senders to derive a mail-server IP from. Publish an SPF record (see the SPF check above) to make blocklist checking possible.",
  blocklist_no_single_ip: () =>
    "This domain's SPF record has no ip4:, a:, or mx: mechanisms that resolve to an address (and no include:/redirect= chain that leads to one either). Blocklist status can't be determined from DNS alone in this case — check with your ESP directly, or inspect a recent email's headers for the actual sending IP.",
  blocklist_range_too_large: (raw) =>
    `This domain's SPF record authorizes sending from IP range "ip4:${raw}", which is too large to fully check from a live, uncached, browser-based tool within its query budget. A production version would need a backend job queue / caching layer to verify large ranges completely — this prototype reports what it couldn't fully check rather than guessing.`,
  blocklist_ipv6_unsupported: () =>
    "This domain's SPF record authorizes sending only via IPv6 (ip6:) entries. None of this tool's three blocklist zones (Spamhaus ZEN, Barracuda, SORBS) support IPv6 queries in this implementation, so blocklist status can't be checked here.",
  blocklist_inconclusive_resolver: (names) =>
    `${names.join(" and ")} could not be reliably checked: ${names.length > 1 ? "these blocklists" : "this blocklist"} reject or rate-limit queries routed through public DNS resolvers, so a "not listed" result from ${names.length > 1 ? "them" : "it"} can't be trusted. This is a known limitation of checking DNSBLs from a browser-only architecture.`,

  surbl_listed: () =>
    "This domain is listed on SURBL, meaning it's been seen used in spam content — e.g. as a link or redirect target in spam messages. This is a different signal from sending-IP reputation (a domain can be SURBL-clean while its sending IPs are blocklisted, or vice versa), so it points to a different problem: the domain itself being abused or compromised, not necessarily its mail infrastructure. Visit SURBL's delisting process (surbl.org) after resolving the underlying issue.",
};

// --- DNS-over-HTTPS lookup -------------------------------------------------

async function dohQuery(name, type) {
  const url = `${DOH_ENDPOINT}?name=${encodeURIComponent(name)}&type=${type}`;
  let res;
  try {
    res = await fetch(url, { headers: { accept: "application/dns-json" } });
  } catch (err) {
    return { networkError: true };
  }
  if (!res.ok) {
    return { networkError: true };
  }
  return res.json();
}

function cleanTxtData(data) {
  let s = data.trim();
  if (s.startsWith('"') && s.endsWith('"')) {
    s = s.slice(1, -1);
  }
  return s.replace(/"\s*"/g, "").replace(/\\"/g, '"');
}

// Returns { outcome: "ok" | "nxdomain" | "error", records: string[] }
// "error" means the lookup itself failed (network/resolver problem) and must
// never be treated the same as a genuine "no record" result.
async function getTxtRecords(name) {
  const json = await dohQuery(name, "TXT");
  if (json.networkError) return { outcome: "error", records: [] };
  if (json.Status === 3) return { outcome: "nxdomain", records: [] };
  if (json.Status !== 0) return { outcome: "error", records: [] };
  const records = (json.Answer || [])
    .filter((a) => a.type === 16)
    .map((a) => cleanTxtData(a.data));
  return { outcome: "ok", records };
}

function parseTags(record) {
  const tags = {};
  record.split(";").forEach((part) => {
    const [k, ...rest] = part.trim().split("=");
    if (k && rest.length) {
      tags[k.trim().toLowerCase()] = rest.join("=").trim();
    }
  });
  return tags;
}

// --- SPF ---------------------------------------------------------------

// Recursively counts DNS-lookup-consuming SPF mechanisms (a, mx, ptr, exists,
// include, redirect), actually fetching and recursing into include/redirect
// targets rather than only counting top-level mechanisms. Cycle-safe via
// `visited`, depth-capped as a safety net.
async function countSpfLookupsRecursive(record, visited, depth) {
  if (depth > 10) return 0;
  // Lookahead after the mechanism name is required — without it, "a" (a real,
  // lookup-consuming SPF mechanism) also matches the leading "a" inside "all"
  // (which consumes no lookup), silently inflating every count that includes
  // an "all"/"~all"/"-all" tag. Confirmed by hand-tracing google.com's SPF
  // chain (1 real "include" lookup) against the buggy regex (reported 3).
  const mechRe = /(?:^|\s)[+\-~?]?(a|mx|ptr|exists|include|redirect)(?=[:/=\s]|$)(?::|=)?(\S*)/gi;
  let count = 0;
  const nested = [];
  let match;
  while ((match = mechRe.exec(record)) !== null) {
    const type = match[1].toLowerCase();
    const value = (match[2] || "").trim();
    count += 1;
    if ((type === "include" || type === "redirect") && value) {
      nested.push(value);
    }
  }
  for (const target of nested) {
    if (visited.has(target)) continue;
    visited.add(target);
    const { outcome, records } = await getTxtRecords(target);
    if (outcome !== "ok") continue;
    const spf = records.find((r) => /^v=spf1(\s|$)/i.test(r.trim()));
    if (spf) {
      count += await countSpfLookupsRecursive(spf, visited, depth + 1);
    }
  }
  return count;
}

async function checkSPF(domain) {
  const { outcome, records } = await getTxtRecords(domain);

  if (outcome === "error") {
    return { status: STATUS.INCONCLUSIVE, notes: ["DNS lookup failed (network/resolver error) — could not check SPF."], raw: [] };
  }
  if (outcome === "nxdomain") {
    return { status: STATUS.FAIL, notes: ["Domain does not exist (confirmed NXDOMAIN)."], raw: [], fixKey: "spf_missing" };
  }

  const spfRecords = records.filter((r) => /^v=spf1(\s|$)/i.test(r.trim()));

  if (spfRecords.length === 0) {
    return {
      status: STATUS.FAIL,
      notes: ["No SPF record found at the domain apex (confirmed — TXT lookup succeeded with no v=spf1 record present)."],
      raw: [],
      fixKey: "spf_missing",
    };
  }

  if (spfRecords.length > 1) {
    return {
      status: STATUS.FAIL,
      notes: [`Found ${spfRecords.length} SPF records. Only one is allowed (RFC 7208).`],
      raw: spfRecords,
      fixKey: "spf_multiple",
      fixArgs: [spfRecords.length],
    };
  }

  const record = spfRecords[0];
  const notes = [];
  let status = STATUS.PASS;
  let fixKey = null;
  let fixArgs = [];

  const allMatch = record.match(/(?:^|\s)([+\-~?]?)all\b/i);
  if (!allMatch) {
    if (/redirect=/i.test(record)) {
      notes.push("Uses redirect= to delegate policy to another domain instead of an all mechanism.");
    } else {
      status = STATUS.WARNING;
      fixKey = "spf_no_all_mechanism";
      notes.push('No "all" mechanism (or redirect=) found — enforcement behavior is undefined.');
    }
  } else {
    const qualifier = allMatch[1];
    if (qualifier === "-") {
      notes.push('Hard fail policy ("-all") — receivers should reject mail from unlisted servers.');
    } else if (qualifier === "~") {
      status = STATUS.WARNING;
      fixKey = "spf_softfail_all";
      notes.push('Soft fail policy ("~all") — unlisted servers are flagged but not rejected outright.');
    } else if (qualifier === "?") {
      status = STATUS.WARNING;
      fixKey = "spf_neutral_all";
      notes.push('Neutral policy ("?all") — provides no real enforcement.');
    } else {
      // '+' or no qualifier at all (bare "all" defaults to +all per RFC 7208)
      status = STATUS.FAIL;
      fixKey = "spf_allow_all";
      notes.push('Uses "+all" (or bare "all"), which explicitly allows ANY server to send mail as this domain.');
    }
  }

  const lookupCount = await countSpfLookupsRecursive(record, new Set([domain]), 0);
  if (lookupCount > 10) {
    if (status === STATUS.PASS) status = STATUS.WARNING;
    notes.push(`Requires ~${lookupCount} DNS lookups to evaluate (recursively counted through include/redirect chains) — RFC 7208 fails closed with a PermError above 10.`);
    fixKey = "spf_too_many_lookups";
    fixArgs = [lookupCount];
  } else {
    notes.push(`Requires ${lookupCount} DNS lookup(s) to evaluate (within the RFC 7208 limit of 10).`);
  }

  return { status, notes, raw: [record], fixKey, fixArgs };
}

// --- DMARC ---------------------------------------------------------------

async function checkDMARC(domain) {
  const { outcome, records } = await getTxtRecords(`_dmarc.${domain}`);

  if (outcome === "error") {
    return { status: STATUS.INCONCLUSIVE, notes: ["DNS lookup failed (network/resolver error) — could not check DMARC."], raw: [] };
  }
  if (outcome === "nxdomain" || records.length === 0) {
    return {
      status: STATUS.FAIL,
      notes: [`No DMARC record found at _dmarc.${domain} (confirmed — no TXT record present).`],
      raw: [],
      fixKey: "dmarc_missing",
    };
  }

  const dmarcRecords = records.filter((r) => /^v=DMARC1/i.test(r.trim()));
  if (dmarcRecords.length === 0) {
    return {
      status: STATUS.FAIL,
      notes: [`No valid DMARC record (must start with "v=DMARC1") at _dmarc.${domain}.`],
      raw: records,
      fixKey: "dmarc_missing",
    };
  }
  if (dmarcRecords.length > 1) {
    return {
      status: STATUS.FAIL,
      notes: [`Found ${dmarcRecords.length} DMARC records. Only one is allowed — receivers may ignore DMARC entirely.`],
      raw: dmarcRecords,
      fixKey: "dmarc_invalid_policy",
      fixArgs: ["(multiple records)"],
    };
  }

  const record = dmarcRecords[0];
  const tags = parseTags(record);
  const notes = [];
  const extraNotes = [];
  let status;
  let fixKey = null;
  let fixArgs = [];

  const policy = tags.p !== undefined ? tags.p.toLowerCase() : undefined;
  if (!policy || !["none", "quarantine", "reject"].includes(policy)) {
    status = STATUS.FAIL;
    fixKey = "dmarc_invalid_policy";
    fixArgs = [policy || "(missing)"];
    notes.push(`Missing or invalid "p=" policy tag (found: "${policy || "none set"}").`);
  } else if (policy === "none") {
    status = STATUS.WARNING;
    fixKey = "dmarc_policy_none";
    notes.push('Policy is "p=none" — monitoring only, no enforcement action is taken.');
  } else {
    status = STATUS.PASS;
    notes.push(`Policy is "p=${policy}" — ${policy === "reject" ? "failing mail is rejected outright." : "failing mail is routed to spam."}`);
  }

  if (!tags.rua) {
    extraNotes.push('No "rua=" aggregate report address set (note — not a hard fail).');
  }
  if (tags.pct && tags.pct !== "100") {
    extraNotes.push(`Policy only applies to ${tags.pct}% of mail ("pct=${tags.pct}").`);
  }

  return { status, notes: notes.concat(extraNotes), raw: [record], fixKey, fixArgs };
}

// --- DKIM ---------------------------------------------------------------

// Some domains have wildcard/catch-all TXT records under arbitrary
// subdomains (confirmed in testing: hubspot.com returns "v=spf1 ~all" for
// almost any "<name>._domainkey.hubspot.com" query, regardless of whether
// that selector is real). A record only counts as an actual DKIM record if
// it looks like one — otherwise a name simply resolving isn't evidence of a
// configured DKIM selector, and treating it as one produces a false "empty
// key" failure.
function isDkimLikeRecord(record) {
  return /^v=dkim1/i.test(record.trim()) || /(^|;)\s*p=/i.test(record);
}

async function checkDKIM(domain, userSelector) {
  const selectorsToTry = userSelector ? [userSelector] : COMMON_DKIM_SELECTORS;

  const lookups = await Promise.all(
    selectorsToTry.map(async (selector) => {
      const { outcome, records } = await getTxtRecords(`${selector}._domainkey.${domain}`);
      if (outcome === "ok" && records.length > 0) {
        const dkimRecord = records.find(isDkimLikeRecord);
        if (dkimRecord) return { selector, record: dkimRecord };
      }
      return null;
    })
  );

  const found = lookups.filter(Boolean);

  if (found.length === 0) {
    if (userSelector) {
      return {
        status: STATUS.FAIL,
        notes: [`No DKIM record found at "${userSelector}._domainkey.${domain}".`],
        raw: [],
        fixKey: "dkim_selector_missing",
        fixArgs: [userSelector],
      };
    }
    return {
      status: STATUS.INCONCLUSIVE,
      notes: [
        "No DKIM record found under common selector names. This is inconclusive, not a confirmed failure — DKIM may still be configured under a custom selector.",
      ],
      raw: [],
      fixKey: "dkim_no_common_selector",
    };
  }

  const notes = [];
  let status = STATUS.PASS;
  let fixKey = null;
  let fixArgs = [];
  const rawEntries = [];

  for (const { selector, record } of found) {
    const tags = parseTags(record);
    rawEntries.push(`[${selector}] ${record}`);

    if (tags.p === undefined) {
      status = STATUS.FAIL;
      fixKey = "dkim_key_revoked";
      fixArgs = [selector];
      notes.push(`Selector "${selector}": missing "p=" public key tag.`);
    } else if (tags.p === "") {
      status = STATUS.FAIL;
      fixKey = "dkim_key_revoked";
      fixArgs = [selector];
      notes.push(`Selector "${selector}": empty public key ("p=") — this key has been revoked.`);
    } else {
      notes.push(`Selector "${selector}" found with a public key configured.`);
    }
  }

  return { status, notes, raw: rawEntries, fixKey, fixArgs };
}

// --- Blocklist ---------------------------------------------------------------
//
// DNSBLs list IP addresses, not domains, and specifically the IPs that send
// mail — not the IPs that receive it. An earlier version of this check used
// the domain's MX record (its inbound mail server) as a stand-in, which is
// the wrong signal: inbound and outbound mail infrastructure are frequently
// different servers entirely, and a domain can (as example.com/example.net
// do, via a null MX) declare "I don't receive mail" while that says nothing
// about whether it sends mail from somewhere else. The correct source for
// "what IPs send mail as this domain" is the domain's own SPF record — it's
// the domain's own published, authoritative list of authorized senders. So
// the candidate IP(s) to check are derived by walking the SPF chain (same
// include/redirect recursion as the SPF check) and collecting concrete
// addresses from its ip4 / a / mx mechanisms.

function parseMxHost(data) {
  const parts = data.trim().split(/\s+/);
  const exchange = parts[parts.length - 1].replace(/\.$/, "");
  const preference = parseInt(parts[0], 10) || 0;
  return { preference, exchange };
}

// Hard cap on how many IPs get checked against blocklists per domain, shared
// across exact ip4:/a:/mx:-derived addresses AND CIDR-range expansion. A
// live, uncached, browser-driven check can't afford to enumerate arbitrarily
// large ranges (e.g. a /16 is 65,536 addresses) — see checkBlocklist for what
// happens when this cap is hit before a range is fully covered.
const MAX_QUERY_IPS = 10;

async function resolveHostToIps(host) {
  const json = await dohQuery(host, "A");
  if (!json || json.networkError || json.Status !== 0) return [];
  return (json.Answer || []).filter((a) => a.type === 1).map((a) => a.data);
}

function ipToInt(ip) {
  const parts = ip.split(".").map(Number);
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function intToIp(int) {
  return [(int >>> 24) & 255, (int >>> 16) & 255, (int >>> 8) & 255, int & 255].join(".");
}

// Lazily yields every address in an ip4 CIDR range, network address first.
// Lazy (not a materialized array) so a huge range (e.g. /8 = 16M addresses)
// never gets fully built in memory — callers stop pulling once they've hit
// their query budget.
function* expandCidr(ip, prefix) {
  const p = prefix === undefined ? 32 : prefix;
  if (p >= 32) {
    yield ip;
    return;
  }
  const size = Math.pow(2, 32 - p);
  const base = ipToInt(ip);
  const mask = p === 0 ? 0 : (~0 << (32 - p)) >>> 0;
  const network = (base & mask) >>> 0;
  for (let i = 0; i < size; i++) {
    yield intToIp((network + i) >>> 0);
  }
}

// Walks the SPF chain collecting sending-IP sources: exact ip4:x.x.x.x/32
// and a/a:/mx/mx: mechanisms (resolved immediately, since they're already
// single addresses) go into `exactIps`; ip4: CIDR ranges wider than /32 go
// into `cidrRanges` for the caller to expand up to the query cap; ip6:
// entries are recorded but never resolved further — no blocklist zone this
// tool queries supports IPv6 lookups. Recurses into include:/redirect=
// targets (same traversal shape as the SPF check's lookup counter).
async function collectSpfSendingSources(domain, visited, depth, collected) {
  if (depth > 10) return;
  if (collected.exactIps.size >= MAX_QUERY_IPS) return;
  const { outcome, records } = await getTxtRecords(domain);
  if (outcome !== "ok") return;
  const spf = records.find((r) => /^v=spf1(\s|$)/i.test(r.trim()));
  if (!spf) return;

  const mechRe = /(?:^|\s)[+\-~?]?(ip4|ip6|a|mx|include|redirect)(?=[:/=\s]|$)(?::|=)?(\S*)/gi;
  let match;
  const aTargets = [];
  const mxTargets = [];
  const includeTargets = [];
  while ((match = mechRe.exec(spf)) !== null) {
    const type = match[1].toLowerCase();
    const value = (match[2] || "").trim();
    if (type === "ip4" && value) {
      const [ip, cidr] = value.split("/");
      if (!cidr || cidr === "32") {
        collected.exactIps.add(ip);
      } else {
        collected.cidrRanges.push({ ip, prefix: parseInt(cidr, 10), raw: value });
      }
    } else if (type === "ip6" && value) {
      collected.ip6Entries.push(value);
    } else if (type === "a") {
      aTargets.push(value || domain);
    } else if (type === "mx") {
      mxTargets.push(value || domain);
    } else if ((type === "include" || type === "redirect") && value && !visited.has(value)) {
      visited.add(value);
      includeTargets.push(value);
    }
  }

  for (const host of aTargets) {
    if (collected.exactIps.size >= MAX_QUERY_IPS) break;
    (await resolveHostToIps(host)).forEach((ip) => collected.exactIps.add(ip));
  }

  for (const host of mxTargets) {
    if (collected.exactIps.size >= MAX_QUERY_IPS) break;
    const mxJson = await dohQuery(host, "MX");
    if (mxJson.networkError || mxJson.Status !== 0) continue;
    const exchanges = (mxJson.Answer || [])
      .filter((a) => a.type === 15)
      .map((a) => parseMxHost(a.data))
      .filter((m) => m.exchange)
      .sort((a, b) => a.preference - b.preference)
      .slice(0, 2);
    for (const ex of exchanges) {
      if (collected.exactIps.size >= MAX_QUERY_IPS) break;
      (await resolveHostToIps(ex.exchange)).forEach((ip) => collected.exactIps.add(ip));
    }
  }

  for (const inc of includeTargets) {
    await collectSpfSendingSources(inc, visited, depth + 1, collected);
  }
}

async function queryDnsbl(ip, zone) {
  const reversed = ip.split(".").reverse().join(".");
  const json = await dohQuery(`${reversed}.${zone}`, "A");
  if (json.networkError) return { outcome: "error" };
  if (json.Status === 0 && json.Answer && json.Answer.length > 0) {
    return { outcome: "listed" };
  }
  if (json.Status === 3) return { outcome: "not-listed" };
  return { outcome: "error" };
}

async function checkBlocklist(domain) {
  const rootCheck = await getTxtRecords(domain);
  if (rootCheck.outcome === "error") {
    return { status: STATUS.INCONCLUSIVE, notes: ["Could not check for an SPF record (network/resolver error) — no sending IP to derive."], raw: [] };
  }
  if (rootCheck.outcome === "nxdomain") {
    return { status: STATUS.INCONCLUSIVE, notes: ["Domain does not exist — no sending IP to check."], raw: [] };
  }

  const hasSpf = rootCheck.records.some((r) => /^v=spf1(\s|$)/i.test(r.trim()));
  if (!hasSpf) {
    return {
      status: STATUS.INCONCLUSIVE,
      notes: ["No SPF record found, so there's no authorized-sender list to derive a mail server IP from (see the SPF check above)."],
      raw: [],
      fixKey: "blocklist_no_spf",
    };
  }

  const collected = { exactIps: new Set(), cidrRanges: [], ip6Entries: [] };
  await collectSpfSendingSources(domain, new Set([domain]), 0, collected);

  // Build the final query list: exact addresses first (cheap, already
  // single hosts), then expand CIDR ranges in the order encountered, up to
  // the shared MAX_QUERY_IPS budget. A range that runs out of budget before
  // being fully enumerated stops everything right there — per spec, hitting
  // the cap mid-range must produce Inconclusive, never a silent partial
  // check reported as if it were complete.
  const ips = [];
  const seen = new Set();
  for (const ip of collected.exactIps) {
    if (ips.length >= MAX_QUERY_IPS) break;
    if (!seen.has(ip)) {
      seen.add(ip);
      ips.push(ip);
    }
  }

  let rangeCapped = false;
  let cappedRangeRaw = null;
  for (const range of collected.cidrRanges) {
    if (ips.length >= MAX_QUERY_IPS) {
      rangeCapped = true;
      cappedRangeRaw = range.raw;
      break;
    }
    let coveredFully = true;
    for (const ip of expandCidr(range.ip, range.prefix)) {
      if (ips.length >= MAX_QUERY_IPS) {
        coveredFully = false;
        break;
      }
      if (!seen.has(ip)) {
        seen.add(ip);
        ips.push(ip);
      }
    }
    if (!coveredFully) {
      rangeCapped = true;
      cappedRangeRaw = range.raw;
      break;
    }
  }

  const ip6Note = collected.ip6Entries.length > 0
    ? `This domain's SPF record also authorizes ${collected.ip6Entries.length} IPv6 sender(s) (e.g. "ip6:${collected.ip6Entries[0]}") — not checked, since none of this tool's blocklist zones support IPv6 queries.`
    : null;

  if (ips.length === 0) {
    if (ip6Note) {
      return {
        status: STATUS.INCONCLUSIVE,
        notes: [`This domain's SPF record only authorizes sending via IPv6 (ip6:) entries. This prototype's blocklist zones (Spamhaus ZEN, Barracuda, SORBS) don't support IPv6 lookups, so this can't be checked.`],
        raw: [],
        fixKey: "blocklist_ipv6_unsupported",
      };
    }
    return {
      status: STATUS.INCONCLUSIVE,
      notes: ["Could not resolve a specific sending IP from this domain's SPF record (its mechanisms didn't resolve to any address)."],
      raw: [],
      fixKey: "blocklist_no_single_ip",
    };
  }

  // Check every candidate IP against every zone — a listing on any pairing is a real hit.
  const perIpResults = await Promise.all(
    ips.map(async (ip) => ({
      ip,
      zones: await Promise.all(BLOCKLIST_ZONES.map(async (z) => ({ ...z, ...(await queryDnsbl(ip, z.zone)) }))),
    }))
  );

  const notes = [`Checked ${ips.length} sending IP(s) derived from this domain's SPF record: ${ips.join(", ")}.`];
  if (ip6Note) notes.push(ip6Note);
  const raw = [];
  const listedPairs = [];
  const cautionZoneNames = new Set();
  let anyReliableNotListed = false;

  for (const { ip, zones } of perIpResults) {
    for (const z of zones) {
      raw.push(`${ip} on ${z.name}: ${z.outcome}${z.reliableViaPublicResolver ? "" : " (unreliable via public resolver)"}`);
      if (z.outcome === "listed") {
        listedPairs.push(`${ip} on ${z.name}`);
      } else if (z.outcome === "not-listed" && z.reliableViaPublicResolver) {
        anyReliableNotListed = true;
      } else {
        // Either "not-listed" from a zone known to reject public-resolver
        // queries (unreliable) or an outright lookup error — neither counts
        // as evidence of "not listed".
        cautionZoneNames.add(z.name);
      }
    }
  }

  if (listedPairs.length > 0) {
    notes.push(`Listed: ${listedPairs.join("; ")}.`);
    return { status: STATUS.FAIL, notes, raw, fixKey: "blocklist_listed", fixArgs: [listedPairs] };
  }

  // A real listing found above still stands (real evidence, checked or not).
  // But if the query cap was hit before a CIDR range was fully enumerated,
  // "nothing listed among the addresses we did check" is not the same as
  // "not listed" — per spec, that must report Inconclusive, not a Pass that
  // silently implies the whole range was verified.
  if (rangeCapped) {
    notes.push(`Query cap (${MAX_QUERY_IPS} IPs) reached before fully checking IP range "ip4:${cappedRangeRaw}" — this range is too large to fully verify from a live, uncached, browser-based check. None of the ${ips.length} address(es) actually checked were listed, but the range was not fully covered, so this can't be reported as a clean Pass.`);
    return { status: STATUS.INCONCLUSIVE, notes, raw, fixKey: "blocklist_range_too_large", fixArgs: [cappedRangeRaw] };
  }

  const cautionNames = Array.from(cautionZoneNames);
  if (cautionNames.length > 0) {
    notes.push(`Could not reliably verify: ${cautionNames.join(", ")} (public-resolver restriction or lookup error).`);
  }

  if (anyReliableNotListed) {
    notes.push("Not listed on the reliably-checkable blocklist(s).");
    return {
      status: STATUS.PASS,
      notes,
      raw,
      fixKey: cautionNames.length ? "blocklist_inconclusive_resolver" : null,
      fixArgs: cautionNames.length ? [cautionNames] : [],
    };
  }

  // No reliable signal at all (e.g. Barracuda itself errored for every IP).
  return {
    status: STATUS.INCONCLUSIVE,
    notes,
    raw,
    fixKey: "blocklist_inconclusive_resolver",
    fixArgs: [cautionNames],
  };
}

// --- SURBL (domain-based) ---------------------------------------------------

async function checkSurbl(domain) {
  const json = await dohQuery(`${domain}.${SURBL_ZONE}`, "A");
  if (json.networkError) {
    return { status: STATUS.INCONCLUSIVE, notes: ["Could not check SURBL (network/resolver error)."], raw: [] };
  }
  if (json.Status === 0 && json.Answer && json.Answer.length > 0) {
    return {
      status: STATUS.FAIL,
      notes: [`Listed on SURBL: ${domain}.${SURBL_ZONE} resolved to ${json.Answer[0].data}.`],
      raw: [`${domain}.${SURBL_ZONE}: listed (${json.Answer.map((a) => a.data).join(", ")})`],
      fixKey: "surbl_listed",
    };
  }
  if (json.Status === 3) {
    return {
      status: STATUS.PASS,
      notes: ["Not listed on SURBL — no evidence found of this domain being used in spam content."],
      raw: [`${domain}.${SURBL_ZONE}: not listed`],
    };
  }
  return { status: STATUS.INCONCLUSIVE, notes: [`SURBL lookup returned an unexpected result (DNS status ${json.Status}).`], raw: [] };
}

// --- Orchestration -------------------------------------------------------

async function runAllChecks(domain, dkimSelector) {
  const [spf, dkim, dmarc, blocklist, surbl] = await Promise.all([
    checkSPF(domain),
    checkDKIM(domain, dkimSelector),
    checkDMARC(domain),
    checkBlocklist(domain),
    checkSurbl(domain),
  ]);

  const checks = { spf, dkim, dmarc, blocklist, surbl };
  const passCount = Object.values(checks).filter((c) => c.status === STATUS.PASS).length;

  return { domain, dkimSelector, checks, passCount, totalChecks: 5 };
}

function getFixSuggestion(checkResult) {
  if (!checkResult.fixKey) return null;
  const template = FIX_TEMPLATES[checkResult.fixKey];
  if (!template) return null;
  return template(...(checkResult.fixArgs || []));
}
