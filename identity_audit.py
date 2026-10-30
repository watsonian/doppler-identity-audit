#!/usr/bin/env python3
"""
Doppler service account identity audit.

Lists every service account identity in every workplace you have a token for,
shows how each one is configured, and flags settings worth a second look.

Read-only: the script only sends GET requests. It needs Python 3.9+ and has no
dependencies. Run `python3 identity_audit.py --help` for usage.

API calls made, per token:
  GET /v3/me                                                        workplace name
  GET /v3/workplace/service_accounts                                service accounts
  GET /v3/workplace/service_accounts/service_account/{sa}/identities  identities
"""

import argparse
import csv
import hashlib
import io
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

DEFAULT_API_HOST = "https://api.doppler.com"
DEFAULT_DASHBOARD_HOST = "https://dashboard.doppler.com"
PAGE_SIZE = 100  # the API's maximum
SEVERITIES = ["high", "medium", "low", "info"]
DEFAULT_OPTIONS = {"stale_days": 90, "max_ttl_seconds": 3600}


# ---------------------------------------------------------------------------
# Reading tokens
# ---------------------------------------------------------------------------

# One token per line. Accepted forms:
#   dp.sa.xxxx
#   prod-workplace  dp.sa.xxxx
#   PROD_WORKPLACE=dp.sa.xxxx          (also `export NAME="dp.sa.xxxx"`, so .env files work)
# Blank lines and lines starting with # are ignored.
TOKEN_LINE = re.compile(
    r"""^(?:export\s+)?(?:(?P<label>[^\s=]+)\s*[=\s]\s*)?["']?(?P<token>dp\.[a-z_]+\.[A-Za-z0-9_\-]+)["']?$"""
)


def parse_tokens(text, source="input"):
    """Returns a list of (label, token); label is None when the line has none, and the
    workplace name from /v3/me names the token instead. Never echoes a line back, since it
    may hold a token."""
    tokens = []
    for line_number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = TOKEN_LINE.match(line)
        if not match:
            raise ValueError(f"{source} line {line_number}: not a Doppler token (expected 'dp.xx.xxxx', optionally preceded by a label)")
        tokens.append((match.group("label"), match.group("token")))
    return tokens


def tokens_from_env(prefix):
    """Every environment variable whose name starts with `prefix` holds one token; the rest of the name is its label."""
    found = []
    for name, value in sorted(os.environ.items()):
        if not name.startswith(prefix) or not value.strip():
            continue
        if not re.fullmatch(r"dp\.[a-z_]+\.[A-Za-z0-9_\-]+", value.strip()):
            raise ValueError(f"environment variable {name} doesn't hold a Doppler token")
        found.append((name[len(prefix):] or name, value.strip()))
    return found


# ---------------------------------------------------------------------------
# Talking to the Doppler API
# ---------------------------------------------------------------------------


class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


class DopplerClient:
    def __init__(self, token, api_host=DEFAULT_API_HOST, timeout=30, max_retries=4):
        self.token = token
        self.api_host = api_host.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries

    def get(self, path, params=None):
        url = self.api_host + path + ("?" + urllib.parse.urlencode(params) if params else "")
        request = urllib.request.Request(
            url,
            headers={"Authorization": f"Bearer {self.token}", "Accept": "application/json", "User-Agent": "doppler-identity-audit/1.0"},
        )
        attempt = 0
        while True:
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    return json.load(response)
            except urllib.error.HTTPError as error:
                # Doppler limits API reads per token per minute (240 or more, depending on the plan)
                # and answers 429 with Retry-After. Large workplaces need more requests than that,
                # so rate limiting gets a bigger retry budget than server errors do.
                budget = max(self.max_retries, 8) if error.code == 429 else self.max_retries
                if (error.code == 429 or error.code >= 500) and attempt < budget:
                    time.sleep(retry_delay(error, attempt))
                    attempt += 1
                    continue
                raise ApiError(error.code, api_error_message(error)) from None
            except urllib.error.URLError as error:
                if attempt < self.max_retries:
                    time.sleep(2**attempt)
                    attempt += 1
                    continue
                raise ApiError(None, f"could not reach {self.api_host}: {error.reason}") from None

    def get_all(self, path, key):
        """Follows page numbers until a page comes back short. These endpoints don't return a total."""
        items, page = [], 1
        while True:
            batch = self.get(path, {"page": page, "per_page": PAGE_SIZE})[key]
            items.extend(batch)
            if len(batch) < PAGE_SIZE:
                return items
            page += 1


def retry_delay(error, attempt):
    retry_after = error.headers.get("Retry-After")
    if retry_after and retry_after.isdigit():
        return min(int(retry_after), 60)
    return 30 if error.code == 429 else 2**attempt


def api_error_message(error):
    try:
        body = json.load(error)
        messages = body.get("messages") or []
        if messages:
            return f"HTTP {error.code}: {'; '.join(messages)}"
    except Exception:
        pass
    return f"HTTP {error.code}"


# ---------------------------------------------------------------------------
# Collecting identities
# ---------------------------------------------------------------------------


def token_preview(token):
    return "…" + token[-4:]


def fetch_workplace(client):
    """GET /v3/me answers for any valid token, whatever its permissions, with the workplace it belongs to."""
    me = client.get("/v3/me")
    return {"slug": me["workplace"]["slug"], "name": me["workplace"]["name"]}


def identify_token(token, api_host):
    """Returns (workplace, error) for one token, so a token can be named and checked before any audit runs."""
    try:
        return fetch_workplace(DopplerClient(token, api_host, max_retries=1)), None
    except ApiError as error:
        return None, explain_error(error)
    except (KeyError, TypeError, ValueError) as error:
        return None, f"unexpected API response ({error.__class__.__name__}: {error})"


def token_name(result):
    """How reports refer to a token: its label if it has one, otherwise its last four characters."""
    return result["token_label"] or result["token_preview"]


def audit_workplace(label, token, api_host, on_service_account=None):
    """Fetches one workplace's service accounts and their identities. Errors are recorded, not raised.
    on_service_account(result), if given, is called after each service account, for progress."""
    client = DopplerClient(token, api_host)
    result = {"token_label": label, "token_preview": token_preview(token), "workplace": None, "service_accounts": [], "error": None}
    try:
        result["workplace"] = fetch_workplace(client)

        for sa in client.get_all("/v3/workplace/service_accounts", "service_accounts"):
            role = sa.get("workplace_role") or {}
            path = f"/v3/workplace/service_accounts/service_account/{urllib.parse.quote(sa['slug'])}/identities"
            result["service_accounts"].append(
                {
                    "name": sa["name"],
                    "slug": sa["slug"],
                    "role_name": role.get("name"),
                    "role_identifier": role.get("identifier"),
                    "identities": client.get_all(path, "identities"),
                }
            )
            if on_service_account:
                on_service_account(result)
    except ApiError as error:
        result["error"] = explain_error(error)
    except (KeyError, TypeError, ValueError) as error:
        result["error"] = f"unexpected API response ({error.__class__.__name__}: {error})"
    return result


def explain_error(error):
    if error.status == 401:
        return f"{error} - the token is invalid, expired or revoked"
    if error.status == 403:
        return f"{error} - the token needs the 'View Service Account Identities' workplace permission, or the plan doesn't include identities"
    return str(error)


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


# Every check, in one place. "when" says what triggers it and "why" says why it matters;
# both are shown in the app's guide to findings, with the thresholds filled in.
RULES = {
    "any-value": {
        "severity": "high", "title": "Claim accepts any value",
        "when": "A claim value is only wildcards, such as sub: *, and the identity uses wildcard matching.",
        "why": "Any token from the issuer passes the check. For a shared issuer such as GitHub Actions, that means any repository on GitHub.",
    },
    "leading-wildcard": {
        "severity": "medium", "title": "Claim starts with a wildcard",
        "when": "A claim value starts with *, such as *:workspace:prod:*, and the identity uses wildcard matching.",
        "why": "The pattern can match values you don't control, such as another organization's.",
    },
    "elevated-role": {
        "severity": "medium", "title": "Owner or Admin service account",
        "when": "The identity's service account has the Owner or Admin workplace role.",
        "why": "Any workload that matches the identity gets that level of access to the whole workplace.",
    },
    "sub-wildcard": {
        "severity": "low", "title": "Wildcard in the subject",
        "when": "The sub claim contains * after its first character, such as repo:acme/*, and the identity uses wildcard matching.",
        "why": "Often intended, but confirm the subject is as narrow as it can be.",
    },
    "long-ttl": {
        "severity": "low", "title": "Long token TTL",
        "when": "The token TTL is longer than {max_ttl}.",
        "why": "Tokens issued to the workload stay valid for longer, so a leaked token is useful for longer.",
    },
    "never-used": {
        "severity": "low", "title": "Never used",
        "when": "The identity has never been used, and was created more than {stale_period} ago.",
        "why": "It may belong to a workload that no longer exists, and could be removed.",
    },
    "stale": {
        "severity": "low", "title": "Not used recently",
        "when": "The identity hasn't been used in the last {stale_period}.",
        "why": "It may belong to a workload that no longer exists, and could be removed.",
    },
    "unknown-method": {
        "severity": "info", "title": "Unrecognized auth method",
        "when": "The identity uses an auth method other than OIDC.",
        "why": "This tool only knows how to check OIDC identities, so review it by hand.",
    },
}


def finding_rules(options):
    """The rules with this run's thresholds filled in, for the app's guide."""
    values = {"max_ttl": format_duration(options["max_ttl_seconds"]), "stale_period": plural(options["stale_days"], "day")}
    return [{"id": rule_id, **rule, "when": rule["when"].format(**values)} for rule_id, rule in RULES.items()]


def check_row(row, now, options):
    """Returns the findings for one identity row: a list of {severity, rule, title, field, message}.
    field names what the finding is about ("claims.sub", "role", "ttl", "last_seen" or "method")."""
    findings = []

    def add(rule, field, message):
        findings.append({"severity": RULES[rule]["severity"], "rule": rule, "title": RULES[rule]["title"], "field": field, "message": message})

    if row.get("method") != "oidc":
        add("unknown-method", "method", f"unrecognized auth method {row.get('method')!r}; review it by hand")

    if row.get("claims_type") == "wildcard":
        for key, options_for_claim in (row.get("claims") or {}).items():
            for option in options_for_claim:
                if not option.replace("*", "").replace("?", ""):
                    add("any-value", f"claims.{key}", f"claim '{key}' accepts any value ({option!r})")
                elif option.startswith("*"):
                    add("leading-wildcard", f"claims.{key}", f"claim '{key}' starts with a wildcard ({option!r}); it can match subjects you don't expect")
                elif "*" in option and key == "sub":
                    add("sub-wildcard", "claims.sub", f"claim 'sub' uses a wildcard ({option!r}); confirm the scope is intended")

    if row.get("service_account_role_identifier") in ("owner", "admin"):
        add("elevated-role", "role", f"service account has the workplace role '{row.get('service_account_role')}', so anything that matches this identity gets that access")

    ttl = row.get("ttl_seconds") or 0
    if ttl > options["max_ttl_seconds"]:
        add("long-ttl", "ttl", f"token TTL is {format_duration(ttl)}, longer than {format_duration(options['max_ttl_seconds'])}")

    last_seen = parse_time(row.get("last_seen_at"))
    created = parse_time(row.get("created_at"))
    stale_after = timedelta(days=options["stale_days"])
    if last_seen is None and created and now - created > stale_after:
        add("never-used", "last_seen", f"never used, created {created.date()}")
    elif last_seen and now - last_seen > stale_after:
        add("stale", "last_seen", f"not used since {last_seen.date()}")

    return findings


def apply_checks(report, options, now=None):
    """Runs every check against a report's identities with these settings and returns a new report.
    The app uses this to apply changed thresholds without fetching everything again."""
    now = now or datetime.now(timezone.utc)
    options = {**DEFAULT_OPTIONS, **options}
    rows = [{**row, "findings": check_row(row, now, options)} for row in report["identities"]]
    summary = {**report["summary"], "findings": {s: sum(1 for r in rows for f in r["findings"] if f["severity"] == s) for s in SEVERITIES}}
    return {**report, "options": options, "rules": finding_rules(options), "identities": rows, "summary": summary}


def build_report(token_entries, api_host=DEFAULT_API_HOST, concurrency=4, options=None, progress=None,
                 dashboard_host=DEFAULT_DASHBOARD_HOST, on_service_account=None):
    """Audits every token and returns the whole report as a dict (the same shape --format json writes)."""
    now = datetime.now(timezone.utc)

    def run(entry):
        result = audit_workplace(entry[0], entry[1], api_host, on_service_account)
        if progress:
            progress(result)
        return result

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        workplaces = list(pool.map(run, token_entries))

    # Two tokens for one workplace would list everything twice.
    seen = {}
    for workplace in workplaces:
        slug = (workplace["workplace"] or {}).get("slug")
        if slug and slug in seen:
            workplace["error"] = f"duplicate: same workplace as token '{seen[slug]}', skipped"
            workplace["service_accounts"] = []
        elif slug:
            seen[slug] = token_name(workplace)

    rows = []
    for workplace in workplaces:
        for sa in workplace["service_accounts"]:
            for identity in sa["identities"]:
                rows.append(identity_row(workplace, sa, identity, dashboard_host))

    report = {
        "generated_at": now.isoformat(timespec="seconds"),
        "api_host": api_host,
        "dashboard_host": dashboard_host,
        "workplaces": [workplace_summary(w) for w in workplaces],
        "identities": rows,
        "summary": {
            "workplaces": len(workplaces),
            "workplaces_failed": sum(1 for w in workplaces if w["error"]),
            "service_accounts": sum(len(w["service_accounts"]) for w in workplaces),
            "service_accounts_with_identities": sum(1 for w in workplaces for sa in w["service_accounts"] if sa["identities"]),
            "identities": len(rows),
        },
    }
    return apply_checks(report, options or {}, now)


def identity_row(workplace, sa, identity, dashboard_host):
    """Flattens one identity into a self-contained record."""
    config = identity.get("config") or {}
    workplace_slug = workplace["workplace"]["slug"]
    return {
        "workplace_name": workplace["workplace"]["name"],
        "workplace_slug": workplace_slug,
        "token_label": token_name(workplace),
        "service_account_name": sa["name"],
        "service_account_slug": sa["slug"],
        "service_account_role": sa.get("role_name"),
        "service_account_role_identifier": sa.get("role_identifier"),
        "identity_name": identity.get("name"),
        "identity_slug": identity.get("slug"),
        "method": identity.get("method"),
        "discovery_url": config.get("discovery_url"),
        "claims_type": config.get("claims_type"),
        "claims": config.get("claims") or {},
        "ttl_seconds": identity.get("ttl_seconds"),
        "created_at": identity.get("created_at"),
        "last_seen_at": identity.get("last_seen_at"),
        "findings": [],
        "dashboard_url": f"{dashboard_host}/workplace/{workplace_slug}/team/service_accounts/{sa['slug']}",
    }


def workplace_summary(workplace):
    return {
        "token_label": workplace["token_label"],
        "token_preview": workplace["token_preview"],
        "workplace": workplace["workplace"],
        "error": workplace["error"],
        "service_accounts": len(workplace["service_accounts"]),
        "identities": sum(len(sa["identities"]) for sa in workplace["service_accounts"]),
    }


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


SEVERITY_COLORS = {"high": "1;31", "medium": "33", "low": "36", "info": "2"}


def painter(color):
    """Returns paint(code, text), which wraps text in an ANSI color code when color is on."""
    return lambda code, text: f"\033[{code}m{text}\033[0m" if color else text


def format_identity(row, paint, indent):
    """Every setting of one identity, one per line, followed by its findings."""
    matching = "wildcard (* and ? match any characters)" if row["claims_type"] == "wildcard" else "exact"
    lines = [
        f"issuer:          {clean(row['discovery_url'])}",
        f"claim matching:  {clean(matching)}",
        "required claims (any one value per claim):",
        *[f"  {clean(key) + ':':<14} {', '.join(clean(v) for v in values)}" for key, values in row["claims"].items()],
        f"token TTL:       {format_duration(row['ttl_seconds'])}",
        f"created:         {short_date(row['created_at'])}",
        f"last used:       {short_date(row['last_seen_at']) or 'never'}",
        f"identity ID:     {clean(row['identity_slug'])}",
    ]
    for finding in row["findings"]:
        lines.append(f"{paint(SEVERITY_COLORS[finding['severity']], '[' + finding['severity'].upper() + ']')} {clean(finding['message'])}")
    return [indent + line for line in lines]


def format_text(report, color=False):
    paint = painter(color)
    out = []
    by_workplace = {}
    for row in report["identities"]:
        by_workplace.setdefault(row["workplace_slug"], []).append(row)

    for workplace in report["workplaces"]:
        info = workplace["workplace"] or {}
        title = f"{clean(info.get('name', '?'))} ({clean(info.get('slug', '?'))})" if info else "(unknown workplace)"
        out.append(paint("1", f"== {title}") + f"   token: {clean(token_name(workplace))}")
        if workplace["error"]:
            out.append("   " + paint("1;31", "ERROR: ") + clean(workplace["error"]))
            out.append("")
            continue
        rows = by_workplace.get(info.get("slug"), [])
        out.append(f"   {plural(workplace['service_accounts'], 'service account')}, {plural(workplace['identities'], 'identity', 'identities')}")
        current_sa = None
        for row in rows:
            if row["service_account_slug"] != current_sa:
                current_sa = row["service_account_slug"]
                out.append("")
                out.append(f"   Service account: {paint('1', clean(row['service_account_name']))}   role: {clean(row['service_account_role'])}")
                out.append(f"   {clean(row['dashboard_url'])}")
            out.append(f"     - Identity: {paint('1', clean(row['identity_name']))}   ({clean(row['method']).upper()})")
            out.extend(format_identity(row, paint, "         "))
        out.append("")

    summary = report["summary"]
    counts = ", ".join(f"{summary['findings'][s]} {s}" for s in SEVERITIES)
    out.append(paint("1", "== Summary"))
    out.append(f"   workplaces: {summary['workplaces']} ({summary['workplaces_failed']} failed)")
    out.append(f"   service accounts: {summary['service_accounts']} ({summary['service_accounts_with_identities']} with identities)")
    out.append(f"   identities: {summary['identities']}")
    out.append(f"   findings: {counts}")
    return "\n".join(out) + "\n"


CSV_COLUMNS = [
    "workplace_name", "workplace_slug", "token_label", "service_account_name", "service_account_slug",
    "service_account_role", "identity_name", "identity_slug", "method", "discovery_url", "claims_type",
    "aud", "sub", "other_claims", "ttl_seconds", "created_at", "last_seen_at", "highest_severity",
    "findings", "dashboard_url",
]


def format_csv(report):
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for row in report["identities"]:
        claims = dict(row["claims"])
        aud, sub = claims.pop("aud", []), claims.pop("sub", [])
        writer.writerow(csv_safe({
            **row,
            "aud": " | ".join(aud),
            "sub": " | ".join(sub),
            "other_claims": "; ".join(f"{k}={' | '.join(v)}" for k, v in claims.items()),
            "highest_severity": highest_severity(row["findings"]) or "",
            "findings": "; ".join(f"[{f['severity']}] {f['message']}" for f in row["findings"]),
        }))
    for workplace in report["workplaces"]:
        if workplace["error"]:
            name = (workplace["workplace"] or {}).get("name", "")
            writer.writerow(csv_safe({"workplace_name": name, "token_label": token_name(workplace), "findings": f"ERROR: {workplace['error']}"}))
    return buffer.getvalue()


def csv_safe(row):
    """Stops spreadsheet apps from running names like '=HYPERLINK(...)' as formulas."""
    return {k: "'" + v if isinstance(v, str) and v[:1] in ("=", "+", "-", "@") else v for k, v in row.items()}


def highest_severity(findings):
    for severity in SEVERITIES:
        if any(f["severity"] == severity for f in findings):
            return severity
    return None


# ---------------------------------------------------------------------------
# Interactive review (--review FILE): one identity at a time, recording a decision
# for each. The file is rewritten after every decision, so a review can be stopped
# and picked up again later.
# ---------------------------------------------------------------------------

REVIEW_COLUMNS = CSV_COLUMNS + ["fingerprint", "decision", "note", "updated_at"]
REVIEW_PROMPT = "[a]pprove  [f]lag  [n]ote  [enter] next  [p]revious  [q]uit > "


def fingerprint(row):
    """Changes whenever the identity's configuration does, which clears an earlier decision."""
    config = [row["discovery_url"], row["claims_type"], row["claims"], row["ttl_seconds"], row["service_account_role"]]
    return hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()[:16]


def load_review(path):
    """Reads decisions from an earlier session: {(identity_slug, fingerprint): {...}}."""
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8", newline="") as handle:
        decisions = {}
        for line in csv.DictReader(handle):
            note = line.get("note") or ""
            if note[:2] in ("'=", "'+", "'-", "'@"):
                note = note[1:]  # undo csv_safe
            decision = line.get("decision") if line.get("decision") in ("approved", "flagged") else ""
            if decision or note:
                decisions[(line["identity_slug"], line["fingerprint"])] = {
                    "decision": decision, "note": note, "updated_at": line.get("updated_at") or "",
                }
        return decisions


def save_review(path, report, decisions):
    """Writes every identity with its decision, replacing the file in one step."""
    rows = {row["identity_slug"]: row for row in csv.DictReader(io.StringIO(format_csv(report))) if row["identity_slug"]}
    temporary = path + ".tmp"
    with open(temporary, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=REVIEW_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for identity in report["identities"]:
            key = (identity["identity_slug"], fingerprint(identity))
            decision = decisions.get(key, {})
            writer.writerow(csv_safe({
                **rows[identity["identity_slug"]],
                "fingerprint": key[1],
                "decision": decision.get("decision") or "not reviewed",
                "note": decision.get("note", ""),
                "updated_at": decision.get("updated_at", ""),
            }))
    os.replace(temporary, path)


def run_review(report, path, color):
    paint = painter(color)
    decisions = load_review(path)
    severity_rank = {s: i for i, s in enumerate(SEVERITIES)}
    order = {w["workplace"]["slug"]: i for i, w in enumerate(report["workplaces"]) if w["workplace"]}
    # Grouped by workplace, most serious automated finding first.
    rows = sorted(report["identities"], key=lambda r: (
        order.get(r["workplace_slug"], 0), severity_rank.get(highest_severity(r["findings"]), len(SEVERITIES)),
        r["service_account_name"], r["identity_name"]))
    if not rows:
        print("There are no identities to review.")
        return

    def decision_for(row):
        return decisions.get((row["identity_slug"], fingerprint(row)), {})

    def next_undecided(start):
        for step in range(1, len(rows) + 1):
            candidate = (start + step) % len(rows)
            if not decision_for(rows[candidate]).get("decision"):
                return candidate
        return None

    def record(row, **changes):
        key = (row["identity_slug"], fingerprint(row))
        decisions[key] = {**decisions.get(key, {"decision": "", "note": ""}), **changes,
                          "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        save_review(path, report, decisions)

    save_review(path, report, decisions)
    index = next_undecided(-1)
    index = 0 if index is None else index
    labels = {"approved": paint("32", "APPROVED"), "flagged": paint("1;33", "FLAGGED")}
    while True:
        row = rows[index]
        decided = [decision_for(r).get("decision") for r in rows]
        current = decision_for(row)
        if color:
            print("\033[2J\033[H", end="")  # clear the screen so each identity reads as its own page
        print(paint("1", f"Identity {index + 1} of {len(rows)}")
              + f"   {decided.count('approved')} approved, {decided.count('flagged')} flagged, {len(rows) - decided.count('approved') - decided.count('flagged')} not reviewed")
        print()
        print(f"  Workplace:        {clean(row['workplace_name'])} ({clean(row['workplace_slug'])})")
        print(f"  Service account:  {clean(row['service_account_name'])}   role: {clean(row['service_account_role'])}")
        print(f"  Identity:         {paint('1', clean(row['identity_name']))}   ({clean(row['method']).upper()})")
        print("\n".join(format_identity(row, paint, "  ")))
        print(f"  {clean(row['dashboard_url'])}")
        print()
        print(f"  Decision: {labels.get(current.get('decision'), 'not reviewed')}" + (f"   Note: {clean(current['note'])}" if current.get("note") else ""))
        try:
            choice = input(REVIEW_PROMPT).strip().lower()
            if choice in ("a", "f"):
                note = current.get("note", "")
                if choice == "f":
                    note = input("  Why does it need follow-up? (optional) > ").strip() or note
                record(row, decision="approved" if choice == "a" else "flagged", note=note)
                following = next_undecided(index)
                if following is None:
                    print(paint("1", "\nEvery identity has a decision."))
                    break
                index = following
            elif choice == "n":
                record(row, note=input("  Note > ").strip())
            elif choice in ("", "j"):
                index = min(index + 1, len(rows) - 1)
            elif choice in ("p", "k"):
                index = max(index - 1, 0)
            elif choice == "q":
                break
        except (EOFError, KeyboardInterrupt):
            print()
            break
    final = [decision_for(r).get("decision") for r in rows]
    print(f"{final.count('approved')} approved, {final.count('flagged')} flagged, "
          f"{len(rows) - final.count('approved') - final.count('flagged')} not reviewed. Saved to {path}")


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def clean(value):
    """Strips control characters so names from the API can't rewrite the terminal."""
    return re.sub(r"[\x00-\x1f\x7f-\x9f]", "", str(value if value is not None else ""))


def plural(count, singular, plural_form=None):
    return f"{count} {singular if count == 1 else plural_form or singular + 's'}"


def parse_time(value):
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def short_date(value):
    parsed = parse_time(value)
    return parsed.strftime("%Y-%m-%d") if parsed else ""


def format_duration(seconds):
    seconds = int(seconds or 0)
    if seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    if seconds % 60 == 0:
        return f"{seconds // 60}m"
    return f"{seconds}s"


def check_api_host(host):
    parsed = urllib.parse.urlparse(host)
    if parsed.scheme != "https" and parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise ValueError("--api-host must use https (http is allowed only for localhost)")
    return host.rstrip("/")


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="List and check every Doppler service account identity across many workplaces.",
        epilog="Tokens are read from DOPPLER_AUDIT_TOKEN_<NAME> environment variables (for example with `doppler run`), never from arguments, so they don't end up in shell history or `ps`.",
    )
    parser.add_argument("-t", "--tokens-file", help="also read tokens from this file, one per line ('-' for stdin); environment variables are preferred")
    parser.add_argument("--env-prefix", default="DOPPLER_AUDIT_TOKEN_", help="also read tokens from env vars with this prefix (default: %(default)s)")
    parser.add_argument("-f", "--format", choices=["text", "csv", "json"], default="text", help="output format (default: %(default)s)")
    parser.add_argument("-o", "--output", help="write to this file instead of stdout")
    parser.add_argument("--review", metavar="FILE", help="step through identities one at a time and record a decision for each in this CSV file; run again to resume")
    parser.add_argument("--findings-only", action="store_true", help="text/csv: show only identities with findings")
    parser.add_argument("--stale-days", type=int, default=DEFAULT_OPTIONS["stale_days"], help="flag identities unused for this many days (default: %(default)s)")
    parser.add_argument("--max-ttl", type=int, default=DEFAULT_OPTIONS["max_ttl_seconds"], help="flag token TTLs longer than this many seconds (default: %(default)s)")
    parser.add_argument("--fail-on", choices=SEVERITIES, help="exit 3 if any finding is at least this severe")
    parser.add_argument("--concurrency", type=int, default=4, help="workplaces audited in parallel (default: %(default)s)")
    parser.add_argument("--api-host", default=os.environ.get("DOPPLER_API_HOST", DEFAULT_API_HOST), help="API host (default: %(default)s)")
    parser.add_argument("--dashboard-host", default=DEFAULT_DASHBOARD_HOST, help="dashboard host used for links (default: %(default)s)")
    args = parser.parse_args(argv)

    try:
        api_host = check_api_host(args.api_host)
        tokens = tokens_from_env(args.env_prefix)
        if args.tokens_file == "-":
            tokens += parse_tokens(sys.stdin.read(), "stdin")
        elif args.tokens_file:
            with open(args.tokens_file, encoding="utf-8") as handle:
                tokens += parse_tokens(handle.read(), os.path.basename(args.tokens_file))
    except (ValueError, OSError) as error:
        parser.error(str(error))
    if not tokens:
        parser.error(f"no tokens found: set {args.env_prefix}<NAME> environment variables, for example with `doppler run`")
    if args.review and not (sys.stdin.isatty() and args.tokens_file != "-"):
        parser.error("--review asks questions as it goes, so it needs a terminal; read tokens from a file or environment variables")

    def progress(result):
        name = (result["workplace"] or {}).get("name") or token_name(result)
        status = "failed" if result["error"] else plural(sum(len(sa["identities"]) for sa in result["service_accounts"]), "identity", "identities")
        print(f"  {clean(name)}: {status}", file=sys.stderr)

    def checked(result):
        # Large workplaces can take minutes, mostly waiting out rate limits; say something every 100.
        count = len(result["service_accounts"])
        if count % 100 == 0:
            name = (result["workplace"] or {}).get("name") or token_name(result)
            print(f"  {clean(name)}: {count} service accounts checked ...", file=sys.stderr)

    print(f"Auditing {len(tokens)} token(s) against {api_host} ...", file=sys.stderr)
    report = build_report(
        tokens, api_host, args.concurrency, {"stale_days": args.stale_days, "max_ttl_seconds": args.max_ttl}, progress,
        args.dashboard_host.rstrip("/"), checked,
    )
    if args.findings_only:
        report["identities"] = [row for row in report["identities"] if row["findings"]]
    if args.review:
        for workplace in report["workplaces"]:
            if workplace["error"]:
                name = (workplace["workplace"] or {}).get("name") or token_name(workplace)
                print(f"  skipped {clean(name)}: {clean(workplace['error'])}", file=sys.stderr)
        run_review(report, args.review, color=sys.stdout.isatty())
        return 0

    if args.format == "json":
        rendered = json.dumps(report, indent=2) + "\n"
    elif args.format == "csv":
        rendered = format_csv(report)
    else:
        rendered = format_text(report, color=not args.output and sys.stdout.isatty())
    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="") as handle:
            handle.write(rendered)
        print(f"Wrote {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(rendered)

    if report["summary"]["workplaces_failed"]:
        return 1
    if args.fail_on:
        threshold = SEVERITIES[: SEVERITIES.index(args.fail_on) + 1]
        if any(f["severity"] in threshold for row in report["identities"] for f in row["findings"]):
            return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
