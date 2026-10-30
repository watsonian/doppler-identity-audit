"""
Web UI for the Doppler service account identity audit.

All Doppler API calls and checks come from identity_audit.py; this file only holds
tokens in memory, runs the audit in a background thread, and serves the page.

Tokens come from DOPPLER_AUDIT_TOKEN_* environment variables. If none are set, the
page asks for them instead. Either way they're held only in memory and never reach
the browser: the page sees each token's label and last four characters, plus the
audit results (identity configuration, no secret values).
"""

import argparse
import json
import os
import secrets
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # running from a checkout
import identity_audit as audit  # noqa: E402

STATIC_DIR = Path(__file__).resolve().parent / "static"
CONTENT_TYPES = {
    ".html": "text/html", ".js": "text/javascript", ".css": "text/css",
    ".svg": "image/svg+xml", ".woff2": "font/woff2", ".txt": "text/plain",
}
# Only files present at startup are served, so request paths never touch the filesystem.
STATIC_FILES = {
    "/" + path.relative_to(STATIC_DIR).as_posix(): path
    for path in STATIC_DIR.rglob("*")
    if path.is_file() and path.suffix in CONTENT_TYPES
}
STATIC_FILES["/"] = STATIC_DIR / "index.html"
MAX_BODY = 1_000_000

# The same settings as the CLI's --stale-days, --max-ttl and --concurrency flags, with the
# limits the page enforces. Startup values come from the environment variables named here.
SETTINGS = {
    "stale_days": {"env": "STALE_DAYS", "default": audit.DEFAULT_OPTIONS["stale_days"], "min": 1, "max": 3650},
    "max_ttl_seconds": {"env": "MAX_TTL_SECONDS", "default": audit.DEFAULT_OPTIONS["max_ttl_seconds"], "min": 30, "max": 43200},
    "concurrency": {"env": "CONCURRENCY", "default": 4, "min": 1, "max": 16},
}


def parse_settings(values, current):
    """Validates new values for SETTINGS; anything not given keeps its current value."""
    settings = dict(current)
    for name, spec in SETTINGS.items():
        if values.get(name) in (None, ""):
            continue
        try:
            number = int(values[name])
        except (TypeError, ValueError):
            raise ValueError(f"{name} must be a whole number") from None
        if not spec["min"] <= number <= spec["max"]:
            raise ValueError(f"{name} must be between {spec['min']} and {spec['max']}")
        settings[name] = number
    return settings


class State:
    """Everything the server remembers. Lives in memory only; a restart forgets pasted tokens."""

    def __init__(self, api_host, dashboard_host, settings=None, env_prefix="DOPPLER_AUDIT_TOKEN_"):
        self.lock = threading.Lock()
        self.api_host = api_host
        self.dashboard_host = dashboard_host
        self.env_prefix = env_prefix
        self.settings = settings or {name: spec["default"] for name, spec in SETTINGS.items()}
        # {"id", "label" (or None), "token", "source", "checking", "workplace", "check_error"}
        self.tokens = []
        self.results = {}  # token id -> that token's workplace summary from the last audit
        self.report = None
        self.report_version = 0  # bumped whenever the report changes
        self.run = None  # {"started_at", "total", "done", "error"} while or after running

    def add_tokens(self, entries, source):
        with self.lock:
            known = {t["token"] for t in self.tokens}
            new = []
            for label, token in entries:
                if token in known:
                    continue
                entry = {"id": secrets.token_hex(6), "label": label, "token": token, "source": source,
                         "checking": True, "workplace": None, "check_error": None}
                self.tokens.append(entry)
                known.add(token)
                new.append((entry["id"], token))
        if new:
            threading.Thread(target=self._identify, args=(new,), daemon=True).start()
        return len(new)

    def _identify(self, new):
        """Asks /v3/me which workplace each new token belongs to, so the page can name it right away."""
        def check(item):
            token_id, token = item
            workplace, error = audit.identify_token(token, self.api_host)
            with self.lock:
                for entry in self.tokens:
                    if entry["id"] == token_id:
                        entry.update(checking=False, workplace=workplace, check_error=error)

        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(check, new))

    def public(self):
        """What the browser may see."""
        with self.lock:
            tokens, first_for_workplace = [], {}
            for t in self.tokens:
                result = self.results.get(t["id"])
                workplace = (result or {}).get("workplace") or t["workplace"]
                name = (workplace or {}).get("name") or t["label"] or audit.token_preview(t["token"])
                slug = (workplace or {}).get("slug")
                if result:
                    status, error = ("failed", result["error"]) if result["error"] else ("audited", None)
                elif t["checking"]:
                    status, error = "checking", None
                elif t["check_error"]:
                    status, error = "invalid", t["check_error"]
                elif slug in first_for_workplace:
                    status, error = "duplicate", f"Same workplace as token {first_for_workplace[slug]}; it's audited once."
                else:
                    status, error = "ready", None
                if slug and slug not in first_for_workplace:
                    first_for_workplace[slug] = t["label"] or audit.token_preview(t["token"])
                tokens.append({
                    "id": t["id"],
                    "name": name,
                    "label": t["label"],
                    "preview": audit.token_preview(t["token"]),
                    "source": t["source"],
                    "workplace": workplace,
                    "status": status,
                    "error": error,
                })
            running = bool(self.run and self.run.get("finished_at") is None)
            # The report can run to megabytes with thousands of identities, so the page polls
            # only this version and fetches /api/report when it changes.
            return {
                "api_host": self.api_host,
                "settings": {**self.settings, "api_host": self.api_host, "dashboard_host": self.dashboard_host, "env_prefix": self.env_prefix},
                "tokens": tokens,
                "busy": running or any(t["checking"] for t in self.tokens),
                "run": self.run,
                "report_version": self.report_version if self.report else None,
            }

    def update_settings(self, settings):
        """Stores new settings and re-applies the checks to the current results straight away,
        so changing a threshold doesn't mean fetching every identity again."""
        with self.lock:
            self.settings = settings
            if self.report:
                self.report = audit.apply_checks(self.report, self.check_options())
                self.report_version += 1

    def check_options(self):
        return {"stale_days": self.settings["stale_days"], "max_ttl_seconds": self.settings["max_ttl_seconds"]}

    def start_audit(self):
        with self.lock:
            if self.run and self.run.get("finished_at") is None:
                return False
            options, concurrency = self.check_options(), self.settings["concurrency"]
            ids = [t["id"] for t in self.tokens]
            entries = [(t["label"], t["token"]) for t in self.tokens]
            self.run = {"started_at": now(), "finished_at": None, "total": len(entries), "done": 0,
                        "service_accounts": 0, "error": None}
        threading.Thread(target=self._audit, args=(ids, entries, options, concurrency), daemon=True).start()
        return True

    def _audit(self, ids, entries, options, concurrency):
        def progress(_result):
            with self.lock:
                self.run["done"] += 1

        def checked(_result):
            with self.lock:
                self.run["service_accounts"] += 1

        try:
            report = audit.build_report(entries, self.api_host, concurrency, options, progress, self.dashboard_host, checked)
            with self.lock:
                # Settings changed during the run apply to its results too.
                self.report = audit.apply_checks(report, self.check_options())
                self.report_version += 1
                # build_report keeps the order of its input, so results line up with token ids.
                self.results = dict(zip(ids, report["workplaces"]))
        except Exception as error:  # surface anything unexpected in the UI rather than losing it in a thread
            with self.lock:
                self.run["error"] = f"{error.__class__.__name__}: {error}"
        finally:
            with self.lock:
                self.run["finished_at"] = now()


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def make_handler(state, allowed_hosts):
    class Handler(BaseHTTPRequestHandler):
        server_version = "identity-audit"

        def log_message(self, fmt, *args):
            sys.stderr.write(f"{self.command} {self.path.split('?')[0]} -> {args[1] if len(args) > 1 else ''}\n")

        # --- guards -------------------------------------------------------

        def host_ok(self):
            # Blocks DNS rebinding: another site's page can't reach us under its own hostname.
            host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]")
            return host in allowed_hosts

        def write_ok(self):
            # Other sites' pages can't set custom headers on cross-origin requests without a CORS
            # preflight, which this server never approves.
            return self.headers.get("X-Identity-Audit") == "1"

        # --- responses ----------------------------------------------------

        def send(self, status, body, content_type="application/json", extra_headers=None):
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(status)
            binary = content_type.startswith("font/")
            self.send_header("Content-Type", content_type if binary else f"{content_type}; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
            for key, value in (extra_headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(data)

        def fail(self, status, message):
            self.send(status, {"error": message})

        def read_json(self):
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                raise ValueError("request too large")
            return json.loads(self.rfile.read(length) or b"{}")

        # --- routes -------------------------------------------------------

        def do_GET(self):
            if not self.host_ok():
                return self.fail(403, "unexpected Host header; set ALLOWED_HOSTS to add hostnames")
            path = self.path.split("?")[0]
            if path in STATIC_FILES:
                file = STATIC_FILES[path]
                return self.send(200, file.read_bytes(), CONTENT_TYPES[file.suffix])
            if path == "/api/state":
                return self.send(200, state.public())
            if path == "/api/report":
                with state.lock:
                    report = state.report
                if not report:
                    return self.fail(404, "run an audit first")
                return self.send(200, report)
            if path in ("/api/export.csv", "/api/export.json"):
                with state.lock:
                    report = state.report
                if not report:
                    return self.fail(404, "run an audit first")
                stamp = report["generated_at"].replace(":", "").replace("+0000", "Z")
                if path.endswith(".csv"):
                    body, kind, ext = audit.format_csv(report).encode(), "text/csv", "csv"
                else:
                    body, kind, ext = (json.dumps(report, indent=2) + "\n").encode(), "application/json", "json"
                disposition = f'attachment; filename="identity-audit-{stamp}.{ext}"'
                return self.send(200, body, kind, {"Content-Disposition": disposition})
            return self.fail(404, "not found")

        def do_POST(self):
            if not self.host_ok() or not self.write_ok():
                return self.fail(403, "forbidden")
            try:
                body = self.read_json()
            except ValueError as error:
                return self.fail(400, str(error))
            path = self.path.split("?")[0]

            if path == "/api/tokens":
                try:
                    entries = audit.parse_tokens(str(body.get("text", "")), str(body.get("source") or "pasted"))
                except ValueError as error:
                    return self.fail(400, str(error))
                added = state.add_tokens(entries, "pasted")
                return self.send(200, {"added": added, "skipped": len(entries) - added})
            if path == "/api/tokens/remove":
                with state.lock:
                    state.tokens = [t for t in state.tokens if t["id"] != body.get("id")]
                    state.results.pop(body.get("id"), None)
                return self.send(200, {})
            if path == "/api/tokens/clear":
                with state.lock:
                    state.tokens = []
                    state.results = {}
                    state.report = None
                    state.run = None
                return self.send(200, {})
            if path == "/api/audit":
                with state.lock:
                    if not state.tokens:
                        return self.fail(400, "add at least one token first")
                if not state.start_audit():
                    return self.fail(409, "an audit is already running")
                return self.send(202, {})
            if path == "/api/settings":
                with state.lock:
                    current = state.settings
                try:
                    settings = parse_settings(body, current)
                except ValueError as error:
                    return self.fail(400, str(error))
                state.update_settings(settings)
                return self.send(200, settings)
            return self.fail(404, "not found")

    return Handler


def main():
    parser = argparse.ArgumentParser(description="Web UI for the Doppler service account identity audit.")
    parser.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8080")))
    parser.add_argument("--env-prefix", default=os.environ.get("TOKEN_ENV_PREFIX", "DOPPLER_AUDIT_TOKEN_"))
    parser.add_argument("--api-host", default=os.environ.get("DOPPLER_API_HOST", audit.DEFAULT_API_HOST))
    parser.add_argument("--dashboard-host", default=os.environ.get("DOPPLER_DASHBOARD_HOST", audit.DEFAULT_DASHBOARD_HOST))
    args = parser.parse_args()

    try:
        defaults = {name: spec["default"] for name, spec in SETTINGS.items()}
        settings = parse_settings({name: os.environ.get(spec["env"]) for name, spec in SETTINGS.items()}, defaults)
        state = State(audit.check_api_host(args.api_host), args.dashboard_host.rstrip("/"), settings, args.env_prefix)
        count = state.add_tokens(audit.tokens_from_env(args.env_prefix), "environment")
    except (ValueError, OSError) as error:
        sys.exit(f"error: {error}")

    allowed_hosts = {"localhost", "127.0.0.1", "::1"} | {h.strip() for h in os.environ.get("ALLOWED_HOSTS", "").split(",") if h.strip()}
    server = ThreadingHTTPServer((args.host, args.port), make_handler(state, allowed_hosts))
    if count:
        print(f"Loaded {count} token(s) from {args.env_prefix}* environment variables.", file=sys.stderr)
    else:
        print(f"No {args.env_prefix}* environment variables set; add tokens on the setup page.", file=sys.stderr)
    print(f"Open http://localhost:{args.port}", file=sys.stderr)
    if os.environ.get("AUTO_RUN", "").lower() in ("1", "true", "yes") and count:
        state.start_audit()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
