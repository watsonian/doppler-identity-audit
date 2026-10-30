"""
A fake Doppler API for tests and demos. It serves the three endpoints the audit uses.

Tokens:
  dp.sa.acme       "Acme Production": 105 service accounts (to exercise paging), several identities
  dp.sa.globex     "Globex": one tidy identity
  dp.sa.noperm     answers 403 on service accounts
  dp.sa.big1..3    about 1,000 identities each, for testing at volume
  dp.sa.ratelimited  answers 429 to every other request, otherwise like dp.sa.globex
  anything else    401

Run it on its own with `python3 tests/mock_api.py 8099`.
"""

import json
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

GITHUB = "https://token.actions.githubusercontent.com"


def identity(slug, name, claims, claims_type="exact", ttl=900, last_seen="2026-10-20T10:00:00.000Z", created="2025-01-10T09:00:00.000Z"):
    return {
        "name": name, "slug": slug, "method": "oidc", "ttl_seconds": ttl,
        "created_at": created, "last_seen_at": last_seen,
        "config": {"discovery_url": GITHUB, "claims_type": claims_type, "claims": claims},
    }


def role(identifier, name):
    return {"name": name, "identifier": identifier, "permissions": [], "created_at": "2025-01-01T00:00:00.000Z", "is_custom_role": False, "is_inline_role": False}


ACME_SAS = [
    {"name": "github-deployer", "slug": "00000000-0000-4000-8000-000000000001", "workplace_role": role("collaborator", "Collaborator")},
    {"name": "terraform-admin", "slug": "00000000-0000-4000-8000-000000000002", "workplace_role": role("admin", "Admin")},
] + [
    {"name": f"filler-{i:03d}", "slug": f"00000000-0000-4000-8000-{i:012d}", "workplace_role": role("no_access", "None")}
    for i in range(3, 106)
] + [
    # Lands on page 2, so it's only found if paging works.
    {"name": "zz-last-page", "slug": "00000000-0000-4000-8000-999999999999", "workplace_role": role("collaborator", "Collaborator")},
]

IDENTITIES = {
    "00000000-0000-4000-8000-000000000001": [
        identity("10000000-0000-4000-8000-000000000001", "main branch deploys",
                 {"aud": ["https://github.com/acme"], "sub": ["repo:acme/api:ref:refs/heads/main"]}),
        identity("10000000-0000-4000-8000-000000000002", "any acme repo",
                 {"aud": ["https://github.com/acme"], "sub": ["repo:acme/*"], "repository_owner": ["acme"]}, claims_type="wildcard"),
        identity("10000000-0000-4000-8000-000000000003", "wide open",
                 {"aud": ["*"], "sub": ["*"]}, claims_type="wildcard", ttl=43200, last_seen=None),
    ],
    "00000000-0000-4000-8000-000000000002": [
        identity("10000000-0000-4000-8000-000000000004", "tf cloud",
                 {"aud": ["doppler"], "sub": ["*:workspace:prod:*"]}, claims_type="wildcard", last_seen="2026-01-02T00:00:00.000Z"),
    ],
    "00000000-0000-4000-8000-999999999999": [
        identity("10000000-0000-4000-8000-000000000005", "=HYPERLINK(\"x\")\x1b[31m sneaky",
                 {"aud": ["a"], "sub": ["b"]}),
    ],
    "20000000-0000-4000-8000-000000000001": [
        identity("30000000-0000-4000-8000-000000000001", "release pipeline",
                 {"aud": ["https://github.com/globex"], "sub": ["repo:globex/app:environment:production"]}),
    ],
}

def big_workplace(number, service_accounts=500):
    """A workplace with many service accounts and identities, for testing the UI at volume."""
    import random
    rng = random.Random(number)
    roles = [role("collaborator", "Collaborator")] * 6 + [role("no_access", "None")] * 3 + [role("admin", "Admin")]
    issuers = ["https://token.actions.githubusercontent.com", "https://gitlab.com", "https://oidc.circleci.com/org/0d9f3a",
               "https://kubernetes.default.svc.cluster.local"]
    sas, identities = [], {}
    for i in range(service_accounts):
        slug = f"{number:08d}-0000-4000-8000-{i:012d}"
        team = rng.choice(["api", "web", "data", "infra", "billing", "search", "mobile"])
        sas.append({"name": f"{team}-deployer-{i:03d}", "slug": slug, "workplace_role": rng.choice(roles)})
        found = []
        for j in range(rng.choice([0, 1, 2, 2, 3, 4])):
            issuer = rng.choice(issuers)
            wildcard = rng.random() < 0.35
            repo = f"acme-{number}/{team}-{rng.randint(1, 40)}"
            sub = f"repo:{repo}:" + ("*" if wildcard and rng.random() < 0.5 else rng.choice(["ref:refs/heads/main", "environment:production", "pull_request"]))
            claims = {"aud": [f"https://github.com/acme-{number}"], "sub": [sub]}
            if rng.random() < 0.05 and wildcard:
                claims["sub"] = ["*"]
            if rng.random() < 0.3:
                claims["repository_owner"] = [f"acme-{number}"]
            if rng.random() < 0.15:
                claims["sub"].append(f"repo:{repo}:ref:refs/tags/v*" if wildcard else f"repo:{repo}:ref:refs/heads/release")
            seen = None if rng.random() < 0.15 else f"2026-{rng.randint(1, 10):02d}-{rng.randint(1, 28):02d}T12:00:00.000Z"
            found.append({
                "name": f"{team} {rng.choice(['deploy', 'release', 'test', 'migrate', 'preview'])} {j + 1}",
                "slug": f"{number:08d}-1111-4000-8000-{i * 10 + j:012d}", "method": "oidc",
                "ttl_seconds": rng.choice([300, 900, 900, 1800, 3600, 7200, 43200]),
                "created_at": "2025-03-01T09:00:00.000Z", "last_seen_at": seen,
                "config": {"discovery_url": issuer, "claims_type": "wildcard" if wildcard else "exact", "claims": claims},
            })
        identities[slug] = found
    return sas, identities


WORKPLACES = {
    "dp.sa.acme": {"workplace": {"slug": "acme123", "name": "Acme Production"}, "sas": ACME_SAS},
    "dp.sa.acmedupe": {"workplace": {"slug": "acme123", "name": "Acme Production"}, "sas": ACME_SAS},
    "dp.sa.globex": {
        "workplace": {"slug": "globex456", "name": "Globex"},
        "sas": [{"name": "ci", "slug": "20000000-0000-4000-8000-000000000001", "workplace_role": role("collaborator", "Collaborator")}],
    },
    "dp.sa.noperm": {"workplace": {"slug": "initech", "name": "Initech"}, "sas": None},
}

for _n in (1, 2, 3):
    _sas, _identities = big_workplace(_n)
    IDENTITIES.update(_identities)
    WORKPLACES[f"dp.sa.big{_n}"] = {"workplace": {"slug": f"bigco{_n}", "name": f"BigCo Region {_n}"}, "sas": _sas}


RATE_LIMITED = {"count": 0}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        token = self.headers.get("Authorization", "").removeprefix("Bearer ")
        if token == "dp.sa.ratelimited":
            # Answers like Doppler's rate limiter on every other request, then like Globex.
            RATE_LIMITED["count"] += 1
            if RATE_LIMITED["count"] % 2:
                data = json.dumps({"messages": ["Exceeded rate limit"], "success": False}).encode()
                self.send_response(429)
                self.send_header("Retry-After", "0")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            token = "dp.sa.globex"
        workplace = WORKPLACES.get(token)
        if not workplace:
            return self.send(401, {"messages": ["Invalid Auth token"], "success": False})
        url = urlparse(self.path)
        query = parse_qs(url.query)
        page, per_page = int(query.get("page", ["1"])[0]), int(query.get("per_page", ["20"])[0])

        def paged(items):
            return items[(page - 1) * per_page : page * per_page]

        if url.path == "/v3/me":
            return self.send(200, {"type": "workplace_service_account", "workplace": workplace["workplace"]})
        if url.path == "/v3/workplace/service_accounts":
            if workplace["sas"] is None:
                return self.send(403, {"messages": ["You do not have access to service accounts."], "success": False})
            return self.send(200, {"service_accounts": paged(workplace["sas"]), "success": True})
        match = re.fullmatch(r"/v3/workplace/service_accounts/service_account/([^/]+)/identities", url.path)
        if match:
            return self.send(200, {"identities": paged(IDENTITIES.get(match.group(1), [])), "success": True})
        return self.send(404, {"messages": ["Not found"], "success": False})


def start(port=0):
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


if __name__ == "__main__":
    server = start(int(sys.argv[1]) if len(sys.argv) > 1 else 8099)
    print(f"mock Doppler API on http://127.0.0.1:{server.server_port}")
    threading.Event().wait()
