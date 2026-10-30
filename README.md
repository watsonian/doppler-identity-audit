# Doppler service account identity audit

This tool lists every [service account identity](https://docs.doppler.com/docs/service-account-identities) across all of your Doppler workplaces in one place. It shows how each identity is configured and flags settings worth a second look.

It comes in two forms, and both run the same audit code:

| | What it is | Use it when |
|---|---|---|
| [`identity_audit.py`](identity_audit.py) | A single Python script with no dependencies. It writes a text, CSV or JSON report. | You want something short to read before running it, or you want to run it in CI. |
| [`app/`](app/) | A Docker container that serves a web page. You can filter and search, mark identities as reviewed, and export the results. | You want to work through the audit visually. |

Both only read data. They send nothing but `GET` requests to the Doppler API, and they never change a workplace.

## Create a token for each workplace

A Doppler API token belongs to a single workplace, so you need one token per workplace. For the least access, create a service account in each workplace that does only this:

1. In the workplace, go to **Team → Roles** and create a custom workplace role with the **View Service Account Identities** permission. Doppler adds the permissions it depends on, **View Service Accounts** and **Team**.
1. Go to **Team → Service Accounts** and create a service account, such as `identity-auditor`, with that role.
1. Create an API token for the service account. Give it an expiry if the audit is a one-off.

A personal token (`dp.pt.…`) from a user who can view service accounts also works.

## Keep the tokens in Doppler

Store the tokens as secrets in a Doppler config of their own, and have Doppler pass them to the tool as environment variables. Then the tokens are never written to a file, and you can rotate or revoke them in one place.

1. Create a project for the audit, such as `identity-audit`, in a workplace you administer, and pick a config, such as `prd`.
1. Add one secret per workplace, named `DOPPLER_AUDIT_TOKEN_<NAME>`, with that workplace's token as the value. For example, `DOPPLER_AUDIT_TOKEN_ACME_PROD` and `DOPPLER_AUDIT_TOKEN_ACME_STAGING`.

Both versions read every environment variable whose name starts with `DOPPLER_AUDIT_TOKEN_`. You don't need to say which workplace a token is for: the tool asks the API (`GET /v3/me`) and uses the workplace's name. The rest of the variable's name, such as `ACME_PROD`, becomes the token's label. It's useful for telling tokens apart when one is invalid and so has no workplace name.

If two tokens belong to the same workplace, the workplace is audited once and the second token is reported as a duplicate.

## Option 1: the command-line script

You need Python 3.9 or later. No packages are required.

```sh
doppler run --project identity-audit --config prd -- python3 identity_audit.py
```

The tool's job is to put every identity's full configuration in front of a person who checks it. The script can list every identity at once, or go through them one at a time and record your decision for each. The web app lists every identity with a decision for each; see [Option 2](#option-2-the-web-app).

### List every identity

By default, the script prints every identity's whole configuration, grouped by workplace and service account, followed by a summary:

```text
== Acme Production (acme123)   token: acme-production
   106 service accounts, 5 identities

   Service account: github-deployer   role: Collaborator
   https://dashboard.doppler.com/workplace/acme123/team/service_accounts/…
     - Identity: wide open   (OIDC)
         issuer:          https://token.actions.githubusercontent.com
         claim matching:  wildcard (* and ? match any characters)
         required claims (any one value per claim):
           aud:           *
           sub:           *
         token TTL:       12h
         created:         2025-01-10
         last used:       never
         identity ID:     10000000-0000-4000-8000-000000000003
         [HIGH] claim 'aud' accepts any value ('*')
         [HIGH] claim 'sub' accepts any value ('*')
         [LOW] token TTL is 12h, longer than 1h
         [LOW] never used, created 2025-01-10
```

Use `--format csv` for a spreadsheet with one row per identity.

### Review one at a time

```sh
doppler run --project identity-audit --config prd -- python3 identity_audit.py --review review.csv
```

The script shows one identity per screen, starting with the most serious automated findings, and asks what to do:

```text
[a]pprove  [f]lag  [n]ote  [enter] next  [p]revious  [q]uit >
```

- **a** approves the identity and **f** flags it for follow-up, asking for an optional reason. Either one moves on to the next identity without a decision.
- **n** adds a note without deciding. **Enter** and **p** move forward and back. **q** stops.

`review.csv` is rewritten after every answer. It lists every identity with its configuration, `decision` (`approved`, `flagged` or `not reviewed`), `note` and `updated_at`, so it doubles as the audit record. Run the same command again to pick up where you left off. If an identity's configuration has changed since you decided, its decision is cleared and it comes back for review.

### Passing tokens

The script reads tokens from environment variables named `DOPPLER_AUDIT_TOKEN_<NAME>`, so `doppler run` is all it needs; see [Keep the tokens in Doppler](#keep-the-tokens-in-doppler). It doesn't accept tokens as arguments, because other users can see arguments in `ps` and shells save them in history.

The script can also read tokens from a file or standard input with `--tokens-file`, one per line, but environment variables are preferred: a file of tokens is one more copy to protect and to clean up afterwards.

### Options

| Option | Description |
|---|---|
| `-t`, `--tokens-file <path>` | Also reads tokens from this file, or from standard input if the path is `-`: one per line, optionally after a label. Environment variables are preferred. |
| `--env-prefix <prefix>` | Reads tokens from environment variables with this prefix. The default is `DOPPLER_AUDIT_TOKEN_`. |
| `-f`, `--format text\|csv\|json` | Sets the output format. The default is `text`. CSV has one row per identity and opens in a spreadsheet. |
| `-o`, `--output <path>` | Writes the report to this file instead of standard output. |
| `--review <file>` | Goes through identities one at a time and records a decision for each in this CSV file. See [Review one at a time](#review-one-at-a-time). Needs a terminal, so tokens can't come from standard input. |
| `--findings-only` | Leaves out identities that have no findings. |
| `--stale-days <n>` | Flags identities that haven't been used for this many days. The default is 90. |
| `--max-ttl <seconds>` | Flags identities whose token TTL is longer than this. The default is 3600 (one hour). |
| `--fail-on high\|medium\|low\|info` | Exits with `3` if any finding is at least this severe. Useful in scheduled CI jobs. |
| `--concurrency <n>` | Sets how many workplaces are audited in parallel. The default is 4. |
| `--api-host <url>` | Sets the API host, for example for a self-hosted instance. You can also use `DOPPLER_API_HOST`. The host must use `https`, except for `localhost`. |
| `--dashboard-host <url>` | Sets the dashboard host used in links. |

The script exits with `0` on success, `1` if any workplace couldn't be audited, `2` for a usage error, and `3` when `--fail-on` matches.

## Option 2: the web app

You need Docker. Build the image once:

```sh
docker compose build        # or: docker build -f app/Dockerfile -t doppler-identity-audit .
```

You can give the app tokens in either of two ways.

### Pass tokens from Doppler

This starts the app with the tokens from your Doppler config as environment variables, and runs the audit straight away:

```sh
docker run --rm -p 127.0.0.1:8080:8080 -e AUTO_RUN=true \
  --env-file <(doppler secrets download --project identity-audit --config prd --no-file --format docker) \
  doppler-identity-audit
```

`doppler secrets download --no-file` prints the secrets instead of saving them, and `<(...)` hands them to Docker through a pipe, so nothing is written to disk. That syntax needs bash or zsh. The download also includes variables such as `DOPPLER_PROJECT`, which the app ignores.

Open <http://localhost:8080>. The results are usually waiting by the time the page loads. Click **Run Again** to refresh them.

### Enter tokens on the page

Start the app without any tokens:

```sh
docker compose up
```

Open <http://localhost:8080>. The page opens on a setup screen. Paste the tokens, one per line, and click **Start Audit**. A label before a token is optional, for example `acme-prod dp.sa.xxxx`.

Tokens entered this way are held in the container's memory only. They aren't written to disk and they're gone when the container stops, so you enter them again next time.

### What the page does

The page uses Doppler's look, in a light or dark theme to match your system. The moon or sun button in the header switches between them.

- **Summary:** totals for workplaces and identities, how many identities are approved, flagged or not reviewed yet, and the automated findings by severity. A banner lists any workplace that couldn't be audited, with the reason.
- **List view:** one row per identity, with each setting in its own aligned column: the identity and its service account and role, the provider and claim matching, the audience, the subject and any other required claims (every allowed value), the token TTL, when it was last seen, and the automated findings. Identities are grouped under a row for each workplace, with its decision counts, and the most serious findings come first. The column headers and the current workplace's row stay at the top while you scroll, and workplaces can be collapsed.

  Settings worth a second look are highlighted where they appear: a wildcard (`*` or `?`) in a claim is marked yellow, a claim that accepts any value is marked red, and an Owner or Admin role, a long TTL or an identity that hasn't been used recently is shown in yellow text. Each row has **Approve** and **Flag** buttons, and a coloured edge shows its decision. Select a row to see why it was flagged, then the issuer URL, creation date, identity ID and a box for notes.
- **Why It's Flagged:** the first thing in an identity's details. Each finding is listed with its severity, its name, the exact value that triggered it, such as ``claim 'sub' accepts any value ('*')``, and why it matters. The token TTL and last-seen values are also marked with a coloured dot when a finding is about them.
- **About Findings:** a guide to every automated finding, with its severity, when it's flagged (using the thresholds in effect) and why it matters. Open it with **About Findings** next to the filters.
- **Filters:** tabs filter by automated finding, including **With Findings** for any identity with at least one. You can also search by name, issuer, claim or note, pick a workplace, or show only identities that are approved, flagged or not reviewed. Use them to review one workplace at a time, or only the high findings.
- **Decisions:** saved in your browser, so they survive a page reload or a container restart but not a different browser. A decision is cleared when the identity's configuration changes, so an edited identity comes back for review.
- **Workplace tokens:** each token's workplace, label, last four characters and status. The app checks every token with `GET /v3/me` as soon as it's added, so the workplace name appears straight away, before any audit. The status shows whether the token is **Connected**, **Invalid** (with the API's reason), or a **Duplicate** of another token for the same workplace, and after an audit whether it was **Audited** or **Failed**. Connected only means the token is valid; a token without the View Service Account Identities permission is reported when the audit runs. You can add or remove tokens and change the thresholds for flagging here. Removing every token returns you to the setup screen.
- **Audit Settings:** the script's flags as settings. See [Settings](#settings).
- **Export Review:** downloads a CSV of every identity with its configuration, automated findings, decision and note: the record of the audit. **Export JSON** downloads the raw results in the same format as the script's `--format json`.

The page makes no requests outside the container. It bundles Latin subsets of the Inter and Roboto Mono fonts (SIL Open Font License 1.1, licence files in `app/static/fonts/`) and FontAwesome Free Solid icons (CC BY 4.0, [fontawesome.com/license/free](https://fontawesome.com/license/free)).

### Container settings

Set these with `-e` on `docker run`, or under `environment` in `compose.yaml`:

| Variable | Description |
|---|---|
| `DOPPLER_AUDIT_TOKEN_<NAME>` | One token per variable. `<NAME>` is the label. |
| `TOKEN_ENV_PREFIX` | Changes the `DOPPLER_AUDIT_TOKEN_` prefix. |
| `AUTO_RUN` | Set to `true` to start the audit when the container starts. |
| `STALE_DAYS`, `MAX_TTL_SECONDS`, `CONCURRENCY` | Starting values for the [settings](#settings). |
| `DOPPLER_API_HOST`, `DOPPLER_DASHBOARD_HOST` | Override the API and dashboard hosts. |
| `ALLOWED_HOSTS` | Adds hostnames the page can be opened under, separated by commas. Only `localhost` and `127.0.0.1` are allowed by default. |

### Settings

The **Audit Settings** section at the bottom of the page, also reached with the **Settings** button, has the script's flags:

| In the app | In the script | Default | Takes effect |
|---|---|---|---|
| Flag identities unused for (days) | `--stale-days` | 90 | Immediately |
| Flag token TTLs longer than (minutes) | `--max-ttl` (seconds) | 60 minutes | Immediately |
| Workplaces audited at once | `--concurrency` | 4 | Next run |
| API host, dashboard host | `--api-host`, `--dashboard-host` | Doppler's | At container start (`DOPPLER_API_HOST`, `DOPPLER_DASHBOARD_HOST`) |
| Token variable prefix | `--env-prefix` | `DOPPLER_AUDIT_TOKEN_` | At container start (`TOKEN_ENV_PREFIX`) |

New thresholds are applied to the results you already have as soon as you save them, so you don't need to fetch everything again. The hosts and the prefix are shown but can't be changed from the page, so that a web page can never send your tokens somewhere else.

The other flags map to the page like this: `--tokens-file` is pasting tokens on the setup page or with **Add Tokens**, `--review` is the **Approve** and **Flag** buttons on each identity with **Export Review**, `--findings-only` is the **With Findings** tab, and `--format` and `--output` are **Export Review** and **Export JSON**. `--fail-on` sets the script's exit code for CI jobs, so it has no equivalent in the app.

### How the app protects tokens

- Tokens are held only in the server process's memory, whether they came from the environment or the setup page. The browser never receives them back; the page sees only the workplace, the label and the last four characters.
- Compose publishes the port on `127.0.0.1` only, so other machines can't reach the page.
- The server rejects requests whose `Host` header isn't an allowed hostname, which blocks DNS rebinding. Requests that change anything must carry a custom header, which other websites can't send.
- The page's Content Security Policy allows only its own script and style, and all data from Doppler is added to the page as text, never as HTML.
- The container runs as a non-root user on a read-only filesystem, with all Linux capabilities dropped.

### Large workplaces

The app is built for thousands of identities. It fetches the report once rather than on every refresh, draws the list in batches as you scroll, and updates only the row you change when you approve or flag an identity. Tested with about 3,000 identities across five workplaces: the first rows appear in about a tenth of a second, and searching, filtering and deciding each take well under a quarter of a second.

The audit itself takes longer for a large workplace, because it makes one API request per service account and Doppler limits each token to 240 or more read requests a minute, depending on the plan. A workplace with 1,000 service accounts takes a few minutes. When the limit is reached, both versions wait until Doppler allows more requests and then carry on, and they show how many service accounts they've checked so far. Workplaces are audited four at a time, and each has its own token and its own limit.

## What gets flagged

The app has the same table under **About Findings**, with the thresholds in effect filled in. Every finding in the JSON output names its `rule`, `title`, `severity`, the `field` it's about and a `message` with the specific value, and the report lists the `rules` it was checked against.

The findings are prompts for review, not proof of a problem. An identity can be set up correctly and still be flagged, and an identity with no findings still needs a person to check that its issuer and claims match the workload it's meant for.

| Severity | Finding | Why it matters |
|---|---|---|
| High | A claim accepts any value, such as `sub` set to `*`, when claims use wildcard matching | Any token from that issuer passes the check. For a shared issuer such as GitHub Actions, that means any repository on GitHub. |
| Medium | A claim value starts with `*` | Patterns like `*:prod:*` can match subjects you didn't intend, such as another organization's. |
| Medium | The service account has the Owner or Admin workplace role | Any workload that matches the identity gets that level of access to the workplace. |
| Low | `sub` contains a wildcard, such as `repo:acme/*` | This is often intended. Confirm that the scope is as narrow as it can be. |
| Low | The token TTL is longer than `--max-ttl` | Tokens issued to the workload stay valid for longer. |
| Low | The identity hasn't been used for `--stale-days`, or never has | It may belong to a workload that no longer exists and could be removed. |
| Info | The identity uses an auth method other than OIDC | The tool only knows how to check OIDC identities, so review it by hand. Doppler supports only OIDC today. |

Wildcards are flagged only when an identity uses wildcard matching. With exact matching, `*` is just a character.

The audit covers each service account's workplace role but not its project access. To review project access, open the service account in Doppler using the link in the report.

## Development

The tests use a mock Doppler API in [`tests/mock_api.py`](tests/mock_api.py), so they need no tokens or network access:

```sh
cd tests && python3 -m unittest -v
```

To try the web app against the mock API without Docker:

```sh
python3 tests/mock_api.py 8099 &
DOPPLER_AUDIT_TOKEN_ACME=dp.sa.acme DOPPLER_AUDIT_TOKEN_GLOBEX=dp.sa.globex AUTO_RUN=1 \
  python3 app/server.py --api-host http://127.0.0.1:8099
```

Leave out the variables to see the setup screen. The mock accepts `dp.sa.acme`, `dp.sa.globex` and `dp.sa.noperm`.
