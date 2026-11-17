# VibeLocked LeakCheck Scan (GitHub Action)

Free, read-only GitHub Action that fails your build when a leaked API key, a committed `.env` file or a Supabase service role key turns up in your repo, your build output, or your live app. Made for apps built with AI coding tools (Lovable, Bolt, v0, Cursor, Replit, Claude Code), where a key can slip into frontend code without anyone noticing.

- **Free.** MIT licensed. No account, no API key, no paid plan needed.
- **Read-only.** Needs only `contents: read`. It never writes to your repo, opens issues or comments.
- **Nothing is uploaded.** Files are scanned on the runner. Values are masked in logs and the job summary.
- **No dependencies.** One JavaScript file on Node 24.

Want a check of the deployed app's database too? [VibeLocked LeakCheck](https://vibelocked.com/leakcheck/?ref=github-action) scans a live URL for Supabase tables the public key can read and open Firebase data, free.

## Quick start

```yaml
# .github/workflows/leakcheck.yml
name: LeakCheck
on: [push, pull_request]
permissions:
  contents: read
jobs:
  leakcheck:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: karlaCastro00/vibelocked-leakcheck-action@v1
```

That scans the whole checkout and fails the job if it finds a likely real secret.

### Scan what ships to the browser

Keys marked public (`NEXT_PUBLIC_`, `VITE_`, `PUBLIC_`) never appear in git, but they end up in your bundle. Scan the build output after your build step:

```yaml
      - run: npm ci && npm run build
      - uses: karlaCastro00/vibelocked-leakcheck-action@v1
        with:
          path: dist            # or .next/static, build, out
```

### Check the live app after deploy

```yaml
      - uses: karlaCastro00/vibelocked-leakcheck-action@v1
        with:
          path: .
          url: https://my-app.example.com
```

With `url`, the action makes read-only GET requests to the page, up to 20 same-origin scripts, their source maps (up to 5), `/.env` and `/.git/config`. It does not log in, post forms or send anything else.

### Report only

```yaml
        with:
          fail-on: none   # high (default), warn, or none
```

## Inputs

| Input | Default | What it does |
|---|---|---|
| `path` | `.` | Folder to scan, inside the workspace. |
| `url` | empty | Optional public URL of the deployed app to check. |
| `fail-on` | `high` | `high` fails on likely real secrets. `warn` also fails on possible secrets to review. `none` never fails. |
| `max-files` | `5000` | Maximum number of files to read. |

## Outputs

| Output | Meaning |
|---|---|
| `high` | Likely real secrets found |
| `warn` | Possible secrets to review |
| `total` | `high` + `warn` |

## What it finds

High (fails by default):
- OpenAI, Anthropic, Stripe and Clerk secret keys, Stripe restricted keys, webhook signing secrets (`whsec_`)
- Supabase secret keys (`sb_secret_`) and Supabase **service role** JWTs (decoded, so the public anon key is not flagged)
- AWS access key IDs and secret access keys, GitHub and GitLab tokens, Slack tokens and webhooks, Discord webhooks
- SendGrid, Resend, Hugging Face, Groq, xAI and Replicate keys
- Private key blocks, database URLs with a password
- `.env` files present in the scanned folder (`.env.example`, `.env.sample` and `.env.template` are fine)
- With `url`: a public `/.env` or `/.git/config`

Review (warn):
- Google API keys (fine in a Firebase config if restricted)
- Possible Twilio keys
- Values assigned to names like `*_SECRET`, `*_TOKEN`, `*_PASSWORD`, `*_API_KEY`
- With `url`: a public production source map

Not flagged: Stripe and Clerk publishable keys, the Supabase anon or publishable key. They are meant for the browser, but only safe if Row Level Security is on.

## Limits

- It is a pattern scan of current files, not of git history. A key deleted in a later commit is still in history: use [Gitleaks](https://github.com/gitleaks/gitleaks), [TruffleHog](https://github.com/trufflesecurity/trufflehog) or GitHub secret scanning for history.
- It does not check whether a key still works, and it cannot see your database rules. A clean result is not a guarantee.
- It skips `node_modules`, `.git`, lockfiles, binary files and files over 2 MB.
- If it finds a real key: **rotate it at the provider first.** Deleting the commit does not un-leak it. See [the first hour after an API key leaks](https://vibelocked.com/guides/first-hour-after-an-api-key-leaks/).

## Pin a version

`@v1` follows compatible updates. For the strictest supply-chain setup, pin the full commit SHA of a release.

## How it compares

Code scanners such as GitGuardian, TruffleHog and Gitleaks go deeper on git history. This action is a fast free gate for repos and build output, plus a light live check. See [LeakCheck vs GitGuardian, TruffleHog and Gitleaks](https://vibelocked.com/guides/leakcheck-vs-gitguardian-trufflehog-gitleaks/).

## About

Made by [VibeLocked](https://vibelocked.com/?ref=github-action), an independent security site for people building apps with AI coding tools. Issues and pull requests welcome. MIT license.
