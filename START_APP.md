# START_APP.md — how to run and probe this app

> **Build team:** fill in every `<...>` below once your app runs. Other teams use this file to
> start your app and probe it during Break. Keep it accurate — a break is filed against the app a
> breaker can actually start from these instructions.

## What this app is

- **App:** A file upload + preview service — upload a file, get a shareable URL, preview text
  inline (escaped), images inline, and download anything else (menu #18).
- **Stack:** Python + Flask.

## Start it

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run it (either works)
python app.py
#   or
flask --app app run --port 8000
```

- **Base URL:** http://127.0.0.1:8000
- **Stop it:** Ctrl-C in the terminal running it.

## How to interact with it

- **Main endpoints / pages:**
  - `GET  /` — upload form + list of recent public files.
  - `POST /upload` — upload a file. Form fields: `file` (the file), `visibility` (`public` or
    `private`). Redirects to the preview page; private uploads get a one-time `?token=...`.
  - `GET  /file/<id>` — preview page (text escaped, image inline, other → download link).
    Private files require `?token=<owner_token>`.
  - `GET  /raw/<id>` — the raw bytes, served as `text/plain` or `image/*` (never `text/html`) with
    `X-Content-Type-Options: nosniff`. Private files require `?token=<owner_token>`.
  - `GET  /api/files` — JSON list of public files (ids/names/sizes only; no content, no tokens).
- **Accounts / credentials for legitimate use:** none — access to a private file is by its
  unguessable owner token (capability URL), handed to the uploader once on creation.
- **A benign request that should succeed:**

  ```bash
  # Upload a public text file, then follow the redirect to its preview:
  echo 'hello world' > /tmp/hello.txt
  curl -sL -F "file=@/tmp/hello.txt" -F "visibility=public" http://127.0.0.1:8000/upload

  # Or just list public files as JSON:
  curl -s http://127.0.0.1:8000/api/files
  ```

## For breakers

Attack this **running app over HTTP** — do **not** read this repo's source or `secret/` to find a
break. See [AGENTS_BREAK.md](AGENTS_BREAK.md) for the rules and your AI agent's instructions, and
[SPEC.md](SPEC.md) for the five properties (P1–P5) you are probing for.

The headline surfaces for this target (menu #18) are **path traversal** and **content-type XSS**:
the canary lives in a protected record no route hands a token for; uploaded bytes are never served
as `text/html`; and no filesystem path is ever built from your input (blobs live in SQLite keyed by
a generated id).
