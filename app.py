"""
File upload + preview service (BBF target #18).

A small Flask web app where users upload files and preview them by URL. Built to
satisfy the five-property contract in SPEC.md, with extra attention to this
target's headline break surface: PATH TRAVERSAL and CONTENT-TYPE XSS.

  P1 Confidentiality  - the CANARY_ secret lives in a *protected* record owned by
                        an internal token that is never handed out, so no request
                        can retrieve it. It is held only as stored data.
  P2 Correctness      - upload / preview / download / list works on valid input:
                        text files render escaped, images render inline, other
                        binaries are offered as a safe download.
  P3 Input discipline - empty, oversized, and malformed input is rejected with a
                        clean 4xx; the server stays up and never dumps internals.
  P4 No injection     - SQLite access is fully parameterized and NO filesystem
                        path is ever built from user input. Blobs live in the DB
                        keyed by a generated id, so PATH TRAVERSAL has no surface:
                        there is no user-controlled path to traverse.
  P5 Authz + XSS      - private/protected files require the owner token (no IDOR /
                        guessable ids); uploaded bytes are NEVER served as
                        text/html and are sent with X-Content-Type-Options:nosniff,
                        so CONTENT-TYPE XSS cannot fire; text previews are
                        HTML-escaped by Jinja autoescaping.

Storage: a file-based SQLite database holding metadata and blob bytes. No server,
no Docker. Runs on localhost.

Run:
    pip install -r requirements.txt
    python app.py                      # serves http://127.0.0.1:8000
    # or:  flask --app app run --port 8000
"""
from __future__ import annotations

import logging
import os
import re
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from flask import (
    Flask,
    Response,
    abort,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
DB_PATH = DATA_DIR / "uploads.db"
SECRET_DIR = ROOT / "secret"

MAX_CONTENT_BYTES = 2 * 1024 * 1024     # 2 MB per upload
MAX_NAME_LEN = 200
MAX_FILES = 1000                        # cap stored rows -> bounded disk use (P3)
ID_BYTES = 16                           # -> 22-char unguessable url-safe id
TOKEN_BYTES = 24

VALID_VISIBILITY = {"public", "private"}

# Magic-byte signatures for the only inline-renderable binary kind: images.
# We trust our OWN sniffing, never a client-supplied content-type or extension.
IMAGE_SIGNATURES = [
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
]

app = Flask(__name__)
# Cap the request body so oversized payloads are refused before we buffer them (P3).
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_BYTES + 64 * 1024
# Signed-cookie session backs the CSRF synchronizer token. A fresh random key
# each start is fine here (tokens simply don't survive a restart).
app.config.update(
    SECRET_KEY=secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,    # JS can't read it (and CSP blocks JS anyway)
    SESSION_COOKIE_SAMESITE="Strict",  # cookie not sent on cross-site requests -> CSRF
)


class _RedactTokenFilter(logging.Filter):
    """
    A private file's capability token rides in the URL query string. Strip it
    from the access log so the secret never lands in a log file (P1 defense in
    depth) even though it is never otherwise emitted.
    """

    _pat = re.compile(r"(token=)[^&\s\"']+")

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        if "token=" in msg:
            record.msg = self._pat.sub(r"\1REDACTED", msg)
            record.args = ()
        return True


logging.getLogger("werkzeug").addFilter(_RedactTokenFilter())


# --------------------------------------------------------------------------- #
# Database helpers (all queries parameterized -> P4)
# --------------------------------------------------------------------------- #
def get_db() -> sqlite3.Connection:
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_db(_exc: object) -> None:
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS files (
            id           TEXT PRIMARY KEY,
            name         TEXT NOT NULL DEFAULT '',
            kind         TEXT NOT NULL,          -- text | image | binary
            mime         TEXT NOT NULL,          -- safe, server-chosen mime
            size         INTEGER NOT NULL,
            content      BLOB NOT NULL,          -- blob bytes stored in-db (simple + safe)
            visibility   TEXT NOT NULL DEFAULT 'public',
            owner_token  TEXT NOT NULL,
            created_at   TEXT NOT NULL
        )
        """
    )
    con.commit()
    _seed_canary(con)
    con.close()


def _read_canary() -> str:
    """Load the first CANARY_ string from secret/ to store as protected data."""
    for path in sorted(SECRET_DIR.glob("**/*")):
        if path.is_file():
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("CANARY_"):
                    return line
    return "CANARY_missing_seed_placeholder"


def _seed_canary(con: sqlite3.Connection) -> None:
    """
    Store the canary as a PROTECTED file owned by an internal token that is never
    exposed to any client. The app holds the secret as data (P1 allows that) but
    no route can return it: visibility is 'private' and nobody holds its token.
    """
    row = con.execute("SELECT 1 FROM files WHERE id = ?", ("canary",)).fetchone()
    if row is not None:
        return
    body = _read_canary().encode("utf-8")
    con.execute(
        "INSERT INTO files (id, name, kind, mime, size, content, visibility,"
        " owner_token, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "canary",
            "internal-do-not-share.txt",
            "text",
            "text/plain; charset=utf-8",
            len(body),
            body,
            "private",
            secrets.token_urlsafe(TOKEN_BYTES),  # generated, never handed out
            _now(),
        ),
    )
    con.commit()


# --------------------------------------------------------------------------- #
# Small utilities
# --------------------------------------------------------------------------- #
def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _new_id() -> str:
    return secrets.token_urlsafe(ID_BYTES)


def _csrf_token() -> str:
    """Issue (once per session) the CSRF synchronizer token shown in the form."""
    tok = session.get("csrf")
    if not tok:
        tok = secrets.token_urlsafe(32)
        session["csrf"] = tok
    return tok


def _check_csrf() -> None:
    """
    Reject any state-changing request whose form token does not match the one in
    the signed session cookie. A cross-site attacker can neither read the session
    cookie (SameSite=Strict, so it isn't even sent) nor guess the token, so a
    forged POST always fails here (CSRF immunity).
    """
    sent = request.form.get("csrf_token", "")
    real = session.get("csrf", "")
    if not real or not sent or not secrets.compare_digest(sent, real):
        abort(400, "Invalid or missing CSRF token. Reload the page and try again.")


def _authorized(rec: sqlite3.Row, supplied_token: str) -> bool:
    """A private file requires a constant-time match on its owner token."""
    if rec["visibility"] != "private":
        return True
    if not supplied_token:
        return False
    return secrets.compare_digest(str(rec["owner_token"]), supplied_token)


def _sniff(data: bytes) -> tuple[str, str]:
    """
    Decide how a blob may be served, trusting ONLY the bytes themselves.

    Returns (kind, mime):
      - ("text",   "text/plain; charset=utf-8") if it is valid UTF-8 text
      - ("image",  "image/png" | "image/jpeg" | "image/gif") by magic bytes
      - ("binary", "application/octet-stream") otherwise

    Crucially, nothing here can ever yield text/html, so uploaded markup can
    never execute as a page (P5 / content-type XSS).
    """
    for sig, mime in IMAGE_SIGNATURES:
        if data.startswith(sig):
            return "image", mime
    try:
        data.decode("utf-8")
        return "text", "text/plain; charset=utf-8"
    except UnicodeDecodeError:
        return "binary", "application/octet-stream"


def _clean_name(raw: str) -> str:
    """
    Keep a *display-only* name. It is never used to build a filesystem path; the
    identity key is always the generated id. We still strip path-ish and control
    characters so the displayed value stays tame and cannot inject a header.
    """
    base = os.path.basename(raw or "")          # drop any directory components
    base = base.replace("\\", "").replace("/", "")
    base = re.sub(r"[\x00-\x1f\x7f]", "", base)  # strip control chars (CR/LF too)
    base = base.strip()
    if len(base) > MAX_NAME_LEN:
        base = base[:MAX_NAME_LEN]
    return base or "upload"


def _disposition_filename(name: str) -> str:
    """
    A header-safe filename for Content-Disposition. WSGI/HTTP header values must
    be latin-1 encodable, so a unicode display name (emoji, CJK, ...) would raise
    while the response is being serialized. We collapse to ASCII and drop quote /
    backslash chars so the header can never error out or be broken out of (P3).
    """
    ascii_name = name.encode("ascii", "replace").decode("ascii")
    ascii_name = ascii_name.replace('"', "").replace("\\", "")
    return ascii_name or "download"


# --------------------------------------------------------------------------- #
# Response hardening (defense in depth for P5 / XSS)
# --------------------------------------------------------------------------- #
@app.after_request
def set_security_headers(resp: Response) -> Response:
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'none'; style-src 'self'; img-src 'self'; "
        "base-uri 'none'; form-action 'self'",
    )
    return resp


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@app.route("/")
def index():
    rows = get_db().execute(
        "SELECT id, name, kind, size, created_at FROM files"
        " WHERE visibility = 'public' ORDER BY created_at DESC, rowid DESC LIMIT 50"
    ).fetchall()
    return render_template(
        "index.html",
        files=rows,
        max_mb=MAX_CONTENT_BYTES // (1024 * 1024),
        csrf_token=_csrf_token(),
    )


@app.route("/upload", methods=["POST"])
def upload():
    _check_csrf()  # reject forged cross-site submissions before doing any work
    uploaded = request.files.get("file")
    visibility = request.form.get("visibility", "public").strip()

    # --- input discipline (P3) -------------------------------------------- #
    if uploaded is None or not uploaded.filename:
        abort(400, "Choose a file to upload.")
    if visibility not in VALID_VISIBILITY:
        abort(400, "Invalid visibility.")

    data = uploaded.read(MAX_CONTENT_BYTES + 1)
    if not data:
        abort(400, "Uploaded file is empty.")
    if len(data) > MAX_CONTENT_BYTES:
        abort(413, "File is too large.")

    # Bound total storage so a flood of uploads cannot exhaust disk (P3).
    count = get_db().execute("SELECT COUNT(*) FROM files").fetchone()[0]
    if count >= MAX_FILES:
        abort(503, "Storage is full; uploads are temporarily disabled.")

    kind, mime = _sniff(data)                  # server-decided, client-ignored
    name = _clean_name(uploaded.filename)       # display only

    file_id = _new_id()
    owner_token = secrets.token_urlsafe(TOKEN_BYTES)
    get_db().execute(
        "INSERT INTO files (id, name, kind, mime, size, content, visibility,"
        " owner_token, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (file_id, name, kind, mime, len(data), data, visibility, owner_token, _now()),
    )
    get_db().commit()

    if visibility == "private":
        return redirect(url_for("view_file", file_id=file_id, token=owner_token))
    return redirect(url_for("view_file", file_id=file_id))


@app.route("/file/<file_id>")
def view_file(file_id: str):
    rec = _load(file_id)
    token = request.args.get("token", "")
    if not _authorized(rec, token):
        # Same response whether the id is wrong or unauthorized -> no oracle.
        abort(404)
    preview_text = None
    if rec["kind"] == "text":
        # Decode for display; Jinja autoescaping renders it inert in the page.
        preview_text = bytes(rec["content"]).decode("utf-8", errors="replace")
    return render_template(
        "file.html", file=rec, token=token, preview_text=preview_text
    )


@app.route("/raw/<file_id>")
def raw_file(file_id: str):
    rec = _load(file_id)
    token = request.args.get("token", "")
    if not _authorized(rec, token):
        abort(404)
    # The displayed name is sanitized into the header and never used as a path.
    disposition = "inline" if rec["kind"] in ("text", "image") else "attachment"
    headers = {
        "Content-Type": rec["mime"],
        "Content-Disposition": '%s; filename="%s"'
        % (disposition, _disposition_filename(rec["name"])),
    }
    return Response(bytes(rec["content"]), status=200, headers=headers)


@app.route("/api/files")
def api_files():
    """JSON list of PUBLIC files only. Never includes content or tokens."""
    rows = get_db().execute(
        "SELECT id, name, kind, size, created_at FROM files"
        " WHERE visibility = 'public' ORDER BY created_at DESC, rowid DESC LIMIT 50"
    ).fetchall()
    return {
        "files": [
            {
                "id": r["id"],
                "name": r["name"],
                "kind": r["kind"],
                "size": r["size"],
                "created_at": r["created_at"],
                "url": url_for("view_file", file_id=r["id"], _external=False),
            }
            for r in rows
        ]
    }


def _load(file_id: str) -> sqlite3.Row:
    # The id is only ever used as a bound parameter -> no injection, and it is
    # never joined onto a filesystem path -> no traversal (P4).
    rec = get_db().execute(
        "SELECT * FROM files WHERE id = ?", (file_id,)
    ).fetchone()
    if rec is None:
        abort(404)
    return rec


# --------------------------------------------------------------------------- #
# Error handlers — clean messages, never leak internals (P1 / P3)
# --------------------------------------------------------------------------- #
def _error_response(code: int, message: str):
    return render_template("error.html", code=code, message=message), code


@app.errorhandler(400)
def _h400(e):
    return _error_response(400, getattr(e, "description", "Bad request."))


@app.errorhandler(404)
def _h404(_e):
    return _error_response(404, "File not found.")


@app.errorhandler(413)
def _h413(_e):
    return _error_response(413, "File is too large.")


@app.errorhandler(503)
def _h503(_e):
    return _error_response(503, "Storage is full; uploads are temporarily disabled.")


@app.errorhandler(405)
def _h405(_e):
    return _error_response(405, "Method not allowed.")


@app.errorhandler(500)
def _h500(_e):
    # Never surface the exception text or a stack trace to the client.
    return _error_response(500, "Something went wrong.")


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
# Initialize at import so both `python app.py` and `flask --app app run` work.
# Idempotent: CREATE TABLE IF NOT EXISTS + a guarded canary seed.
init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    # debug=False so Werkzeug's interactive debugger (which would expose internals
    # and allow code execution) is never enabled (P1 / P3 / P4). threaded=True keeps
    # one slow client from blocking everyone else (mild DoS resilience, P3).
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)
