import fastapi, hashlib, secrets
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sqlite3, datetime
from datetime import timezone

def _now() -> str:
    return datetime.datetime.now(timezone.utc).isoformat()

app = fastapi.FastAPI(title="SENU API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DB = "senu.db"


def init_db():
    with sqlite3.connect(DB) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS results (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                name    TEXT,
                score   INTEGER,
                total   INTEGER,
                section TEXT,
                pct     REAL,
                ts      TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                username   TEXT UNIQUE NOT NULL,
                email      TEXT UNIQUE NOT NULL,
                pass_hash  TEXT NOT NULL,
                salt       TEXT NOT NULL,
                points     INTEGER DEFAULT 0,
                created_at TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token      TEXT PRIMARY KEY,
                user_id    INTEGER NOT NULL,
                created_at TEXT,
                expires_at TEXT
            )
        """)

init_db()


def hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()


def get_user_from_token(token: str | None):
    if not token:
        return None
    with sqlite3.connect(DB) as conn:
        row = conn.execute(
            """SELECT u.id, u.username, u.email, u.points
               FROM sessions s JOIN users u ON u.id = s.user_id
               WHERE s.token = ? AND s.expires_at > ?""",
            (token, _now())
        ).fetchone()
    if row:
        return {"id": row[0], "username": row[1], "email": row[2], "points": row[3]}
    return None


# ─── Auth models ─────────────────────────────────────────────────
class RegisterBody(BaseModel):
    username: str
    email: str
    password: str

class LoginBody(BaseModel):
    email: str
    password: str


# ─── Auth endpoints ───────────────────────────────────────────────
@app.post("/register")
def register(body: RegisterBody):
    if len(body.password) < 6:
        raise fastapi.HTTPException(400, "Password must be at least 6 characters")
    if not body.username.strip():
        raise fastapi.HTTPException(400, "Username is required")
    salt = secrets.token_hex(16)
    pass_hash = hash_password(body.password, salt)
    ts = _now()
    try:
        with sqlite3.connect(DB) as conn:
            conn.execute(
                "INSERT INTO users (username, email, pass_hash, salt, points, created_at) VALUES (?,?,?,?,0,?)",
                (body.username.strip(), body.email.strip().lower(), pass_hash, salt, ts)
            )
    except sqlite3.IntegrityError:
        raise fastapi.HTTPException(400, "Username or email already exists")
    return {"status": "ok"}


@app.post("/login")
def login(body: LoginBody):
    with sqlite3.connect(DB) as conn:
        row = conn.execute(
            "SELECT id, username, pass_hash, salt, points FROM users WHERE email = ?",
            (body.email.strip().lower(),)
        ).fetchone()
    if not row:
        raise fastapi.HTTPException(401, "Invalid email or password")
    user_id, username, pass_hash, salt, points = row
    if hash_password(body.password, salt) != pass_hash:
        raise fastapi.HTTPException(401, "Invalid email or password")

    token = secrets.token_hex(32)
    ts = _now()
    expires = (datetime.datetime.now(timezone.utc) + datetime.timedelta(days=30)).isoformat()
    with sqlite3.connect(DB) as conn:
        conn.execute(
            "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?,?,?,?)",
            (token, user_id, ts, expires)
        )
    return {"status": "ok", "token": token, "username": username, "points": points}


@app.post("/logout")
def logout(authorization: str = fastapi.Header(None)):
    token = authorization.replace("Bearer ", "") if authorization else None
    if token:
        with sqlite3.connect(DB) as conn:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
    return {"status": "ok"}


@app.get("/me")
def get_me(authorization: str = fastapi.Header(None)):
    token = authorization.replace("Bearer ", "") if authorization else None
    user = get_user_from_token(token)
    if not user:
        raise fastapi.HTTPException(401, "Not authenticated")
    return user


# ─── History ──────────────────────────────────────────────────────
@app.get("/history")
def get_history(authorization: str = fastapi.Header(None)):
    token = authorization.replace("Bearer ", "") if authorization else None
    user = get_user_from_token(token)
    if not user:
        raise fastapi.HTTPException(401, "Not authenticated")
    with sqlite3.connect(DB) as conn:
        rows = conn.execute(
            "SELECT id, score, total, section, pct, ts FROM results WHERE user_id = ? ORDER BY id DESC LIMIT 50",
            (user["id"],)
        ).fetchall()
    return [
        {"id": r[0], "score": r[1], "total": r[2], "section": r[3], "pct": r[4], "ts": r[5]}
        for r in rows
    ]


# ─── Submit result ────────────────────────────────────────────────
class Result(BaseModel):
    name: str
    score: int
    total: int
    section: str = "CT"


@app.post("/submit")
def submit(result: Result, authorization: str = fastapi.Header(None)):
    pct = round(result.score / result.total * 100, 1)
    ts = _now()

    token = authorization.replace("Bearer ", "") if authorization else None
    user = get_user_from_token(token)
    user_id = user["id"] if user else None

    # 10 pts per correct answer, +50 bonus for perfect score
    points_earned = result.score * 10
    if result.score == result.total:
        points_earned += 50

    with sqlite3.connect(DB) as conn:
        conn.execute(
            "INSERT INTO results (user_id, name, score, total, section, pct, ts) VALUES (?,?,?,?,?,?,?)",
            (user_id, result.name, result.score, result.total, result.section, pct, ts)
        )
        if user_id and points_earned > 0:
            conn.execute(
                "UPDATE users SET points = points + ? WHERE id = ?",
                (points_earned, user_id)
            )

    new_points = None
    if user_id:
        with sqlite3.connect(DB) as conn:
            row = conn.execute("SELECT points FROM users WHERE id = ?", (user_id,)).fetchone()
            new_points = row[0] if row else None

    return {"status": "ok", "pct": pct, "points_earned": points_earned, "total_points": new_points}


# ─── Public stats ─────────────────────────────────────────────────
@app.get("/results")
def get_results():
    with sqlite3.connect(DB) as conn:
        rows = conn.execute(
            "SELECT id, name, score, total, section, pct, ts FROM results ORDER BY id DESC LIMIT 100"
        ).fetchall()
    return [
        {"id": r[0], "name": r[1], "score": r[2], "total": r[3],
         "section": r[4], "pct": r[5], "ts": r[6]}
        for r in rows
    ]


@app.get("/stats")
def get_stats():
    with sqlite3.connect(DB) as conn:
        total = conn.execute("SELECT COUNT(*) FROM results").fetchone()[0]
        avg   = conn.execute("SELECT AVG(pct) FROM results").fetchone()[0]
        best  = conn.execute("SELECT MAX(pct) FROM results").fetchone()[0]
    return {
        "total_attempts": total,
        "avg_score_pct": round(avg or 0, 1),
        "best_score_pct": round(best or 0, 1),
    }


@app.get("/")
def root():
    return {"service": "SENU API", "status": "running"}
