import os
import json
import sqlite3
import secrets
import hashlib
import datetime
from typing import Optional

import fastapi
from fastapi import Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = fastapi.FastAPI(title="SENU API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DB = "senu.db"
SEED_FILE = os.path.join(os.path.dirname(__file__), "questions_seed.json")

POINTS_PER_CORRECT = 10  # очков за каждый верный ответ


# ─────────────────────────── БАЗА ДАННЫХ ───────────────────────────

def get_conn():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT UNIQUE NOT NULL,
                email         TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                points        INTEGER DEFAULT 0,
                created_at    TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token      TEXT PRIMARY KEY,
                user_id    INTEGER NOT NULL,
                created_at TEXT
            )
        """)
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
            CREATE TABLE IF NOT EXISTS questions (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                section     TEXT,
                topic       TEXT,
                difficulty  INTEGER,
                text        TEXT,
                options     TEXT,
                answer      INTEGER,
                explanation TEXT
            )
        """)

        cols = [r["name"] for r in conn.execute("PRAGMA table_info(results)")]
        if "user_id" not in cols:
            conn.execute("ALTER TABLE results ADD COLUMN user_id INTEGER")

        seed_questions(conn)


def seed_questions(conn):
    """Если таблица вопросов пустая — заливаем её из questions_seed.json."""
    count = conn.execute("SELECT COUNT(*) AS c FROM questions").fetchone()["c"]
    if count > 0:
        return
    if not os.path.exists(SEED_FILE):
        print(f"[seed] {SEED_FILE} not found - questions table left empty")
        return
    with open(SEED_FILE, encoding="utf-8") as f:
        data = json.load(f)
    for q in data:
        conn.execute(
            "INSERT INTO questions (section, topic, difficulty, text, options, answer, explanation) "
            "VALUES (?,?,?,?,?,?,?)",
            (q["section"], q["topic"], q["difficulty"], q["text"],
             json.dumps(q["options"], ensure_ascii=False), q["answer"], q["explanation"]),
        )
    print(f"[seed] loaded {len(data)} questions")


init_db()


# ─────────────────────────── ПАРОЛИ ───────────────────────────

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
    return f"{salt}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, hexhash = stored.split("$", 1)
    except ValueError:
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
    return secrets.compare_digest(dk.hex(), hexhash)


# ─────────────────────────── ТОКЕНЫ ───────────────────────────

def user_from_token(authorization: Optional[str]):
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    token = authorization.split(" ", 1)[1].strip()
    with get_conn() as conn:
        return conn.execute(
            "SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?",
            (token,),
        ).fetchone()


# ─────────────────────────── МОДЕЛИ ───────────────────────────

class RegisterIn(BaseModel):
    username: str
    email: str
    password: str


class LoginIn(BaseModel):
    email: str
    password: str


class Result(BaseModel):
    name: str
    score: int
    total: int
    section: str = "CT"


class AnswerIn(BaseModel):
    question_id: int
    choice: int


# ─────────────────────────── АВТОРИЗАЦИЯ ───────────────────────────

@app.post("/register")
def register(body: RegisterIn):
    username = body.username.strip()
    email = body.email.strip().lower()

    if not username:
        raise HTTPException(400, "Username is required")
    if "@" not in email or "." not in email:
        raise HTTPException(400, "Valid email is required")
    if len(body.password) < 6:
        raise HTTPException(400, "Password must be at least 6 characters")

    with get_conn() as conn:
        exists = conn.execute(
            "SELECT 1 FROM users WHERE email = ? OR username = ?", (email, username)
        ).fetchone()
        if exists:
            raise HTTPException(400, "User with this email or username already exists")
        conn.execute(
            "INSERT INTO users (username, email, password_hash, points, created_at) "
            "VALUES (?,?,?,?,?)",
            (username, email, hash_password(body.password), 0,
             datetime.datetime.utcnow().isoformat()),
        )
    return {"status": "ok"}


@app.post("/login")
def login(body: LoginIn):
    email = body.email.strip().lower()
    with get_conn() as conn:
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if not user or not verify_password(body.password, user["password_hash"]):
            raise HTTPException(401, "Invalid email or password")
        token = secrets.token_urlsafe(32)
        conn.execute(
            "INSERT INTO sessions (token, user_id, created_at) VALUES (?,?,?)",
            (token, user["id"], datetime.datetime.utcnow().isoformat()),
        )
    return {"token": token, "username": user["username"], "points": user["points"]}


@app.post("/logout")
def logout(authorization: Optional[str] = Header(None)):
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        with get_conn() as conn:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
    return {"status": "ok"}


# ─────────────────────── АДАПТИВНЫЕ ВОПРОСЫ ───────────────────────

@app.get("/questions/next")
def next_question(section: str, ability: float = 2.0, exclude: str = ""):
    """Следующий вопрос, ближайший по сложности к уровню ученика.
    Правильный ответ и объяснение клиенту НЕ отправляются."""
    excluded = [int(x) for x in exclude.split(",") if x.strip().isdigit()]

    sql = "SELECT * FROM questions WHERE section = ?"
    params = [section]
    if excluded:
        placeholders = ",".join("?" for _ in excluded)
        sql += f" AND id NOT IN ({placeholders})"
        params += excluded
    sql += " ORDER BY ABS(difficulty - ?) ASC, RANDOM() LIMIT 1"
    params.append(ability)

    with get_conn() as conn:
        row = conn.execute(sql, params).fetchone()

    if not row:
        return {"done": True}

    return {
        "id": row["id"],
        "section": row["section"],
        "topic": row["topic"],
        "difficulty": row["difficulty"],
        "text": row["text"],
        "options": json.loads(row["options"]),
    }


@app.post("/questions/answer")
def answer_question(body: AnswerIn):
    """Проверить ответ на сервере и вернуть результат + объяснение."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT answer, explanation FROM questions WHERE id = ?", (body.question_id,)
        ).fetchone()
    if not row:
        raise HTTPException(404, "Question not found")
    return {
        "correct": body.choice == row["answer"],
        "correct_index": row["answer"],
        "explanation": row["explanation"],
    }


# ─────────────────────────── РЕЗУЛЬТАТЫ ───────────────────────────

@app.post("/submit")
def submit(result: Result, authorization: Optional[str] = Header(None)):
    pct = round(result.score / result.total * 100, 1) if result.total else 0.0
    ts = datetime.datetime.utcnow().isoformat()

    user = user_from_token(authorization)
    user_id = user["id"] if user else None

    points_earned = 0
    total_points = None

    with get_conn() as conn:
        conn.execute(
            "INSERT INTO results (user_id, name, score, total, section, pct, ts) "
            "VALUES (?,?,?,?,?,?,?)",
            (user_id, result.name, result.score, result.total, result.section, pct, ts),
        )
        if user:
            points_earned = result.score * POINTS_PER_CORRECT
            conn.execute(
                "UPDATE users SET points = points + ? WHERE id = ?",
                (points_earned, user["id"]),
            )
            total_points = conn.execute(
                "SELECT points FROM users WHERE id = ?", (user["id"],)
            ).fetchone()["points"]

    return {
        "status": "ok",
        "pct": pct,
        "points_earned": points_earned,
        "total_points": total_points,
    }


@app.get("/results")
def get_results():
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, name, score, total, section, pct, ts "
            "FROM results ORDER BY id DESC LIMIT 100"
        ).fetchall()
    return [dict(r) for r in rows]


@app.get("/stats")
def get_stats():
    with get_conn() as conn:
        total = conn.execute("SELECT COUNT(*) AS c FROM results").fetchone()["c"]
        avg = conn.execute("SELECT AVG(pct) AS a FROM results").fetchone()["a"]
        best = conn.execute("SELECT MAX(pct) AS b FROM results").fetchone()["b"]
        users = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
        qs = conn.execute("SELECT COUNT(*) AS c FROM questions").fetchone()["c"]
    return {
        "total_attempts": total,
        "avg_score_pct": round(avg or 0, 1),
        "best_score_pct": round(best or 0, 1),
        "registered_users": users,
        "questions_in_bank": qs,
    }


@app.get("/")
def root():
    return {"service": "SENU API", "status": "running"}
