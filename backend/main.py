import os
import json
import secrets
import hashlib
import datetime
from typing import Optional

import fastapi
from fastapi import Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from sqlalchemy import (
    create_engine, Column, Integer, String, Float, Text, func, text, inspect
)
from sqlalchemy.orm import declarative_base, sessionmaker

# ─────────────────────── ВЫБОР БАЗЫ ───────────────────────
DB_URL = os.environ.get("DATABASE_URL", "sqlite:///senu.db")
if DB_URL.startswith("postgres://"):
    DB_URL = DB_URL.replace("postgres://", "postgresql://", 1)

connect_args = {"check_same_thread": False} if DB_URL.startswith("sqlite") else {}
engine = create_engine(DB_URL, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

SEED_FILE = os.path.join(os.path.dirname(__file__), "questions_seed.json")
POINTS_PER_CORRECT = 10

# ─────────────────────── НАСТРОЙКИ ПОЧТЫ ───────────────────────
# Если RESEND_API_KEY не задан — почта выключена: регистрация подтверждает
# аккаунт автоматически (как раньше), письма не шлются. Это позволяет
# работать локально и до настройки Resend без поломок.
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
EMAIL_FROM = os.environ.get("EMAIL_FROM", "SENU <onboarding@resend.dev>")
FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:5500").rstrip("/")
EMAIL_ENABLED = bool(RESEND_API_KEY)


# ─────────────────────── МОДЕЛИ ТАБЛИЦ ───────────────────────

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    points = Column(Integer, default=0)
    verified = Column(Integer, default=0)
    created_at = Column(String(40))


class AuthSession(Base):
    __tablename__ = "sessions"
    token = Column(String(80), primary_key=True)
    user_id = Column(Integer, nullable=False)
    created_at = Column(String(40))


class Token(Base):
    __tablename__ = "tokens"
    token = Column(String(80), primary_key=True)
    user_id = Column(Integer, nullable=False)
    purpose = Column(String(20))      # 'verify' или 'reset'
    expires_at = Column(String(40))


class Result(Base):
    __tablename__ = "results"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer)
    name = Column(String(120))
    score = Column(Integer)
    total = Column(Integer)
    section = Column(String(10))
    pct = Column(Float)
    ts = Column(String(40))


class Question(Base):
    __tablename__ = "questions"
    id = Column(Integer, primary_key=True)
    section = Column(String(10))
    topic = Column(String(120))
    difficulty = Column(Integer)
    text = Column(Text)
    options = Column(Text)
    answer = Column(Integer)
    explanation = Column(Text)


Base.metadata.create_all(engine)


# ─────────────────────── МИГРАЦИЯ ───────────────────────

def migrate():
    """Добавить колонку verified в существующую таблицу users, если её нет.
    Существующих пользователей считаем подтверждёнными (чтобы не залочить)."""
    cols = [c["name"] for c in inspect(engine).get_columns("users")]
    if "verified" not in cols:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE users ADD COLUMN verified INTEGER DEFAULT 0"))
            conn.execute(text("UPDATE users SET verified = 1"))
        print("[migrate] added users.verified (existing users grandfathered)")


migrate()


# ─────────────────────── ЗАСЕВ ВОПРОСОВ ───────────────────────

def seed_questions():
    db = SessionLocal()
    try:
        if db.query(Question).count() > 0:
            return
        if not os.path.exists(SEED_FILE):
            print(f"[seed] {SEED_FILE} not found - questions table left empty")
            return
        with open(SEED_FILE, encoding="utf-8") as f:
            data = json.load(f)
        for q in data:
            db.add(Question(
                section=q["section"], topic=q["topic"], difficulty=q["difficulty"],
                text=q["text"], options=json.dumps(q["options"], ensure_ascii=False),
                answer=q["answer"], explanation=q["explanation"],
            ))
        db.commit()
        print(f"[seed] loaded {len(data)} questions")
    finally:
        db.close()


seed_questions()


# ─────────────────────── ПРИЛОЖЕНИЕ ───────────────────────

app = fastapi.FastAPI(title="SENU API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────── ОТПРАВКА ПОЧТЫ (Resend) ───────────────────────

def send_email(to: str, subject: str, html: str) -> bool:
    if not EMAIL_ENABLED:
        print(f"[email] disabled (no RESEND_API_KEY) — skipped '{subject}' -> {to}")
        return False
    try:
        import requests
        r = requests.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}",
                     "Content-Type": "application/json"},
            json={"from": EMAIL_FROM, "to": [to], "subject": subject, "html": html},
            timeout=15,
        )
        if r.status_code >= 400:
            print(f"[email] Resend error {r.status_code}: {r.text}")
            return False
        return True
    except Exception as e:
        print(f"[email] exception: {e}")
        return False


def _button(link: str, label: str) -> str:
    return (f'<a href="{link}" style="display:inline-block;background:#fdc35f;color:#161310;'
            f'padding:12px 24px;border-radius:999px;text-decoration:none;font-weight:600">{label}</a>')


def send_verify_email(to: str, token: str) -> bool:
    link = f"{FRONTEND_URL}/verify.html?token={token}"
    html = (
        '<div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;color:#1c1a15">'
        '<h2 style="font-weight:700">Verify your SENU account</h2>'
        '<p>Welcome to SENU. Confirm your email to activate your account:</p>'
        f'<p style="margin:22px 0">{_button(link, "Verify email →")}</p>'
        f'<p style="color:#888;font-size:13px">Or open this link:<br>{link}</p>'
        '<p style="color:#888;font-size:13px">This link expires in 24 hours.</p>'
        '</div>'
    )
    return send_email(to, "Verify your SENU account", html)


def send_reset_email(to: str, token: str) -> bool:
    link = f"{FRONTEND_URL}/reset.html?token={token}"
    html = (
        '<div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;color:#1c1a15">'
        '<h2 style="font-weight:700">Reset your SENU password</h2>'
        '<p>We received a request to reset your password. Click below to choose a new one:</p>'
        f'<p style="margin:22px 0">{_button(link, "Reset password →")}</p>'
        f'<p style="color:#888;font-size:13px">Or open this link:<br>{link}</p>'
        '<p style="color:#888;font-size:13px">This link expires in 1 hour. '
        'If you didn\'t request this, you can ignore this email.</p>'
        '</div>'
    )
    return send_email(to, "Reset your SENU password", html)


# ─────────────────────── ПАРОЛИ И ТОКЕНЫ ───────────────────────

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


def user_from_token(db, authorization: Optional[str]):
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    token = authorization.split(" ", 1)[1].strip()
    sess = db.query(AuthSession).filter(AuthSession.token == token).first()
    if not sess:
        return None
    return db.query(User).filter(User.id == sess.user_id).first()


def make_token(db, user_id: int, purpose: str, hours: int) -> str:
    tok = secrets.token_urlsafe(32)
    exp = (datetime.datetime.utcnow() + datetime.timedelta(hours=hours)).isoformat()
    db.add(Token(token=tok, user_id=user_id, purpose=purpose, expires_at=exp))
    return tok


def consume_token(db, token: str, purpose: str):
    """Найти токен нужного назначения, удалить его (одноразовый) и вернуть
    пользователя, либо None если токен не найден/просрочен."""
    t = db.query(Token).filter(Token.token == token, Token.purpose == purpose).first()
    if not t:
        return None
    expired = False
    try:
        expired = datetime.datetime.fromisoformat(t.expires_at) < datetime.datetime.utcnow()
    except Exception:
        expired = False
    user = db.query(User).filter(User.id == t.user_id).first()
    db.delete(t)
    if expired or not user:
        return None
    return user


# ─────────────────────── МОДЕЛИ ЗАПРОСОВ ───────────────────────

class RegisterIn(BaseModel):
    username: str
    email: str
    password: str


class LoginIn(BaseModel):
    email: str
    password: str


class EmailIn(BaseModel):
    email: str


class ResetIn(BaseModel):
    token: str
    password: str


class ResultIn(BaseModel):
    name: str
    score: int
    total: int
    section: str = "CT"


class AnswerIn(BaseModel):
    question_id: int
    choice: int


# ─────────────────────── АВТОРИЗАЦИЯ ───────────────────────

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

    db = SessionLocal()
    try:
        exists = db.query(User).filter(
            (User.email == email) | (User.username == username)
        ).first()
        if exists:
            raise HTTPException(400, "User with this email or username already exists")

        verified = 0 if EMAIL_ENABLED else 1
        user = User(
            username=username, email=email,
            password_hash=hash_password(body.password), points=0,
            verified=verified, created_at=datetime.datetime.utcnow().isoformat(),
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        if EMAIL_ENABLED:
            tok = make_token(db, user.id, "verify", 24)
            db.commit()
            send_verify_email(user.email, tok)

        return {"status": "ok", "verification_required": bool(EMAIL_ENABLED)}
    finally:
        db.close()


@app.post("/login")
def login(body: LoginIn):
    email = body.email.strip().lower()
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user or not verify_password(body.password, user.password_hash):
            raise HTTPException(401, "Invalid email or password")
        if not user.verified:
            raise HTTPException(403, "Please verify your email — check your inbox.")
        token = secrets.token_urlsafe(32)
        db.add(AuthSession(
            token=token, user_id=user.id,
            created_at=datetime.datetime.utcnow().isoformat(),
        ))
        db.commit()
        return {"token": token, "username": user.username, "points": user.points}
    finally:
        db.close()


@app.post("/logout")
def logout(authorization: Optional[str] = Header(None)):
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        db = SessionLocal()
        try:
            db.query(AuthSession).filter(AuthSession.token == token).delete()
            db.commit()
        finally:
            db.close()
    return {"status": "ok"}


@app.get("/verify")
def verify(token: str):
    db = SessionLocal()
    try:
        user = consume_token(db, token, "verify")
        if not user:
            db.commit()
            raise HTTPException(400, "Invalid or expired verification link")
        user.verified = 1
        db.commit()
        return {"status": "ok", "message": "Email verified"}
    finally:
        db.close()


@app.post("/resend")
def resend_verification(body: EmailIn):
    db = SessionLocal()
    try:
        if EMAIL_ENABLED:
            user = db.query(User).filter(User.email == body.email.strip().lower()).first()
            if user and not user.verified:
                tok = make_token(db, user.id, "verify", 24)
                db.commit()
                send_verify_email(user.email, tok)
        return {"status": "ok"}
    finally:
        db.close()


@app.post("/forgot")
def forgot_password(body: EmailIn):
    db = SessionLocal()
    try:
        if EMAIL_ENABLED:
            user = db.query(User).filter(User.email == body.email.strip().lower()).first()
            if user:
                tok = make_token(db, user.id, "reset", 1)
                db.commit()
                send_reset_email(user.email, tok)
        # Всегда отвечаем ok, чтобы не раскрывать, есть ли такой email.
        return {"status": "ok", "email_enabled": bool(EMAIL_ENABLED)}
    finally:
        db.close()


@app.post("/reset")
def reset_password(body: ResetIn):
    if len(body.password) < 6:
        raise HTTPException(400, "Password must be at least 6 characters")
    db = SessionLocal()
    try:
        user = consume_token(db, body.token, "reset")
        if not user:
            db.commit()
            raise HTTPException(400, "Invalid or expired reset link")
        user.password_hash = hash_password(body.password)
        user.verified = 1   # успешный сброс подтверждает владение почтой
        db.commit()
        return {"status": "ok"}
    finally:
        db.close()


# ─────────────────────── АДАПТИВНЫЕ ВОПРОСЫ ───────────────────────

@app.get("/questions/next")
def next_question(section: str, ability: float = 2.0, exclude: str = ""):
    excluded = [int(x) for x in exclude.split(",") if x.strip().isdigit()]
    db = SessionLocal()
    try:
        q = db.query(Question).filter(Question.section == section)
        if excluded:
            q = q.filter(Question.id.notin_(excluded))
        row = q.order_by(func.abs(Question.difficulty - ability), func.random()).first()
        if not row:
            return {"done": True}
        return {
            "id": row.id, "section": row.section, "topic": row.topic,
            "difficulty": row.difficulty, "text": row.text,
            "options": json.loads(row.options),
        }
    finally:
        db.close()


@app.post("/questions/answer")
def answer_question(body: AnswerIn):
    db = SessionLocal()
    try:
        row = db.query(Question).filter(Question.id == body.question_id).first()
        if not row:
            raise HTTPException(404, "Question not found")
        return {
            "correct": body.choice == row.answer,
            "correct_index": row.answer,
            "explanation": row.explanation,
        }
    finally:
        db.close()


# ─────────────────────── РЕЗУЛЬТАТЫ ───────────────────────

@app.post("/submit")
def submit(result: ResultIn, authorization: Optional[str] = Header(None)):
    pct = round(result.score / result.total * 100, 1) if result.total else 0.0
    ts = datetime.datetime.utcnow().isoformat()
    db = SessionLocal()
    try:
        user = user_from_token(db, authorization)
        user_id = user.id if user else None
        db.add(Result(
            user_id=user_id, name=result.name, score=result.score,
            total=result.total, section=result.section, pct=pct, ts=ts,
        ))
        points_earned = 0
        total_points = None
        if user:
            points_earned = result.score * POINTS_PER_CORRECT
            user.points = (user.points or 0) + points_earned
            total_points = user.points
        db.commit()
        return {"status": "ok", "pct": pct,
                "points_earned": points_earned, "total_points": total_points}
    finally:
        db.close()


@app.get("/history")
def history(authorization: Optional[str] = Header(None)):
    db = SessionLocal()
    try:
        user = user_from_token(db, authorization)
        if not user:
            raise HTTPException(401, "Not signed in")
        rows = (db.query(Result).filter(Result.user_id == user.id)
                .order_by(Result.id.desc()).limit(100).all())
        return {
            "username": user.username, "points": user.points,
            "attempts": [
                {"score": r.score, "total": r.total, "section": r.section,
                 "pct": r.pct, "ts": r.ts}
                for r in rows
            ],
        }
    finally:
        db.close()


@app.get("/results")
def get_results():
    db = SessionLocal()
    try:
        rows = db.query(Result).order_by(Result.id.desc()).limit(100).all()
        return [
            {"id": r.id, "name": r.name, "score": r.score, "total": r.total,
             "section": r.section, "pct": r.pct, "ts": r.ts}
            for r in rows
        ]
    finally:
        db.close()


@app.get("/stats")
def get_stats():
    db = SessionLocal()
    try:
        total = db.query(func.count(Result.id)).scalar() or 0
        avg = db.query(func.avg(Result.pct)).scalar()
        best = db.query(func.max(Result.pct)).scalar()
        users = db.query(func.count(User.id)).scalar() or 0
        qs = db.query(func.count(Question.id)).scalar() or 0
        return {
            "total_attempts": total,
            "avg_score_pct": round(avg or 0, 1),
            "best_score_pct": round(best or 0, 1),
            "registered_users": users,
            "questions_in_bank": qs,
        }
    finally:
        db.close()


@app.get("/")
def root():
    return {"service": "SENU API", "status": "running", "email_enabled": EMAIL_ENABLED}
