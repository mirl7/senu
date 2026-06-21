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
    create_engine, Column, Integer, String, Float, Text, func
)
from sqlalchemy.orm import declarative_base, sessionmaker

# ─────────────────────── ВЫБОР БАЗЫ ───────────────────────
# Если задана переменная окружения DATABASE_URL (на Render) — используем Postgres.
# Иначе локально работаем с файлом SQLite, как раньше.
DB_URL = os.environ.get("DATABASE_URL", "sqlite:///senu.db")
if DB_URL.startswith("postgres://"):           # Render даёт схему postgres://,
    DB_URL = DB_URL.replace("postgres://", "postgresql://", 1)  # SQLAlchemy 2.x хочет postgresql://

connect_args = {"check_same_thread": False} if DB_URL.startswith("sqlite") else {}
engine = create_engine(DB_URL, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

SEED_FILE = os.path.join(os.path.dirname(__file__), "questions_seed.json")
POINTS_PER_CORRECT = 10


# ─────────────────────── МОДЕЛИ ТАБЛИЦ ───────────────────────

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    points = Column(Integer, default=0)
    created_at = Column(String(40))


class AuthSession(Base):
    __tablename__ = "sessions"
    token = Column(String(80), primary_key=True)
    user_id = Column(Integer, nullable=False)
    created_at = Column(String(40))


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
    options = Column(Text)        # JSON-массив строкой
    answer = Column(Integer)
    explanation = Column(Text)


Base.metadata.create_all(engine)


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


# ─────────────────────── ПАРОЛИ ───────────────────────

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


# ─────────────────────── МОДЕЛИ ЗАПРОСОВ ───────────────────────

class RegisterIn(BaseModel):
    username: str
    email: str
    password: str


class LoginIn(BaseModel):
    email: str
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
        db.add(User(
            username=username, email=email,
            password_hash=hash_password(body.password), points=0,
            created_at=datetime.datetime.utcnow().isoformat(),
        ))
        db.commit()
    finally:
        db.close()
    return {"status": "ok"}


@app.post("/login")
def login(body: LoginIn):
    email = body.email.strip().lower()
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user or not verify_password(body.password, user.password_hash):
            raise HTTPException(401, "Invalid email or password")
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
            "id": row.id,
            "section": row.section,
            "topic": row.topic,
            "difficulty": row.difficulty,
            "text": row.text,
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
        return {
            "status": "ok",
            "pct": pct,
            "points_earned": points_earned,
            "total_points": total_points,
        }
    finally:
        db.close()


@app.get("/history")
def history(authorization: Optional[str] = Header(None)):
    """История попыток текущего пользователя (нужен токен)."""
    db = SessionLocal()
    try:
        user = user_from_token(db, authorization)
        if not user:
            raise HTTPException(401, "Not signed in")
        rows = (
            db.query(Result)
            .filter(Result.user_id == user.id)
            .order_by(Result.id.desc())
            .limit(100)
            .all()
        )
        return {
            "username": user.username,
            "points": user.points,
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
    return {"service": "SENU API", "status": "running"}
