import fastapi
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sqlite3, datetime

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
                name    TEXT,
                score   INTEGER,
                total   INTEGER,
                section TEXT,
                pct     REAL,
                ts      TEXT
            )
        """)
init_db()


class Result(BaseModel):
    name: str
    score: int
    total: int
    section: str = "CT"


@app.post("/submit")
def submit(result: Result):
    pct = round(result.score / result.total * 100, 1)
    ts = datetime.datetime.utcnow().isoformat()
    with sqlite3.connect(DB) as conn:
        conn.execute(
            "INSERT INTO results (name, score, total, section, pct, ts) VALUES (?,?,?,?,?,?)",
            (result.name, result.score, result.total, result.section, pct, ts)
        )
    return {"status": "ok", "pct": pct}


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
