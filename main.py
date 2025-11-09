import os
import hashlib
import logging
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from database import db, create_document, get_documents
from schemas import UserProfile, Challenge, Submission

logger = logging.getLogger("ctffolio")

app = FastAPI(title="CTFfolio API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------- Utility ----------

def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def get_collection(name: str):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    return db[name]


# ---------- Models for requests ----------

class ValidateFlagRequest(BaseModel):
    username: str
    flag: str

class AdminChallengeCreate(BaseModel):
    slug: str
    title: str
    concept: str
    section: str
    difficulty: Optional[str] = "easy"
    flag: str


# ---------- Startup seed (safe) ----------

@app.on_event("startup")
def seed_challenges():
    if db is None:
        logger.warning("Database not configured; skipping challenge seed.")
        return
    try:
        col = db["challenge"]
        existing = {c.get("slug"): c for c in col.find({}, {"slug": 1})}
        samples = [
            {"slug": "enum-01", "title": "Enumeration 101", "concept": "Enumeration", "section": "skills", "difficulty": "easy", "flag": "ctf{robots_rule}"},
            {"slug": "osint-01", "title": "OSINT: Shadow Profile", "concept": "OSINT", "section": "about", "difficulty": "easy", "flag": "ctf{trace_the_trail}"},
            {"slug": "sql-01", "title": "SQL Injection – Baby", "concept": "SQLi", "section": "projects", "difficulty": "easy", "flag": "ctf{1_or_1_equals_1}"},
        ]
        to_insert = []
        for s in samples:
            if s["slug"] not in existing:
                ch = Challenge(
                    slug=s["slug"],
                    title=s["title"],
                    concept=s["concept"],
                    section=s["section"],
                    difficulty=s["difficulty"],
                    flag_hash=sha256_hex(s["flag"]),
                    is_active=True,
                )
                to_insert.append(ch.model_dump())
        if to_insert:
            col.insert_many(to_insert)
            logger.info("Seeded %d challenges", len(to_insert))
        else:
            logger.info("Challenges already seeded; nothing to do.")
    except Exception as e:
        # Do not crash startup if the environment denies writes (e.g., quota)
        logger.error("Seeding challenges failed: %s", str(e))
        return


# ---------- Basic health/test ----------

@app.get("/")
def root():
    return {"message": "CTFfolio API running"}

@app.get("/test")
def test_database():
    resp = {
        "backend": "running",
        "database": "connected" if db is not None else "not_configured",
        "collections": [],
    }
    try:
        if db is not None:
            resp["collections"] = db.list_collection_names()
    except Exception as e:
        resp["database"] = f"error: {str(e)[:120]}"
    return resp


# ---------- Public endpoints ----------

@app.get("/api/challenges")
def list_challenges():
    col = get_collection("challenge")
    items = list(col.find({"is_active": True}, {"_id": 0, "flag_hash": 0}))
    return {"items": items}

@app.post("/api/auth/demo-login")
def demo_login(username: str = "demo"):
    users = get_collection("userprofile")
    doc = users.find_one({"username": username})
    if not doc:
        profile = UserProfile(username=username)
        create_document("userprofile", profile)
        doc = users.find_one({"username": username}, {"_id": 0})
    else:
        doc.pop("_id", None)
    return {"user": doc}

@app.get("/api/leaderboard")
def leaderboard(limit: int = 10):
    users = get_collection("userprofile")
    cur = users.aggregate([
        {"$addFields": {"flags": {"$size": {"$ifNull": ["$solved", []]}}}},
        {"$sort": {"flags": -1, "username": 1}},
        {"$limit": limit},
        {"$project": {"_id": 0, "username": 1, "flags": 1}},
    ])
    return {"leaders": list(cur)}


@app.post("/api/validate-flag")
def validate_flag(payload: ValidateFlagRequest):
    if not payload.flag or not payload.username:
        raise HTTPException(status_code=400, detail="Missing username or flag")

    ch_col = get_collection("challenge")
    sub_col = get_collection("submission")
    user_col = get_collection("userprofile")

    flag_h = sha256_hex(payload.flag.strip())
    challenge = ch_col.find_one({"flag_hash": flag_h, "is_active": True})

    if not challenge:
        # record incorrect submission (best-effort)
        try:
            sub = Submission(username=payload.username, challenge_slug="unknown", correct=False, provided_hash=flag_h)
            create_document("submission", sub)
        except Exception:
            pass
        return {"success": False, "message": "Invalid flag"}

    slug = challenge["slug"]
    section = challenge["section"]

    # Record correct submission (best-effort)
    try:
        sub = Submission(username=payload.username, challenge_slug=slug, correct=True, provided_hash=flag_h)
        create_document("submission", sub)
    except Exception:
        pass

    # Update user profile progress (best-effort)
    try:
        user = user_col.find_one({"username": payload.username})
        if not user:
            profile = UserProfile(username=payload.username, solved=[slug], unlocked_sections=[section])
            create_document("userprofile", profile)
        else:
            user_col.update_one(
                {"username": payload.username},
                {
                    "$addToSet": {
                        "solved": slug,
                        "unlocked_sections": section,
                    },
                },
            )
    except Exception:
        pass

    return {"success": True, "message": "Flag correct", "unlockedSection": section, "solvedSlug": slug}


# ---------- Admin endpoints ----------

def require_admin(x_admin_token: Optional[str] = Header(default=None)):
    admin_token = os.getenv("ADMIN_TOKEN")
    if not admin_token:
        raise HTTPException(status_code=403, detail="Admin not configured")
    if x_admin_token != admin_token:
        raise HTTPException(status_code=401, detail="Unauthorized")


@app.post("/api/admin/challenges")
def admin_create_challenge(body: AdminChallengeCreate, _: None = Depends(require_admin)):
    col = get_collection("challenge")
    if col.find_one({"slug": body.slug}):
        raise HTTPException(status_code=409, detail="Slug already exists")
    doc = Challenge(
        slug=body.slug,
        title=body.title,
        concept=body.concept,
        section=body.section,
        difficulty=body.difficulty or "easy",
        flag_hash=sha256_hex(body.flag),
        is_active=True,
    ).model_dump()
    create_document("challenge", doc)
    return {"created": True, "slug": body.slug}

@app.get("/api/admin/challenges")
def admin_list_challenges(_: None = Depends(require_admin)):
    col = get_collection("challenge")
    items = list(col.find({}, {"_id": 0}))
    return {"items": items}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
