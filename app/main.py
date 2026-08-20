import hashlib
import hmac
import os
import secrets
from datetime import datetime, timezone
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import BigInteger, DateTime, JSON, String, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./eblannft-sync.db")
ADMIN_SECRET = os.getenv("ADMIN_SECRET", "")
TOKEN_PEPPER = os.getenv("TOKEN_PEPPER", "")

# Railway exposes PostgreSQL URLs as postgresql://... (and some providers still
# use postgres://...). SQLAlchemy interprets plain postgresql:// as psycopg2,
# while this project intentionally uses psycopg 3. Normalize the scheme so the
# correct driver is selected without requiring users to edit Railway variables.
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = "postgresql+psycopg://" + DATABASE_URL[len("postgresql://"):]
elif DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = "postgresql+psycopg://" + DATABASE_URL[len("postgres://"):]

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, pool_pre_ping=True, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class Profile(Base):
    __tablename__ = "profiles"
    telegram_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    state: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


Base.metadata.create_all(engine)

app = FastAPI(title="eblannft-sync", version="1.0.1")


class IssueTokenRequest(BaseModel):
    telegram_id: int = Field(gt=0)
    rotate: bool = False


class IssueTokenResponse(BaseModel):
    telegram_id: int
    token: str


class ProfileState(BaseModel):
    verification: dict[str, Any] | None = None
    wearing: dict[str, Any] | None = None
    gifts: list[dict[str, Any]] = Field(default_factory=list)
    nft_usernames: list[str] = Field(default_factory=list)
    nft_numbers: list[str] = Field(default_factory=list)
    rating: dict[str, Any] | None = None
    hide_official_gifts: bool = False


def now() -> datetime:
    return datetime.now(timezone.utc)


def hash_token(token: str) -> str:
    payload = (TOKEN_PEPPER + token).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def require_admin(x_admin_key: str | None = Header(default=None)):
    if not ADMIN_SECRET:
        raise HTTPException(503, "ADMIN_SECRET is not configured")
    if not x_admin_key or not hmac.compare_digest(x_admin_key, ADMIN_SECRET):
        raise HTTPException(401, "bad admin key")


def bearer_token(authorization: str | None = Header(default=None)) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing bearer token")
    token = authorization[7:].strip()
    if len(token) < 24:
        raise HTTPException(401, "invalid bearer token")
    return token


@app.get("/health")
def health(db: Session = Depends(get_db)):
    count = len(db.scalars(select(Profile.telegram_id)).all())
    return {"ok": True, "version": app.version, "users": count}


@app.post("/v1/admin/issue-token", response_model=IssueTokenResponse, dependencies=[Depends(require_admin)])
def issue_token(req: IssueTokenRequest, db: Session = Depends(get_db)):
    row = db.get(Profile, req.telegram_id)
    if row is not None and not req.rotate:
        raise HTTPException(409, "profile already claimed; set rotate=true to replace token")

    token = "ebl_" + secrets.token_urlsafe(32)
    token_hash = hash_token(token)
    if row is None:
        row = Profile(telegram_id=req.telegram_id, token_hash=token_hash, state={}, updated_at=now())
        db.add(row)
    else:
        row.token_hash = token_hash
        row.updated_at = now()
    db.commit()
    return IssueTokenResponse(telegram_id=req.telegram_id, token=token)


@app.get("/v1/profile/{telegram_id}")
def get_profile(telegram_id: int, db: Session = Depends(get_db)):
    row = db.get(Profile, telegram_id)
    if row is None:
        raise HTTPException(404, "profile not found")
    return {
        "ok": True,
        "telegram_id": row.telegram_id,
        "state": row.state or {},
        "updated_at": row.updated_at.isoformat(),
    }


@app.put("/v1/profile/me")
def put_my_profile(state: ProfileState, token: str = Depends(bearer_token), db: Session = Depends(get_db)):
    token_hash = hash_token(token)
    row = db.scalar(select(Profile).where(Profile.token_hash == token_hash))
    if row is None:
        raise HTTPException(401, "unknown token")
    payload = state.model_dump(mode="json")
    if len(str(payload)) > 2_000_000:
        raise HTTPException(413, "state too large")
    row.state = payload
    row.updated_at = now()
    db.commit()
    return {"ok": True, "telegram_id": row.telegram_id, "updated_at": row.updated_at.isoformat()}
