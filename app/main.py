import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timezone
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import BigInteger, DateTime, JSON, String, create_engine, delete, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./eblannft-sync.db")
ADMIN_SECRET = os.getenv("ADMIN_SECRET", "")
TOKEN_PEPPER = os.getenv("TOKEN_PEPPER", "")

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


class TransferEvent(Base):
    __tablename__ = "transfer_events"
    event_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    sender_id: Mapped[int] = mapped_column(BigInteger, nullable=False, index=True)
    receiver_id: Mapped[int] = mapped_column(BigInteger, nullable=False, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)


Base.metadata.create_all(engine)

app = FastAPI(title="eblannft-sync", version="1.2.0")


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


def parse_user_key(user_key: str) -> int:
    value = str(user_key or "").strip()
    for prefix in ("tg-main:", "tg:"):
        if value.startswith(prefix):
            value = value[len(prefix):]
            break
    try:
        uid = int(value)
    except Exception:
        raise HTTPException(400, "invalid user key")
    if uid <= 0:
        raise HTTPException(400, "invalid user key")
    return uid


def profile_for_plugin_key(plugin_key: str | None, db: Session) -> Profile:
    token = str(plugin_key or "").strip()
    if len(token) < 24:
        raise HTTPException(401, "missing or invalid X-Plugin-Key")
    row = db.scalar(select(Profile).where(Profile.token_hash == hash_token(token)))
    if row is None:
        raise HTTPException(401, "unknown plugin token")
    return row


def bounded_state(payload: dict[str, Any]) -> dict[str, Any]:
    if len(json.dumps(payload, ensure_ascii=False, separators=(",", ":"))) > 2_000_000:
        raise HTTPException(413, "state too large")
    return payload


def require_receiver_owner(receiver_id: int, plugin_key: str | None, db: Session) -> Profile:
    row = profile_for_plugin_key(plugin_key, db)
    if int(row.telegram_id) != int(receiver_id):
        raise HTTPException(403, "token does not own this receiver")
    return row


@app.get("/health")
def health(db: Session = Depends(get_db)):
    count = len(db.scalars(select(Profile.telegram_id)).all())
    queued = len(db.scalars(select(TransferEvent.event_id)).all())
    return {"ok": True, "version": app.version, "users": count, "queued_transfers": queued}


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
    row.state = bounded_state(state.model_dump(mode="json"))
    row.updated_at = now()
    db.commit()
    return {"ok": True, "telegram_id": row.telegram_id, "updated_at": row.updated_at.isoformat()}


# Compatibility API for the original eblanNFT Java/DEX SyncClient.
@app.get("/api/v1/users/{user_key}/state")
def legacy_get_state(user_key: str, db: Session = Depends(get_db)):
    uid = parse_user_key(user_key)
    row = db.get(Profile, uid)
    if row is None:
        raise HTTPException(404, "profile not found")
    payload = dict(row.state or {})
    payload.setdefault("updated_at", int(row.updated_at.timestamp()))
    return payload


@app.put("/api/v1/users/{user_key}/state")
def legacy_put_state(
    user_key: str,
    state: dict[str, Any],
    x_plugin_key: str | None = Header(default=None, alias="X-Plugin-Key"),
    db: Session = Depends(get_db),
):
    uid = parse_user_key(user_key)
    row = profile_for_plugin_key(x_plugin_key, db)
    if int(row.telegram_id) != uid:
        raise HTTPException(403, "token does not own this Telegram id")
    row.state = bounded_state(dict(state or {}))
    row.updated_at = now()
    db.commit()
    return {"ok": True, "telegram_id": uid, "updated_at": int(row.updated_at.timestamp())}


@app.get("/api/v1/badges")
def legacy_badges():
    return {"badges": []}


# Native gift-transfer inbox expected by the embedded eblanNFT DEX.
# DEX flow:
#   sender:   PUT  /api/v1/transfers/{receiver_id}  with an opaque gift event JSON
#   receiver: GET  /api/v1/transfers/{receiver_id}
#   receiver: POST /api/v1/transfers/{receiver_id}/ack {"event_ids":[...]}
# The client itself converts these events into Telegram TL_messageService with
# TL_messageActionStarGift / TL_messageActionStarGiftUnique and inserts them in ChatActivity.
@app.put("/api/v1/transfers/{receiver_id}")
def push_transfer(
    receiver_id: int,
    event: dict[str, Any],
    x_plugin_key: str | None = Header(default=None, alias="X-Plugin-Key"),
    db: Session = Depends(get_db),
):
    sender = profile_for_plugin_key(x_plugin_key, db)
    payload = bounded_state(dict(event or {}))

    try:
        body_receiver = int(payload.get("receiver_id", receiver_id))
    except Exception:
        raise HTTPException(400, "bad receiver_id")
    if body_receiver != int(receiver_id):
        raise HTTPException(400, "receiver_id mismatch")

    try:
        body_sender = int(payload.get("sender_id", sender.telegram_id))
    except Exception:
        raise HTTPException(400, "bad sender_id")
    if body_sender != int(sender.telegram_id):
        raise HTTPException(403, "sender_id does not match token owner")

    event_id = str(payload.get("event_id") or "").strip()
    if not event_id:
        canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        event_id = hashlib.sha256(
            (f"{body_sender}:{receiver_id}:" + canonical).encode("utf-8")
        ).hexdigest()[:48]
        payload["event_id"] = event_id

    if len(event_id) > 160:
        raise HTTPException(400, "event_id too long")

    existing = db.get(TransferEvent, event_id)
    if existing is None:
        event_time = now()
        raw_ts = payload.get("date") or payload.get("created_at")
        try:
            ts = int(raw_ts or 0)
            if ts > 10_000_000_000:
                ts //= 1000
            if ts > 0:
                event_time = datetime.fromtimestamp(ts, tz=timezone.utc)
        except Exception:
            pass
        db.add(
            TransferEvent(
                event_id=event_id,
                sender_id=body_sender,
                receiver_id=int(receiver_id),
                payload=payload,
                created_at=event_time,
            )
        )
        db.commit()

    return {"ok": True, "event_id": event_id}


@app.get("/api/v1/transfers/{receiver_id}")
def fetch_transfers(
    receiver_id: int,
    x_plugin_key: str | None = Header(default=None, alias="X-Plugin-Key"),
    db: Session = Depends(get_db),
):
    require_receiver_owner(receiver_id, x_plugin_key, db)
    rows = db.scalars(
        select(TransferEvent)
        .where(TransferEvent.receiver_id == int(receiver_id))
        .order_by(TransferEvent.created_at.asc())
        .limit(200)
    ).all()
    return {"transfers": [dict(row.payload or {}) for row in rows]}


@app.post("/api/v1/transfers/{receiver_id}/ack")
def ack_transfers(
    receiver_id: int,
    body: dict[str, Any],
    x_plugin_key: str | None = Header(default=None, alias="X-Plugin-Key"),
    db: Session = Depends(get_db),
):
    require_receiver_owner(receiver_id, x_plugin_key, db)
    raw_ids = body.get("event_ids") if isinstance(body, dict) else None
    ids = [str(x).strip() for x in (raw_ids or []) if str(x).strip()]
    if not ids:
        return {"ok": True, "acked": 0}

    result = db.execute(
        delete(TransferEvent).where(
            TransferEvent.receiver_id == int(receiver_id),
            TransferEvent.event_id.in_(ids),
        )
    )
    db.commit()
    return {"ok": True, "acked": int(result.rowcount or 0)}
