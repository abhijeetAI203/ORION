from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")
DATABASE_PATH = Path(os.getenv("ORION_DATABASE_PATH", ROOT / "orion.db"))
ADMIN_USERNAME = os.getenv("ORION_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ORION_ADMIN_PASSWORD", "change-this-before-use")
ADMIN_TOKEN = os.getenv("ORION_ADMIN_TOKEN", secrets.token_urlsafe(32))

app = FastAPI(title="ORION License API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in os.getenv("ORION_CORS_ORIGINS", "http://127.0.0.1:8000").split(",")],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def now() -> datetime:
    return datetime.now(timezone.utc)


def db() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db() -> None:
    with db() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS licenses (
                id TEXT PRIMARY KEY,
                key_hash TEXT UNIQUE NOT NULL,
                key_hint TEXT NOT NULL,
                customer TEXT NOT NULL,
                status TEXT NOT NULL,
                expires_at TEXT,
                max_devices INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY,
                license_id TEXT NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
                installation_id TEXT NOT NULL,
                activated_at TEXT NOT NULL,
                UNIQUE(license_id, installation_id)
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                license_id TEXT NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
                installation_id TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );
            """
        )


@app.on_event("startup")
def startup() -> None:
    init_db()


class LoginRequest(BaseModel):
    username: str
    password: str


class LicenseCreateRequest(BaseModel):
    customer: str = Field(min_length=1, max_length=120)
    duration_days: int | None = Field(default=365, ge=1, le=3650)
    max_devices: int = Field(default=1, ge=1, le=20)


class ActivateRequest(BaseModel):
    key: str
    installation_id: str = Field(min_length=8, max_length=200)


class ValidateRequest(BaseModel):
    session_token: str
    installation_id: str


def require_admin(authorization: Annotated[str | None, Header()] = None) -> None:
    if authorization != f"Bearer {ADMIN_TOKEN}":
        raise HTTPException(status_code=401, detail="Admin authentication required")


def key_hash(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def license_payload(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "customer": row["customer"],
        "key_hint": row["key_hint"],
        "status": row["status"],
        "expires_at": row["expires_at"],
        "max_devices": row["max_devices"],
        "created_at": row["created_at"],
    }


def session_payload(row: sqlite3.Row, token: str) -> dict:
    device_count = row["device_count"]
    return {
        "license_id": row["id"],
        "status": row["status"],
        "expires_at": row["expires_at"],
        "device_count": device_count,
        "max_devices": row["max_devices"],
        "server_validated_at": now().isoformat(),
        "session_token": token,
    }


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/auth/login")
def login(payload: LoginRequest) -> dict[str, str]:
    if not hmac.compare_digest(payload.username, ADMIN_USERNAME) or not hmac.compare_digest(payload.password, ADMIN_PASSWORD):
        raise HTTPException(status_code=401, detail="Invalid admin credentials")
    return {"access_token": ADMIN_TOKEN, "token_type": "bearer"}


@app.post("/licenses")
def create_license(payload: LicenseCreateRequest, _: None = Depends(require_admin)) -> dict:
    raw_key = "ORION-" + "-".join(secrets.token_hex(4).upper() for _ in range(3))
    license_id = secrets.token_hex(12)
    created_at = now()
    expires_at = None if payload.duration_days is None else (created_at + timedelta(days=payload.duration_days)).isoformat()
    with db() as connection:
        connection.execute(
            "INSERT INTO licenses VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (license_id, key_hash(raw_key), raw_key[-8:], payload.customer, "ACTIVE", expires_at, payload.max_devices, created_at.isoformat()),
        )
        row = connection.execute("SELECT * FROM licenses WHERE id = ?", (license_id,)).fetchone()
    return {"license": license_payload(row), "license_key": raw_key}


@app.get("/licenses")
def list_licenses(_: None = Depends(require_admin)) -> list[dict]:
    with db() as connection:
        rows = connection.execute("SELECT * FROM licenses ORDER BY created_at DESC").fetchall()
    return [license_payload(row) for row in rows]


@app.post("/license/activate")
def activate(payload: ActivateRequest) -> dict:
    with db() as connection:
        row = connection.execute(
            "SELECT l.*, COUNT(d.id) AS device_count FROM licenses l LEFT JOIN devices d ON d.license_id = l.id WHERE l.key_hash = ? GROUP BY l.id",
            (key_hash(payload.key),),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Invalid license key")
        if row["status"] != "ACTIVE":
            raise HTTPException(status_code=403, detail=f"License is {row['status']}")
        if row["expires_at"] and datetime.fromisoformat(row["expires_at"]) <= now():
            connection.execute("UPDATE licenses SET status = 'EXPIRED' WHERE id = ?", (row["id"],))
            raise HTTPException(status_code=403, detail="License has expired")
        known = connection.execute("SELECT id FROM devices WHERE license_id = ? AND installation_id = ?", (row["id"], payload.installation_id)).fetchone()
        if known is None and row["device_count"] >= row["max_devices"]:
            raise HTTPException(status_code=409, detail="Maximum device limit reached")
        if known is None:
            connection.execute("INSERT INTO devices VALUES (?, ?, ?, ?)", (secrets.token_hex(12), row["id"], payload.installation_id, now().isoformat()))
        token = secrets.token_urlsafe(40)
        token_expiry = now() + timedelta(hours=12)
        connection.execute("INSERT INTO sessions VALUES (?, ?, ?, ?)", (token, row["id"], payload.installation_id, token_expiry.isoformat()))
        refreshed = connection.execute("SELECT l.*, COUNT(d.id) AS device_count FROM licenses l LEFT JOIN devices d ON d.license_id = l.id WHERE l.id = ? GROUP BY l.id", (row["id"],)).fetchone()
    return session_payload(refreshed, token)


@app.post("/license/validate")
def validate(payload: ValidateRequest) -> dict:
    with db() as connection:
        row = connection.execute(
            "SELECT l.*, COUNT(d.id) AS device_count, s.expires_at AS session_expires FROM sessions s JOIN licenses l ON l.id = s.license_id LEFT JOIN devices d ON d.license_id = l.id WHERE s.token = ? AND s.installation_id = ? GROUP BY l.id, s.expires_at",
            (payload.session_token, payload.installation_id),
        ).fetchone()
    if row is None or datetime.fromisoformat(row["session_expires"]) <= now():
        raise HTTPException(status_code=401, detail="Session expired or invalid")
    if row["status"] != "ACTIVE":
        raise HTTPException(status_code=403, detail=f"License is {row['status']}")
    return session_payload(row, payload.session_token)


@app.get("/admin", include_in_schema=False)
def admin_panel() -> FileResponse:
    return FileResponse(ROOT / "admin" / "index.html")
