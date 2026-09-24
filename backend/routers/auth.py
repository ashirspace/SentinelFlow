"""Authentication endpoints for SentinelFlow."""
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, EmailStr

from auth import (
    verify_password, create_access_token, create_refresh_token,
    set_auth_cookies, clear_auth_cookies
)
from core.database import db
from core.deps import current_user, audit

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginBody(BaseModel):
    email: EmailStr
    password: str


@router.post("/login")
async def login(body: LoginBody, request: Request, response: Response):
    email = body.email.lower().strip()
    ip = request.client.host if request.client else "unknown"
    identifier = f"{ip}:{email}"

    # Brute-force lockout: 5 fails in 15 min
    now = datetime.now(timezone.utc)
    attempt = await db.login_attempts.find_one({"identifier": identifier})
    if attempt and attempt.get("locked_until"):
        lu = datetime.fromisoformat(attempt["locked_until"])
        if lu.tzinfo is None:
            lu = lu.replace(tzinfo=timezone.utc)
        if lu > now:
            raise HTTPException(status_code=429, detail="Too many failed attempts. Try again later.")

    user = await db.users.find_one({"email": email})
    if not user or not verify_password(body.password, user["password_hash"]):
        # Record failure
        fails = (attempt or {}).get("fails", 0) + 1
        update = {"identifier": identifier, "fails": fails, "last_at": now.isoformat()}
        if fails >= 5:
            update["locked_until"] = (now + timedelta(minutes=15)).isoformat()
        await db.login_attempts.update_one({"identifier": identifier}, {"$set": update}, upsert=True)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if user.get("disabled"):
        raise HTTPException(status_code=403, detail="Account disabled")

    await db.login_attempts.delete_one({"identifier": identifier})
    uid = str(user["_id"])
    tv = int(user.get("token_version", 0))
    access = create_access_token(uid, email, user["role"], tv)
    refresh = create_refresh_token(uid, tv)
    set_auth_cookies(response, access, refresh)
    await audit(email, "login", target=uid)
    return {"id": uid, "email": email, "name": user["name"], "role": user["role"]}


@router.post("/logout")
async def logout(response: Response, user: dict = Depends(current_user)):
    clear_auth_cookies(response)
    await audit(user["email"], "logout", target=user["id"])
    return {"ok": True}


@router.get("/me")
async def me(user: dict = Depends(current_user)):
    return {"id": user["id"], "email": user["email"], "name": user["name"], "role": user["role"]}
