"""User management endpoints (Admin only)."""
from datetime import datetime, timezone
from typing import List, Optional
from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr, Field

from auth import hash_password
from core.database import db
from core.deps import require_admin, audit

router = APIRouter(prefix="/users", tags=["users"])


class UserCreateBody(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6)
    name: str
    role: str = Field(pattern="^(admin|analyst)$")


class UserOut(BaseModel):
    id: str
    email: str
    name: str
    role: str
    created_at: Optional[str] = None


@router.get("", response_model=List[UserOut])
async def list_users(_: dict = Depends(require_admin)):
    docs = await db.users.find({}, {"password_hash": 0}).to_list(1000)
    out = []
    for d in docs:
        out.append(UserOut(
            id=str(d["_id"]), email=d["email"], name=d["name"],
            role=d["role"], created_at=d.get("created_at"),
        ))
    return out


@router.post("", response_model=UserOut)
async def create_user(body: UserCreateBody, admin: dict = Depends(require_admin)):
    email = body.email.lower().strip()
    if await db.users.find_one({"email": email}):
        raise HTTPException(status_code=409, detail="Email already exists")
    doc = {
        "email": email,
        "password_hash": hash_password(body.password),
        "name": body.name,
        "role": body.role,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    r = await db.users.insert_one(doc)
    await audit(admin["email"], "create_user", target=email, meta={"role": body.role})
    return UserOut(id=str(r.inserted_id), email=email, name=body.name,
                   role=body.role, created_at=doc["created_at"])


@router.delete("/{user_id}")
async def delete_user(user_id: str, admin: dict = Depends(require_admin)):
    if user_id == admin["id"]:
        raise HTTPException(status_code=400, detail="Cannot delete self")
    r = await db.users.delete_one({"_id": ObjectId(user_id)})
    if r.deleted_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    await audit(admin["email"], "delete_user", target=user_id)
    return {"ok": True}
