"""Detection rules metadata router."""
from fastapi import APIRouter, Depends
from core.deps import current_user
from rules import RULES_META

router = APIRouter(prefix="/rules", tags=["rules"])


@router.get("")
async def list_rules(_: dict = Depends(current_user)):
    return RULES_META
