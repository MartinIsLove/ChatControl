from fastapi import APIRouter
from routes.login import router as r_login
from routes.signup import router as r_signup
from routes.chat import router as r_chats
from routes.message import router as r_messages

router = APIRouter()
router.include_router(r_login, tags=["login"])
router.include_router(r_signup, tags=["signup"])
router.include_router(r_chats, tags=["chats"])
router.include_router(r_messages, tags=["messages"])
