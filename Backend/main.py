from routes_handler import router as r
from fastapi import FastAPI
from database import sqlite as db_setup
from routes_handler import router as api_router
from fastapi.middleware.cors import CORSMiddleware





app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://localhost:5173", 
        "https://192.168.1.228:5173",
        "https://server.apernici.it",
        "https://apernici.it",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)
# Initialize database on backend startup
@app.on_event("startup")
async def startup_event():
	"""Run database setup when the backend starts."""
	db_setup.initDB()  # This executes the setup code in sqlite.py



	
