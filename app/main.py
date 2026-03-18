from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
from pathlib import Path

from app.config import settings
from app.database import create_db_and_tables

# routers
from app.routers import auth
from app.routers import urlscanner
from app.routers import ids
from app.routers import reports
from app.routers import dashboard
from app.routers import rag
from app.routers import filescanner
from app.routers import ids_realtime, ids_stream
from app.routers import profile

# middleware
from app.middleware.ids_middleware import ids_middleware


# ------------------------
# APP LIFESPAN
# ------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Application Startup: Creating database tables...")
    create_db_and_tables()
    yield
    print("Application Shutdown: Cleanup complete.")


# ------------------------
# FASTAPI APP
# ------------------------
app = FastAPI(
    title=settings.APP_NAME,
    version="1.0.0",
    docs_url="/api/v1/docs",
    redoc_url="/api/v1/redoc",
    lifespan=lifespan
)


# ------------------------
# CORS (IMPORTANT FOR VERCEL + LOCAL)
# ------------------------
origins = [
    "http://localhost:5173",
    "http://localhost:3000",
    "https://sentinel-sec-ai.vercel.app",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_origin_regex="https://.*\.vercel\.app",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ------------------------
# IDS MIDDLEWARE
# ------------------------
app.middleware("http")(ids_middleware)


# ------------------------
# STATIC FILES (PROFILE AVATAR STORAGE)
# ------------------------
media_path = Path("app/media")
media_path.mkdir(parents=True, exist_ok=True)

app.mount(
    "/api/media",
    StaticFiles(directory="app/media"),
    name="media"
)


# ------------------------
# API ROUTES
# ------------------------
API_PREFIX = "/api/v1"

app.include_router(auth.router, prefix=API_PREFIX)
app.include_router(urlscanner.router, prefix=API_PREFIX)
app.include_router(ids.router, prefix=API_PREFIX)
app.include_router(filescanner.router, prefix=API_PREFIX)
app.include_router(dashboard.router, prefix=API_PREFIX)
app.include_router(rag.router, prefix=API_PREFIX)
app.include_router(reports.router, prefix=API_PREFIX)
app.include_router(ids_realtime.router, prefix=API_PREFIX)
app.include_router(ids_stream.router, prefix=API_PREFIX)
app.include_router(profile.router, prefix=API_PREFIX)


# ------------------------
# ROOT ENDPOINT
# ------------------------
@app.get("/")
def root():
    return {
        "project": "SentinelAI",
        "status": "running",
        "api_docs": "/api/v1/docs"
    }