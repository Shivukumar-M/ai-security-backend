from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
from pathlib import Path

from app.config import settings
from app.database import create_db_and_tables

# all routers
from app.routers import auth
from app.routers import urlscanner
from app.routers import ids
from app.routers import reports
from app.routers import dashboard
from app.routers import rag
from app.routers import filescanner
from app.routers import ids_realtime, ids_stream
from app.middleware.ids_middleware import ids_middleware
from app.routers import profile




@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Application Startup: Creating database tables...")
    create_db_and_tables()
    yield
    print("Application Shutdown: Cleanup complete.")


app = FastAPI(
    title=settings.APP_NAME,
    version="1.0.0",
    docs_url="/api/v1/docs",
    redoc_url="/api/v1/redoc",
    lifespan=lifespan
)

# ------------------------
# CORS (REQUIRED)
# ------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------
# IDS MIDDLEWARE (REAL-TIME)
# ------------------------
app.middleware("http")(ids_middleware)

# ------------------------
# STATIC FILES (AVATARS)
# ------------------------
media_path = Path("app/media")
media_path.mkdir(parents=True, exist_ok=True)
app.mount("/api/media", StaticFiles(directory="app/media"), name="media")

# ------------------------
# ROUTES
# ------------------------
API_PREFIX = "/api/v1"

app.include_router(auth.router, prefix=API_PREFIX)
app.include_router(urlscanner.router, prefix=API_PREFIX)
app.include_router(ids.router, prefix=API_PREFIX)
app.include_router(filescanner.router, prefix=API_PREFIX)
app.include_router(dashboard.router, prefix=API_PREFIX)
app.include_router(rag.router, prefix=API_PREFIX)
app.include_router(reports.router, prefix=API_PREFIX)
app.include_router(ids_realtime.router, prefix="/api/v1")
app.include_router(ids_stream.router, prefix="/api/v1")
app.include_router(profile.router, prefix=API_PREFIX)


@app.get("/")
def root():
    return {"message": "FastAPI backend running"}
