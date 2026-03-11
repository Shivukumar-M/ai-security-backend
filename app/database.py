# backend/app/database.py
from typing import Generator
from sqlmodel import create_engine, Session, SQLModel
from app.config import settings
import logging

# ⭐ IMPORT ALL MODELS HERE ⭐
from app.models import filescan_model
from app.models import urlscan_model
from app.models import user_model

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

engine = create_engine(settings.DATABASE_URL, echo=False, pool_pre_ping=True)

def create_db_and_tables():
    logger.info("Creating database tables...")
    try:
        SQLModel.metadata.create_all(engine)
        logger.info("Tables created successfully.")
    except Exception as e:
        logger.error(f"Error creating tables: {e}")

def get_session() -> Generator[Session, None, None]:
    with Session(engine) as session:
        yield session
