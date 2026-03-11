# backend/app/config.py
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Load from .env
    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore"
    )

    # --- Core App Settings ---
    APP_NAME: str = "AI Security Platform"
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # --- Database Settings ---
    DATABASE_URL: str

    # --- Threat Intel API Keys ---
    VIRUSTOTAL_API_KEY: str = ""           # REQUIRED for File Scanner
    APIVOID_API_KEY: str = ""              # OPTIONAL
    IPQS_API_KEY: str = ""                 # OPTIONAL
    GOOGLE_SAFE_BROWSING_API_KEY: str = "" # OPTIONAL

    # --- RAG / Gemini LLM ---
    GOOGLE_API_KEY: str = ""               # REQUIRED for RAG (Gemini)

    # --- HuggingFace Model Hosting ---
    HF_TOKEN: str = ""                     # OPTIONAL if repo is public

    # --- GitHub Integration ---
    GITHUB_TOKEN: str = ""                 # OPTIONAL (required for private repos / GitHub API)

    # --- Legacy OpenAI Key (Safe to keep) ---
    OPENAI_API_KEY: str = ""


settings = Settings()
