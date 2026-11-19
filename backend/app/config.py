"""Runtime configuration. Every secret comes from environment variables (or backend/.env)."""
from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _load_dotenv() -> None:
    env_file = BASE_DIR / ".env"
    if not env_file.exists():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_dotenv()


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


class Settings:
    database_url: str = os.getenv("WOLVE_DATABASE_URL", f"sqlite:///{(BASE_DIR / 'wolve.db').as_posix()}")
    upload_dir: Path = Path(os.getenv("WOLVE_UPLOAD_DIR", str(BASE_DIR / "storage")))
    max_upload_mb: int = int(os.getenv("WOLVE_MAX_UPLOAD_MB", "25"))
    cors_origins: list[str] = [
        o.strip() for o in os.getenv("WOLVE_CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",") if o.strip()
    ]

    # AI provider (Claude). Never hardcode keys.
    anthropic_api_key: str | None = os.getenv("ANTHROPIC_API_KEY") or None
    ai_model: str = os.getenv("WOLVE_AI_MODEL", "claude-opus-5-5")
    ai_enabled_default: bool = _bool("WOLVE_AI_ENABLED", True)

    # External lookups (DNS, geolocation). These contact third-party services.
    external_lookups_default: bool = _bool("WOLVE_EXTERNAL_LOOKUPS", True)

    # Optional threat-intel providers. Absent key => provider reported as "not configured".
    virustotal_api_key: str | None = os.getenv("VIRUSTOTAL_API_KEY") or None
    abuseipdb_api_key: str | None = os.getenv("ABUSEIPDB_API_KEY") or None

    rate_limit_per_minute: int = int(os.getenv("WOLVE_RATE_LIMIT_PER_MINUTE", "60"))


settings = Settings()
settings.upload_dir.mkdir(parents=True, exist_ok=True)
(settings.upload_dir / "quarantine").mkdir(exist_ok=True)
(settings.upload_dir / "tmp").mkdir(exist_ok=True)
