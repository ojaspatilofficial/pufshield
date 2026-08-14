"""Application-wide configuration loaded from environment / .env file."""

from functools import lru_cache
import os
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """Runtime settings for PUFShield."""

    app_host: str = "127.0.0.1"
    app_port: int = 8000
    app_debug: bool = True

    database_path: str = "data/pufshield.db"
    puf_credential_secret_path: str = "data/puf_secret.bin"

    boot_certificate_valid_days: int = 730
    ca_certificate_valid_days: int = 3650
    intermediate_certificate_valid_days: int = 1825
    device_key_size_bytes: int = 32

    log_level: str = "INFO"

    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    @property
    def database_file(self) -> Path:
        path = Path(self.database_path)
        if not path.is_absolute():
            path = PROJECT_ROOT / path
        return path

    @property
    def credential_secret_file(self) -> Path:
        path = Path(self.puf_credential_secret_path)
        if not path.is_absolute():
            path = PROJECT_ROOT / path
        return path


@lru_cache
def get_settings() -> Settings:
    return Settings()


@lru_cache
def get_puf_credential_secret() -> bytes:
    """Load (or create) the server-side secret used to derive PUF credentials.

    The secret lives outside the database so a DB leak alone never exposes
    usable PUF credentials. Persisted locally; override the file path via
    ``PUF_CREDENTIAL_SECRET_PATH``.
    """
    settings = get_settings()
    path = settings.credential_secret_file
    if path.exists():
        try:
            return bytes.fromhex(path.read_text(encoding="utf-8").strip())
        except (ValueError, UnicodeDecodeError) as exc:
            raise RuntimeError(
                f"PUF credential secret file {path} is corrupt; restore it or delete it to regenerate "
                "(regenerating invalidates every existing enrollment)"
            ) from exc
    secret = os.urandom(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(secret.hex(), encoding="utf-8")
    return secret
