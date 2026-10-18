"""Налаштування бота зі змінних оточення."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional, Tuple
from zoneinfo import ZoneInfo

API_URL_TEMPLATE = (
    "https://app.yasno.ua/api/blackout-service/public/shutdowns"
    "/regions/{region}/dsos/{dsos}/planned-outages"
)

DEFAULT_QUIET_HOURS = "23-7"

# Поле конфігу -> назва змінної оточення (для зрозумілих помилок).
ENV_NAMES = {
    "bot_token": "BOT_TOKEN",
    "region": "REGION",
    "dsos": "DSOS",
    "group": "GROUP",
    "encryption_key": "ENCRYPTION_KEY",
}


class ConfigError(RuntimeError):
    pass


def parse_quiet_hours(value: str) -> Optional[Tuple[int, int]]:
    """'23-7' -> (23, 7); 'off' / 'none' -> None (тихі години вимкнено)."""
    value = value.strip().lower()
    if value in ("off", "none", "no", "0"):
        return None
    try:
        start, end = (int(part) for part in value.split("-"))
    except ValueError:
        raise ConfigError(f"QUIET_HOURS має бути у форматі '23-7' або 'off', отримано: {value!r}")
    if not (0 <= start <= 23 and 0 <= end <= 23):
        raise ConfigError(f"QUIET_HOURS: години мають бути від 0 до 23, отримано: {value!r}")
    return start, end


@dataclass(frozen=True)
class Config:
    bot_token: str
    region: str
    dsos: str
    group: str
    encryption_key: str
    db_file: Path
    history_dir: Path
    tz: ZoneInfo
    quiet_hours: Optional[Tuple[int, int]]

    @property
    def api_url(self) -> str:
        return API_URL_TEMPLATE.format(region=self.region, dsos=self.dsos)

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "Config":
        env = os.environ if env is None else env

        def get(name: str, default: str = "") -> str:
            # Порожні значення (наприклад, незадані vars у GitHub Actions) = значення за замовчуванням.
            return (env.get(name) or default).strip()

        return cls(
            bot_token=get("BOT_TOKEN"),
            region=get("REGION"),
            dsos=get("DSOS"),
            group=get("GROUP"),
            encryption_key=get("ENCRYPTION_KEY"),
            db_file=Path(get("DB_FILE", "bot_data.json")),
            history_dir=Path(get("HISTORY_DIR", "data/history")),
            tz=ZoneInfo(get("TIMEZONE", "Europe/Kyiv")),
            quiet_hours=parse_quiet_hours(get("QUIET_HOURS", DEFAULT_QUIET_HOURS)),
        )

    def require(self, *fields: str) -> None:
        missing = [ENV_NAMES[f] for f in fields if not getattr(self, f)]
        if missing:
            raise ConfigError("Не задані змінні оточення: " + ", ".join(missing))

    def is_quiet(self, hour: int) -> bool:
        if self.quiet_hours is None:
            return False
        start, end = self.quiet_hours
        if start <= end:
            return start <= hour < end
        return hour >= start or hour < end
