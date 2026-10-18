from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from zoneinfo import ZoneInfo

import pytest

from yasno_bot.config import Config
from yasno_bot.history import History
from yasno_bot.storage import EncryptedStore
from yasno_bot.telegram import BotBlockedError, TelegramError

KYIV = ZoneInfo("Europe/Kyiv")


def at(day: int, hour: int, minute: int = 0, month: int = 10) -> datetime:
    return datetime(2026, month, day, hour, minute, tzinfo=KYIV)


def raw_day(date: str, slots, status: str = "ScheduleApplies") -> Dict[str, Any]:
    return {
        "date": f"{date}T00:00:00+03:00",
        "status": status,
        "slots": [{"start": s, "end": e, "type": t} for s, e, t in slots],
    }


def full_day(*outages):
    """Слоти на добу: задані відключення Definite, решта — NotPlanned."""
    slots, cursor = [], 0
    for start, end in outages:
        if start > cursor:
            slots.append((cursor, start, "NotPlanned"))
        slots.append((start, end, "Definite"))
        cursor = end
    if cursor < 1440:
        slots.append((cursor, 1440, "NotPlanned"))
    return slots


def raw_api(today: str, today_slots, tomorrow: str, tomorrow_slots, group: str = "3.1"):
    return {
        group: {
            "today": raw_day(today, today_slots),
            "tomorrow": raw_day(tomorrow, tomorrow_slots, "ScheduleApplies" if tomorrow_slots else "WaitingForSchedule"),
            "updatedOn": "2026-10-17T05:35:00+00:00",
        }
    }


class FakeTelegram:
    def __init__(self) -> None:
        self.updates: List[Dict[str, Any]] = []
        self.sent: List[Dict[str, Any]] = []
        self.edited: List[Dict[str, Any]] = []
        self.deleted: List[tuple] = []
        self.blocked: set = set()
        self.failing: set = set()
        self.not_editable: set = set()
        self._next_id = 100

    def get_updates(self, offset: Optional[int] = None):
        pending = [u for u in self.updates if offset is None or u["update_id"] >= offset]
        return pending[:100]

    def _check(self, method: str, chat_id: str) -> None:
        if chat_id in self.blocked:
            raise BotBlockedError(method, "Forbidden: bot was blocked by the user", 403)
        if chat_id in self.failing:
            raise TelegramError(method, "Bad Gateway", 502)

    def send_message(self, chat_id: str, text: str, silent: bool = False) -> int:
        self._check("sendMessage", chat_id)
        self._next_id += 1
        self.sent.append({"chat_id": chat_id, "text": text, "silent": silent, "id": self._next_id})
        return self._next_id

    def edit_message(self, chat_id: str, message_id: int, text: str) -> bool:
        self._check("editMessageText", chat_id)
        if message_id in self.not_editable:
            return False
        self.edited.append({"chat_id": chat_id, "id": message_id, "text": text})
        return True

    def delete_message(self, chat_id: str, message_id: int) -> bool:
        self._check("deleteMessage", chat_id)
        self.deleted.append((chat_id, message_id))
        return True

    def texts_to(self, chat_id: str) -> List[str]:
        return [m["text"] for m in self.sent if m["chat_id"] == chat_id]

    def clear(self) -> None:
        self.sent.clear()
        self.edited.clear()
        self.deleted.clear()


def start_update(update_id: int, chat_id: int, text: str = "/start") -> Dict[str, Any]:
    return {"update_id": update_id, "message": {"chat": {"id": chat_id}, "text": text}}


@pytest.fixture
def cfg(tmp_path: Path) -> Config:
    return Config(
        bot_token="123:abc",
        region="3",
        dsos="301",
        group="3.1",
        encryption_key="test-key",
        db_file=tmp_path / "bot_data.json",
        history_dir=tmp_path / "history",
        tz=KYIV,
        quiet_hours=(23, 7),
    )


@pytest.fixture
def store(cfg: Config) -> EncryptedStore:
    return EncryptedStore(cfg.encryption_key)


@pytest.fixture
def history(store: EncryptedStore, cfg: Config) -> History:
    return History(store, cfg.history_dir)
