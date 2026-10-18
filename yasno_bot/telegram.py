"""Мінімальний клієнт Telegram Bot API."""

from __future__ import annotations

import logging
import time
from typing import Any, Callable, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

# Ці методи безпечно повторювати: повтор не створить дубль повідомлення.
IDEMPOTENT_METHODS = {"getUpdates", "editMessageText", "deleteMessage", "getMe"}

BLOCKED_MARKERS = (
    "bot was blocked by the user",
    "user is deactivated",
    "chat not found",
    "bot was kicked",
    "bot can't initiate conversation",
)
NOT_MODIFIED = "message is not modified"
NOT_EDITABLE_MARKERS = ("message to edit not found", "message can't be edited", "message_id_invalid")

MAX_ATTEMPTS = 4
MAX_RETRY_AFTER = 60


class TelegramError(RuntimeError):
    def __init__(self, method: str, description: str, code: Optional[int] = None) -> None:
        super().__init__(f"{method}: {description}")
        self.method = method
        self.description = description
        self.code = code


class BotBlockedError(TelegramError):
    """Користувач заблокував бота або чат більше не існує — писати туди марно."""


class TelegramClient:
    def __init__(
        self,
        token: str,
        session: Optional[requests.Session] = None,
        timeout: float = 15,
        min_interval: float = 0.05,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._token = token
        self._base = f"https://api.telegram.org/bot{token}/"
        self._session = session or requests.Session()
        self._timeout = timeout
        self._min_interval = min_interval  # ~20 запитів/с, ліміт Telegram — 30
        self._sleep = sleep
        self._last_call = 0.0

    def _hide_token(self, text: str) -> str:
        return text.replace(self._token, "***") if self._token else text

    def _throttle(self) -> None:
        wait = self._last_call + self._min_interval - time.monotonic()
        if wait > 0:
            self._sleep(wait)
        self._last_call = time.monotonic()

    def call(self, method: str, payload: Dict[str, Any]) -> Any:
        idempotent = method in IDEMPOTENT_METHODS
        last_error = "немає відповіді"
        for attempt in range(1, MAX_ATTEMPTS + 1):
            self._throttle()
            try:
                r = self._session.post(self._base + method, json=payload, timeout=self._timeout)
            except requests.RequestException as e:
                last_error = self._hide_token(str(e))
                # sendMessage повторюємо лише якщо з'єднання навіть не встановилося,
                # інакше повідомлення могло дійти і користувач отримає дубль.
                if idempotent or isinstance(e, requests.ConnectTimeout):
                    logger.warning("%s: мережева помилка (спроба %d): %s", method, attempt, last_error)
                    self._sleep(attempt * 2)
                    continue
                raise TelegramError(method, last_error)

            try:
                data = r.json()
            except ValueError:
                data = {"ok": False, "error_code": r.status_code, "description": f"HTTP {r.status_code}"}

            if data.get("ok"):
                return data.get("result")

            code = data.get("error_code")
            description = str(data.get("description", ""))
            last_error = description
            if code == 429:
                retry_after = (data.get("parameters") or {}).get("retry_after", 1)
                logger.warning("%s: ліміт Telegram, чекаємо %s с", method, retry_after)
                self._sleep(min(float(retry_after), MAX_RETRY_AFTER))
                continue
            if code and code >= 500 and idempotent:
                self._sleep(attempt * 2)
                continue
            lowered = description.lower()
            if code == 403 or any(m in lowered for m in BLOCKED_MARKERS):
                raise BotBlockedError(method, description, code)
            raise TelegramError(method, description, code)
        raise TelegramError(method, f"не вдалося після {MAX_ATTEMPTS} спроб: {last_error}")

    # ------------------------------------------------------------------ методи

    def get_updates(self, offset: Optional[int] = None) -> List[Dict[str, Any]]:
        payload: Dict[str, Any] = {
            "timeout": 0,
            "limit": 100,
            "allowed_updates": ["message", "my_chat_member"],
        }
        if offset is not None:
            payload["offset"] = offset
        return self.call("getUpdates", payload) or []

    def send_message(self, chat_id: str, text: str, silent: bool = False) -> Optional[int]:
        result = self.call(
            "sendMessage",
            {"chat_id": chat_id, "text": text, "disable_notification": silent},
        )
        return (result or {}).get("message_id")

    def edit_message(self, chat_id: str, message_id: int, text: str) -> bool:
        """True — повідомлення має потрібний текст; False — редагувати неможливо."""
        try:
            self.call("editMessageText", {"chat_id": chat_id, "message_id": message_id, "text": text})
        except BotBlockedError:
            raise
        except TelegramError as e:
            lowered = e.description.lower()
            if NOT_MODIFIED in lowered:
                return True
            if any(m in lowered for m in NOT_EDITABLE_MARKERS):
                return False
            raise
        return True

    def delete_message(self, chat_id: str, message_id: int) -> bool:
        # Бот може видаляти лише повідомлення, молодші за 48 годин; старіші просто лишаються.
        try:
            self.call("deleteMessage", {"chat_id": chat_id, "message_id": message_id})
        except BotBlockedError:
            raise
        except TelegramError as e:
            logger.info("Не вдалося видалити повідомлення %s у %s: %s", message_id, chat_id, e.description)
            return False
        return True
