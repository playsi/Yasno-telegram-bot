from __future__ import annotations

import json
import logging
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import requests
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ------------------------------- CONFIG -------------------------------------
load_dotenv("secrets.env")

TOKEN = os.getenv("BOT_TOKEN")
REGION = os.getenv("REGION")
DSOS = os.getenv("DSOS")
GROUP = os.getenv("GROUP")

DB_FILE = Path(os.getenv("DB_FILE", "bot_data.json"))
API_URL = (
    f"https://app.yasno.ua/api/blackout-service/public/shutdowns/regions/{REGION}/dsos/{DSOS}/planned-outages"
)

# Timeouts / retries
HTTP_TIMEOUT = 20
TG_TIMEOUT = 10

# ------------------------------- LOGGING ------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("yasno-bot")

# ------------------------------- UTIL ---------------------------------------
# Encrypted JSON storage using ENCRYPTION_KEY (Fernet)

from cryptography.fernet import Fernet
import base64
import hashlib

ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")

if not ENCRYPTION_KEY:
    raise RuntimeError("ENCRYPTION_KEY is not set in environment")


def _derive_key(raw_key: str) -> bytes:
    """Derive a valid 32-byte Fernet key from any string."""
    digest = hashlib.sha256(raw_key.encode()).digest()
    return base64.urlsafe_b64encode(digest)


FERNET = Fernet(_derive_key(ENCRYPTION_KEY))


def safe_load_json(path: Path) -> Dict[str, Any]:
    try:
        if path.exists():
            with path.open("rb") as f:
                encrypted = f.read()
            decrypted = FERNET.decrypt(encrypted)
            return json.loads(decrypted.decode("utf-8"))
    except Exception as e:
        logger.warning("Failed to load or decrypt DB: %s", e)
    return {"users": {}, "last_update_id": 0}


def atomic_write_json(path: Path, data: Dict[str, Any]) -> None:
    # Encrypt -> write to temp -> atomic replace
    try:
        raw = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        encrypted = FERNET.encrypt(raw)

        tmp_fd, tmp_path = tempfile.mkstemp(prefix="tmp_bot_db_", suffix=".bin")
        with os.fdopen(tmp_fd, "wb") as f:
            f.write(encrypted)

        os.replace(tmp_path, str(path))
    except Exception as e:
        logger.error("Failed to save encrypted DB atomically: %s", e)


# --------------------------- REQUESTS SESSIONS -------------------------------

def create_session(retries: int = 3, backoff_factor: float = 0.3) -> requests.Session:
    s = requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        status=retries,
        backoff_factor=backoff_factor,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "POST"]),
    )
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s

API_SESSION = create_session()
TG_SESSION = create_session()


# ------------------------------- FORMATTING ---------------------------------

def minutes_to_time(minutes: int) -> str:
    hours = minutes // 60
    mins = minutes % 60
    return f"{hours:02d}:{mins:02d}"


def format_day(title: str, day_data: Dict[str, Any]) -> str:
    text = f"\n {title}:\n"
    
    status = day_data.get("status", "")
    slots = day_data.get("slots", [])
    
    # Якщо немає слотів взагалі - графік формується
    if not slots:
        return text + "Графік формується\n"
    
    # Якщо є слоти - показуємо їх незалежно від статусу
    icons = {
        "NotPlanned": "🟢 світло є",
        "Definite": "🔴 світла немає",
        "Possible": "🟡 можливе відключення",
    }

    for slot in slots:
        start_time = minutes_to_time(slot.get("start", 0))
        end_time = minutes_to_time(slot.get("end", 0))
        slot_type = slot.get("type", "")
        text += f"{start_time} - {end_time} {icons.get(slot_type, '')}\n"
    
    # Додаємо примітку якщо статус не стандартний
    if status == "WaitingForSchedule":
        text += "Графік може змінитися\n"

    return text

def format_schedule(group_data: Dict[str, Any]) -> str:
    if not group_data:
        return "❌ Дані недоступні"

    text = f"Графік відключень\n"

    text += format_day("СЬОГОДНІ", group_data.get("today", {}))
    text += format_day("ЗАВТРА", group_data.get("tomorrow", {}))

    updated_on = group_data.get("updatedOn") or group_data.get("updated_on")
    if updated_on:
        try:
            # Try to parse ISO timestamp, ensure timezone awareness
            dt = datetime.fromisoformat(updated_on.replace("Z", "+00:00"))
            dt = dt.astimezone()  # convert to local tz
            text += f"\nОновлено: {dt.strftime('%d.%m.%Y %H:%M')}"
        except Exception:
            # ignore parse errors
            pass

    return text


# --------------------------- TELEGRAM HELPERS -------------------------------

def tg_request(method: str, payload: Dict[str, Any], timeout: int = TG_TIMEOUT) -> Dict[str, Any]:
    if not TOKEN:
        raise RuntimeError("BOT_TOKEN not set in environment")

    url = f"https://api.telegram.org/bot{TOKEN}/{method}"
    try:
        r = TG_SESSION.post(url, json=payload, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        logger.warning("Telegram request %s failed: %s", method, e)
        return {}


def send_telegram_message(chat_id: str, text: str) -> Optional[int]:
    r = tg_request("sendMessage", {"chat_id": chat_id, "text": text})
    return r.get("result", {}).get("message_id")


def edit_telegram_message(chat_id: str, message_id: int, text: str) -> bool:
    r = tg_request(
        "editMessageText",
        {"chat_id": chat_id, "message_id": message_id, "text": text},
    )

    if not r:
        return False

    # Telegram returns {"ok": False, "description": "..."} on errors
    ok = r.get("ok") is True
    if not ok:
        desc = r.get("description", "")
        # common irrecoverable errors
        if "message to edit not found" in desc or "message can't be edited" in desc:
            logger.info("Edit failed because message is missing / not editable: %s", desc)
            return False
    return ok


def delete_telegram_message(chat_id: str, message_id: int) -> bool:
    r = tg_request("deleteMessage", {"chat_id": chat_id, "message_id": message_id})
    return r.get("ok") is True if r else False


def safe_edit_or_send(chat_id: str, old_message_id: Optional[int], text: str) -> Optional[int]:
    """Try edit. If fails, send new, return new message_id (or None on failure)."""
    if old_message_id is not None:
        try:
            if edit_telegram_message(chat_id, old_message_id, text):
                return old_message_id
        except Exception as e:
            logger.debug("Edit raised: %s", e)

    # edit failed or no message id — send new
    logger.info("Sending new message to %s (old id: %s)", chat_id, old_message_id)
    return send_telegram_message(chat_id, text)


# ----------------------------- YASNO API ------------------------------------

def get_api_data() -> Dict[str, Any]:
    try:
        r = API_SESSION.get(API_URL, timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        logger.warning("Failed to fetch API data: %s", e)
        return {}


# ----------------------------- USER HANDLING -------------------------------

@dataclass
class UserRecord:
    schedule_message_id: Optional[int] = None
    notify_message_id: Optional[int] = None
    last_schedule: Optional[str] = None


def register_user(db: Dict[str, Any], chat_id: str, api_data: Dict[str, Any]) -> None:
    group_data = api_data.get(GROUP, {}) if api_data else {}
    schedule_text = format_schedule(group_data)

    msg_id = send_telegram_message(chat_id, schedule_text)

    db.setdefault("users", {})
    db["users"][chat_id] = {
        "schedule_message_id": msg_id,
        "notify_message_id": None,
        "last_schedule": schedule_text,
    }


    logger.info("Registered new user %s (msg_id=%s)", chat_id, msg_id)


def check_new_users(db: Dict[str, Any], api_data: Dict[str, Any]) -> None:
    last_update_id = db.get("last_update_id", 0)
    payload = {"offset": last_update_id + 1, "timeout": 0}
    r = tg_request("getUpdates", payload)
    if not r:
        return

    for update in r.get("result", []):
        db["last_update_id"] = max(db.get("last_update_id", 0), update.get("update_id", 0))

        message = update.get("message") or {}
        text = message.get("text")
        chat = message.get("chat") or {}
        chat_id = str(chat.get("id"))

        if text == "/start":
            if chat_id not in db.get("users", {}):
                register_user(db, chat_id, api_data)
            else:
                # re-send schedule to user who used /start again
                logger.info("User %s sent /start but already registered", chat_id)
                user = db["users"][chat_id]
                send_telegram_message(chat_id, user.get("last_schedule", "❌ Дані недоступні"))


def update_users_schedules(db: Dict[str, Any], api_data: Dict[str, Any]) -> None:
    group_data = api_data.get(GROUP, {})
    new_schedule = format_schedule(group_data)

    users = db.get("users", {})
    if not users:
        logger.info("No users to update")
        return

    for chat_id, u in list(users.items()):
        old_schedule = u.get("last_schedule")
        old_msg_id = u.get("schedule_message_id")

        if old_schedule == new_schedule:
            continue

        new_msg_id = safe_edit_or_send(chat_id, old_msg_id, new_schedule)
        if new_msg_id is None:
            logger.warning("Failed to update or send message for %s", chat_id)
            continue

        # update DB record
        u["schedule_message_id"] = new_msg_id
        u["last_schedule"] = new_schedule

        old_notify_id = u.get("notify_message_id")

        # Видаляємо старе 🔔 повідомлення (навіть з попереднього дня)
        if old_notify_id:
            delete_telegram_message(chat_id, old_notify_id)

        # Відправляємо нове 🔔 повідомлення
        new_notify_id = send_telegram_message(chat_id, "🔔 Графік оновлено")

        # Зберігаємо новий ID
        u["notify_message_id"] = new_notify_id

        logger.info("Updated schedule for user")


# ---------------------------------- MAIN -----------------------------------

def main() -> int:
    logger.info("Starting bot run")

    db = safe_load_json(DB_FILE)

    api_data = get_api_data()
    if not api_data:
        logger.warning("API data missing — will still check for new users")

    # Check for new users (handles /start via getUpdates offset)
    try:
        check_new_users(db, api_data)
    except Exception as e:
        logger.exception("Error checking new users: %s", e)

    # Update schedules for existing users if we have API data
    if api_data:
        try:
            update_users_schedules(db, api_data)
        except Exception as e:
            logger.exception("Error updating schedules: %s", e)

    # Persist DB
    try:
        atomic_write_json(DB_FILE, db)
    except Exception as e:
        logger.exception("Failed to save DB: %s", e)

    logger.info("Run complete — users=%d", len(db.get("users", {})))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())