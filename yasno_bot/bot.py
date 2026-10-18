"""Один запуск бота: обробка команд і оновлення графіка в усіх користувачів."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from yasno_bot import formatting
from yasno_bot.config import Config
from yasno_bot.history import History
from yasno_bot.schedule import EMPTY_SIGNATURE, Day, Schedule
from yasno_bot.telegram import BotBlockedError, TelegramClient, TelegramError

logger = logging.getLogger(__name__)

DB_VERSION = 2
# Скільки останніх update_id пам'ятати, щоб не обробити одну команду двічі.
PROCESSED_UPDATES_LIMIT = 500
MAX_UPDATE_PAGES = 20

COMMAND_ALIASES = {
    "/start": "start",
    "/schedule": "start",
    "/stop": "stop",
    "/stats": "stats",
    "/history": "history",
    "/help": "help",
}


def new_db() -> Dict[str, Any]:
    return {"version": DB_VERSION, "users": {}, "processed_updates": [], "meta": {}}


def migrate(db: Dict[str, Any]) -> Dict[str, Any]:
    """Оновлює базу старого формату (v1: last_schedule у кожного користувача)."""
    db.setdefault("users", {})
    db.setdefault("processed_updates", [])
    db.setdefault("meta", {})
    if "last_update_id" in db:
        # v1 не підтверджував останню пачку оновлень: без цього фільтра перший запуск
        # нової версії відповів би на вже оброблені /start ще раз.
        db["legacy_last_update_id"] = db.pop("last_update_id")
    for user in db["users"].values():
        user.pop("last_schedule", None)
        user.setdefault("schedule_message_id", None)
        user.setdefault("notify_message_id", None)
        # known=None: базовий стан ще не зафіксовано, перший запуск нічого не сповіщає.
        user.setdefault("known", None)
    db["version"] = DB_VERSION
    return db


def parse_command(text: str) -> Optional[str]:
    """'/start', '/start payload', '/start@MyBot' -> 'start'; не команда -> None."""
    if not text.startswith("/"):
        return None
    word = text.split()[0].split("@")[0].lower()
    return COMMAND_ALIASES.get(word, "help")


def detect_changes(known: Optional[Dict[str, str]], schedule: Schedule) -> List[Tuple[str, Day, str]]:
    """Що змінилося для користувача з минулого разу.

    Порівнюємо за датою, а не «сьогодні/завтра»: після півночі вчорашнє «завтра»
    стає «сьогодні» з тим самим відбитком — це не зміна і сповіщення не буде.
    """
    if known is None:
        return []
    changes = []
    for title, day in (("сьогодні", schedule.today), ("завтра", schedule.tomorrow)):
        previous = known.get(day.date.isoformat())
        if previous == day.signature or not day.slots:
            continue
        kind = "new" if previous in (None, EMPTY_SIGNATURE) else "changed"
        changes.append((title, day, kind))
    return changes


class Bot:
    def __init__(
        self,
        cfg: Config,
        tg: TelegramClient,
        db: Dict[str, Any],
        history: History,
        now: datetime,
    ) -> None:
        self.cfg = cfg
        self.tg = tg
        self.db = db
        self.users: Dict[str, Dict[str, Any]] = db["users"]
        self.history = history
        self.now = now
        self.schedule: Optional[Schedule] = None
        self.stale = False

    @property
    def quiet(self) -> bool:
        return self.cfg.is_quiet(self.now.hour)

    def run(self, schedule: Optional[Schedule], stale: bool = False) -> None:
        self.schedule = schedule
        self.stale = stale
        touched = self.handle_updates()
        self.refresh_users(skip=touched)
        # Раз на добу база змінюється навіть без подій: коміт = активність у репозиторії,
        # інакше GitHub вимикає cron через 60 днів тиші (наприклад, влітку без відключень).
        self.db["meta"]["last_run_date"] = self.now.date().isoformat()

    # ------------------------------------------------------------------ команди

    def fetch_updates(self) -> Tuple[List[Dict[str, Any]], bool]:
        """Усі непідтверджені оновлення і чи вдалося їх отримати.

        Перший запит — без offset: збережений offset міг би «проковтнути» нові
        повідомлення, бо після тижня тиші Telegram починає нумерацію update_id
        з випадкового числа. Від повторів захищає список processed_updates.
        """
        updates: List[Dict[str, Any]] = []
        offset = None
        ok = True
        try:
            for _ in range(MAX_UPDATE_PAGES):
                batch = self.tg.get_updates(offset)
                updates.extend(batch)
                if len(batch) < 100:
                    break
                offset = batch[-1]["update_id"] + 1
        except TelegramError as e:
            ok = False
            if e.code == 409:
                logger.error("getUpdates конфліктує з webhook — видаліть його: deleteWebhook")
            else:
                logger.error("Не вдалося отримати повідомлення: %s", e)
        return updates, ok

    def handle_updates(self) -> Set[str]:
        processed = self.db["processed_updates"]
        seen = set(processed)
        legacy_last = self.db.get("legacy_last_update_id") or 0
        handled: Set[Tuple[str, str]] = set()
        touched: Set[str] = set()
        updates, ok = self.fetch_updates()
        if ok:
            self.db.pop("legacy_last_update_id", None)
        for update in updates:
            update_id = update.get("update_id")
            if update_id in seen:
                continue
            seen.add(update_id)
            processed.append(update_id)
            if update_id <= legacy_last:
                continue
            try:
                self.handle_update(update, handled, touched)
            except Exception:
                logger.exception("Помилка обробки оновлення %s", update_id)
        del processed[:-PROCESSED_UPDATES_LIMIT]
        return touched

    def handle_update(self, update: Dict[str, Any], handled: Set[Tuple[str, str]], touched: Set[str]) -> None:
        member = update.get("my_chat_member")
        if member:
            if (member.get("new_chat_member") or {}).get("status") in ("kicked", "left"):
                self.remove_user(str(member["chat"]["id"]), "бота заблоковано")
            return

        message = update.get("message") or {}
        command = parse_command(message.get("text") or "")
        if command is None or "chat" not in message:
            return
        chat_id = str(message["chat"]["id"])
        # Кілька однакових команд за один запуск (людина натиснула /start тричі,
        # поки чекала) — відповідаємо один раз.
        if (chat_id, command) in handled:
            return
        handled.add((chat_id, command))

        try:
            if command == "start":
                self.cmd_start(chat_id)
                touched.add(chat_id)
            elif command == "stop":
                self.remove_user(chat_id, "команда /stop")
                self.tg.send_message(chat_id, formatting.STOP_TEXT)
            elif command == "stats":
                self.tg.send_message(chat_id, formatting.truncate(
                    formatting.render_stats(self.history, self.now.date(), self.cfg.group, self.cfg.tz)))
            elif command == "history":
                self.tg.send_message(chat_id, formatting.truncate(
                    formatting.render_history(self.history, self.now.date(), self.cfg.tz)))
            else:
                self.tg.send_message(chat_id, formatting.HELP_TEXT)
        except BotBlockedError:
            self.remove_user(chat_id, "бота заблоковано")

    def cmd_start(self, chat_id: str) -> None:
        user = self.users.get(chat_id)
        if user is None:
            user = self.users[chat_id] = {
                "schedule_message_id": None,
                "notify_message_id": None,
                "known": None,
                "joined": self.now.isoformat(),
            }
            logger.info("Новий користувач %s", chat_id)
            self.tg.send_message(chat_id, formatting.WELCOME_TEXT)
        self.send_fresh_schedule(chat_id, user)

    def send_fresh_schedule(self, chat_id: str, user: Dict[str, Any]) -> None:
        """Нове повідомлення з графіком внизу чату; старе видаляємо, щоб не було дублів."""
        old_id = user.get("schedule_message_id")
        text = self.render() if self.schedule else formatting.NO_DATA_TEXT
        try:
            new_id = self.tg.send_message(chat_id, text)
        except BotBlockedError:
            raise
        except TelegramError as e:
            # Користувача вже збережено: графік надішле наступний запуск.
            logger.warning("Не вдалося надіслати графік %s: %s", chat_id, e)
            return
        user["schedule_message_id"] = new_id
        if self.schedule and not self.stale:
            user["known"] = self.schedule.signatures()
        if old_id and old_id != new_id:
            self.tg.delete_message(chat_id, old_id)

    def remove_user(self, chat_id: str, reason: str) -> None:
        if self.users.pop(chat_id, None) is not None:
            logger.info("Користувача %s видалено: %s", chat_id, reason)

    # ------------------------------------------------------------------ розсилка

    def render(self) -> str:
        assert self.schedule is not None
        return formatting.render_schedule(self.schedule, self.now, self.cfg.group, self.stale)

    def refresh_users(self, skip: Set[str]) -> None:
        if self.schedule is None:
            logger.warning("Графіка немає — повідомлення користувачів не оновлюються")
            return
        text = self.render()
        for chat_id, user in list(self.users.items()):
            if chat_id in skip:
                continue
            try:
                self.refresh_user(chat_id, user, text)
            except BotBlockedError:
                self.remove_user(chat_id, "бота заблоковано")
            except TelegramError as e:
                # Стан користувача не змінено — наступний запуск спробує знову.
                logger.warning("Не вдалося оновити %s: %s", chat_id, e)

    def refresh_user(self, chat_id: str, user: Dict[str, Any], text: str) -> None:
        assert self.schedule is not None
        changes = [] if self.stale else detect_changes(user.get("known"), self.schedule)

        # Повідомлення з графіком редагуємо щоразу: оновлюється «через скільки».
        message_id = user.get("schedule_message_id")
        if not (message_id and self.tg.edit_message(chat_id, message_id, text)):
            user["schedule_message_id"] = self.tg.send_message(chat_id, text, silent=True)

        if changes:
            old_notify = user.get("notify_message_id")
            if old_notify:
                self.tg.delete_message(chat_id, old_notify)
            user["notify_message_id"] = self.tg.send_message(
                chat_id, formatting.render_notification(changes), silent=self.quiet
            )
            logger.info("Користувачу %s надіслано сповіщення про зміни", chat_id)

        if not self.stale:
            user["known"] = self.schedule.signatures()
