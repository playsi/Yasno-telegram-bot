"""Точка входу: python main.py [--preview | --list-groups]."""

from __future__ import annotations

import argparse
import logging
from datetime import datetime
from typing import List, Optional

from yasno_bot import formatting, yasno
from yasno_bot.bot import Bot, migrate, new_db
from yasno_bot.config import Config, ConfigError
from yasno_bot.history import History
from yasno_bot.storage import EncryptedStore, StorageError
from yasno_bot.telegram import TelegramClient

logger = logging.getLogger("yasno_bot")


def load_dotenv_if_available() -> None:
    """Для локального запуску: змінні з secrets.env (у GitHub Actions — з Secrets)."""
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    load_dotenv("secrets.env")


def run_bot(cfg: Config) -> int:
    store = EncryptedStore(cfg.encryption_key)
    db = migrate(store.load(cfg.db_file, new_db))
    history = History(store, cfg.history_dir)
    now = datetime.now(cfg.tz)

    schedule, stale = None, False
    try:
        raw = yasno.fetch_raw(yasno.create_session(), cfg.api_url)
        schedule = yasno.parse_schedule(raw, cfg.group, now)
        history.record(schedule, now)
    except yasno.YasnoError as e:
        logger.warning("%s", e)
        schedule = history.fallback_schedule(now.date(), cfg.tz)
        stale = schedule is not None

    bot = Bot(cfg, TelegramClient(cfg.bot_token), db, history, now)
    try:
        bot.run(schedule, stale)
    finally:
        # Зберігаємо навіть після збою посередині, щоб не надсилати вже надіслане ще раз.
        store.save(cfg.db_file, db)
        history.save()
    logger.info("Готово: користувачів %d, графік %s", len(db["users"]),
                "застарілий" if stale else ("є" if schedule else "недоступний"))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Yasno Telegram bot")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--preview", action="store_true",
                      help="показати графік у консолі (потрібні лише REGION, DSOS, GROUP)")
    mode.add_argument("--list-groups", action="store_true",
                      help="показати групи, доступні для REGION і DSOS")
    args = parser.parse_args(argv)

    load_dotenv_if_available()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    try:
        cfg = Config.from_env()
        if args.list_groups:
            cfg.require("region", "dsos")
            raw = yasno.fetch_raw(yasno.create_session(), cfg.api_url)
            print("\n".join(yasno.list_groups(raw)))
            return 0
        if args.preview:
            cfg.require("region", "dsos", "group")
            now = datetime.now(cfg.tz)
            raw = yasno.fetch_raw(yasno.create_session(), cfg.api_url)
            print(formatting.render_schedule(yasno.parse_schedule(raw, cfg.group, now), now, cfg.group))
            return 0
        cfg.require("bot_token", "region", "dsos", "group", "encryption_key")
        return run_bot(cfg)
    except (ConfigError, StorageError) as e:
        logger.error("%s", e)
        return 2
    except yasno.YasnoError as e:
        logger.error("%s", e)
        return 1
