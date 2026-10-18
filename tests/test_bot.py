from __future__ import annotations

from datetime import datetime

from tests.conftest import FakeTelegram, at, full_day, raw_api, start_update
from yasno_bot import yasno
from yasno_bot.bot import Bot, migrate, new_db, parse_command
from yasno_bot.history import History


class Runner:
    """Імітує послідовні запуски workflow зі збереженням стану між ними."""

    def __init__(self, cfg, store) -> None:
        self.cfg = cfg
        self.store = store
        self.tg = FakeTelegram()

    def run(self, now: datetime, raw=None) -> dict:
        db = migrate(self.store.load(self.cfg.db_file, new_db))
        history = History(self.store, self.cfg.history_dir)
        schedule, stale = None, False
        if raw is not None:
            schedule = yasno.parse_schedule(raw, self.cfg.group, now)
            history.record(schedule, now)
        else:
            schedule = history.fallback_schedule(now.date(), self.cfg.tz)
            stale = schedule is not None
        try:
            Bot(self.cfg, self.tg, db, history, now).run(schedule, stale)
        finally:
            self.store.save(self.cfg.db_file, db)
            history.save()
        return db


DAY17 = full_day((960, 1200))           # 16:00–20:00
DAY18 = full_day((480, 720))            # 08:00–12:00
DAY18_CHANGED = full_day((480, 840))    # 08:00–14:00


def test_parse_command_variants():
    assert parse_command("/start") == "start"
    assert parse_command("/start promo") == "start"
    assert parse_command("/start@YasnoBot") == "start"
    assert parse_command("/STATS") == "stats"
    assert parse_command("/unknown") == "help"
    assert parse_command("привіт") is None


def test_start_registers_and_sends_one_schedule_for_repeated_presses(cfg, store):
    r = Runner(cfg, store)
    r.tg.updates = [start_update(1, 42), start_update(2, 42), start_update(3, 42, "/start@Bot")]
    db = r.run(at(17, 10), raw_api("2026-10-17", DAY17, "2026-10-18", []))

    texts = r.tg.texts_to("42")
    assert len(texts) == 2  # привітання + один графік
    assert texts[1].startswith("💡 Графік відключень")
    assert "42" in db["users"]


def test_same_updates_are_not_processed_twice(cfg, store):
    r = Runner(cfg, store)
    r.tg.updates = [start_update(1, 42)]
    raw = raw_api("2026-10-17", DAY17, "2026-10-18", [])
    r.run(at(17, 10), raw)
    r.tg.clear()
    # Telegram повертає те саме непідтверджене оновлення ще раз.
    r.run(at(17, 11), raw)
    assert r.tg.sent == []


def test_updates_with_lower_ids_after_reset_are_not_ignored(cfg, store):
    r = Runner(cfg, store)
    raw = raw_api("2026-10-17", DAY17, "2026-10-18", [])
    r.tg.updates = [start_update(900000, 1)]
    r.run(at(17, 10), raw)
    # Після тижня тиші Telegram може почати нумерацію з меншого числа.
    r.tg.updates = [start_update(5, 2)]
    db = r.run(at(17, 11), raw)
    assert "2" in db["users"]


def test_repeated_start_replaces_previous_schedule_message(cfg, store):
    r = Runner(cfg, store)
    raw = raw_api("2026-10-17", DAY17, "2026-10-18", [])
    r.tg.updates = [start_update(1, 42)]
    db = r.run(at(17, 10), raw)
    first_id = db["users"]["42"]["schedule_message_id"]

    r.tg.updates = [start_update(2, 42)]
    r.tg.clear()
    db = r.run(at(17, 11), raw)
    assert len(r.tg.texts_to("42")) == 1
    assert ("42", first_id) in r.tg.deleted
    assert db["users"]["42"]["schedule_message_id"] != first_id


def test_midnight_rollover_does_not_notify(cfg, store):
    r = Runner(cfg, store)
    r.tg.updates = [start_update(1, 42)]
    r.run(at(17, 22), raw_api("2026-10-17", DAY17, "2026-10-18", DAY18))
    r.tg.clear()

    # Після півночі «завтра» стало «сьогодні», нове «завтра» ще формується.
    r.run(at(18, 0, 30), raw_api("2026-10-18", DAY18, "2026-10-19", []))
    assert r.tg.sent == []
    assert len(r.tg.edited) == 1  # лише тихе оновлення повідомлення з графіком


def test_new_and_changed_schedule_notify_once(cfg, store):
    r = Runner(cfg, store)
    r.tg.updates = [start_update(1, 42)]
    r.run(at(17, 10), raw_api("2026-10-17", DAY17, "2026-10-18", []))
    r.tg.clear()

    r.run(at(17, 19), raw_api("2026-10-17", DAY17, "2026-10-18", DAY18))
    assert len(r.tg.sent) == 1
    assert r.tg.sent[0]["text"].startswith("📅 З'явився графік на завтра")
    assert r.tg.sent[0]["silent"] is False
    first_notify = r.tg.sent[0]["id"]
    r.tg.clear()

    r.run(at(17, 20), raw_api("2026-10-17", DAY17, "2026-10-18", DAY18))
    assert r.tg.sent == []

    r.run(at(17, 23, 30), raw_api("2026-10-17", DAY17, "2026-10-18", DAY18_CHANGED))
    assert len(r.tg.sent) == 1
    assert "🔔 Змінено графік на завтра" in r.tg.sent[0]["text"]
    assert "08:00–14:00" in r.tg.sent[0]["text"]
    assert r.tg.sent[0]["silent"] is True  # тихі години
    assert ("42", first_notify) in r.tg.deleted


def test_yasno_down_keeps_last_schedule(cfg, store):
    r = Runner(cfg, store)
    r.tg.updates = [start_update(1, 42)]
    r.run(at(17, 10), raw_api("2026-10-17", DAY17, "2026-10-18", []))
    r.tg.clear()

    r.run(at(17, 11), raw=None)
    assert r.tg.sent == []
    text = r.tg.edited[0]["text"]
    assert "16:00 - 20:00 🔴 світла немає" in text
    assert "Yasno зараз не відповідає" in text


def test_new_user_when_yasno_down_gets_schedule_later(cfg, store):
    r = Runner(cfg, store)
    r.tg.updates = [start_update(1, 42)]
    db = r.run(at(17, 10), raw=None)
    placeholder = db["users"]["42"]["schedule_message_id"]
    assert "не вдалося отримати графік" in r.tg.texts_to("42")[-1]

    r.tg.clear()
    r.run(at(17, 11), raw_api("2026-10-17", DAY17, "2026-10-18", []))
    assert r.tg.edited[0]["id"] == placeholder
    assert r.tg.sent == []


def test_blocked_user_is_removed(cfg, store):
    r = Runner(cfg, store)
    r.tg.updates = [start_update(1, 42), start_update(2, 7)]
    raw = raw_api("2026-10-17", DAY17, "2026-10-18", [])
    r.run(at(17, 10), raw)
    r.tg.blocked.add("42")
    db = r.run(at(17, 11), raw)
    assert set(db["users"]) == {"7"}


def test_kicked_member_update_removes_user(cfg, store):
    r = Runner(cfg, store)
    raw = raw_api("2026-10-17", DAY17, "2026-10-18", [])
    r.tg.updates = [start_update(1, 42)]
    r.run(at(17, 10), raw)
    r.tg.updates = [{"update_id": 2, "my_chat_member": {"chat": {"id": 42}, "new_chat_member": {"status": "kicked"}}}]
    db = r.run(at(17, 11), raw)
    assert db["users"] == {}


def test_failed_notification_is_retried_next_run(cfg, store):
    r = Runner(cfg, store)
    r.tg.updates = [start_update(1, 42)]
    r.run(at(17, 10), raw_api("2026-10-17", DAY17, "2026-10-18", []))
    r.tg.failing.add("42")
    r.run(at(17, 19), raw_api("2026-10-17", DAY17, "2026-10-18", DAY18))
    r.tg.failing.clear()
    r.tg.clear()
    r.run(at(17, 20), raw_api("2026-10-17", DAY17, "2026-10-18", DAY18))
    assert [m["text"].split()[0] for m in r.tg.sent] == ["📅"]


def test_not_editable_message_is_resent(cfg, store):
    r = Runner(cfg, store)
    raw = raw_api("2026-10-17", DAY17, "2026-10-18", [])
    r.tg.updates = [start_update(1, 42)]
    db = r.run(at(17, 10), raw)
    r.tg.not_editable.add(db["users"]["42"]["schedule_message_id"])
    r.tg.clear()
    r.run(at(17, 11), raw)
    assert len(r.tg.sent) == 1 and r.tg.sent[0]["silent"] is True


def test_migrates_v1_database_without_spurious_notifications(cfg, store):
    store.save(cfg.db_file, {
        "users": {"42": {"schedule_message_id": 5, "notify_message_id": 6, "last_schedule": "old text"}},
        "last_update_id": 777,
    })
    r = Runner(cfg, store)
    db = r.run(at(17, 10), raw_api("2026-10-17", DAY17, "2026-10-18", DAY18))
    assert r.tg.sent == []
    assert r.tg.edited[0]["id"] == 5
    assert "last_schedule" not in db["users"]["42"]
    assert db["version"] == 2


def test_v1_last_batch_is_not_answered_again(cfg, store):
    store.save(cfg.db_file, {"users": {"42": {"schedule_message_id": 5}}, "last_update_id": 10})
    r = Runner(cfg, store)
    r.tg.updates = [start_update(10, 42), start_update(11, 7)]
    db = r.run(at(17, 10), raw_api("2026-10-17", DAY17, "2026-10-18", []))
    assert r.tg.texts_to("42") == []
    assert "7" in db["users"]
    assert "legacy_last_update_id" not in db


def test_stats_and_history_commands(cfg, store):
    r = Runner(cfg, store)
    r.run(at(16, 12), raw_api("2026-10-16", full_day((0, 240)), "2026-10-17", []))
    r.run(at(16, 21), raw_api("2026-10-16", full_day((0, 240)), "2026-10-17", DAY17))
    r.run(at(16, 22), raw_api("2026-10-16", full_day((0, 240)), "2026-10-17", full_day((960, 1320))))
    r.tg.updates = [start_update(1, 42, "/stats"), start_update(2, 42, "/history")]
    r.run(at(17, 10), raw_api("2026-10-17", full_day((960, 1320)), "2026-10-18", []))

    stats, hist = r.tg.texts_to("42")
    assert "За 7 днів: без світла 10 год" in stats
    assert "змін графіка: 1" in stats
    assert "17.10 (сб) — 16:00–22:00 · 6 год" in stats
    assert "16:00–20:00" in hist and "16:00–22:00" in hist


def test_db_unchanged_between_runs_within_a_day(cfg, store):
    r = Runner(cfg, store)
    raw = raw_api("2026-10-17", DAY17, "2026-10-18", [])
    r.tg.updates = [start_update(1, 42)]
    r.run(at(17, 10), raw)
    before = cfg.db_file.read_bytes()
    r.run(at(17, 11), raw)
    assert cfg.db_file.read_bytes() == before  # немає змін — немає коміту
