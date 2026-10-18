from __future__ import annotations

from tests.conftest import at, full_day, raw_api
from yasno_bot import formatting, yasno
from yasno_bot.config import Config, parse_quiet_hours


def schedule(now, today, tomorrow):
    raw = raw_api(now.date().isoformat(), today, "2026-10-18", tomorrow)
    return yasno.parse_schedule(raw, "3.1", now)


def test_next_outage_countdown_and_duration():
    now = at(17, 13, 17)
    s = schedule(now, full_day((960, 1200)), [])
    line = formatting.next_outage_line(s, now)
    assert line == "⏳ Наступне відключення о 16:00 (через 2 год 43 хв), триватиме 4 год"


def test_current_outage_spanning_midnight_is_merged():
    now = at(17, 23, 0)
    s = schedule(now, full_day((1320, 1440)), full_day((0, 180)))
    line = formatting.next_outage_line(s, now)
    assert line == "🔴 Зараз світла немає. Увімкнуть завтра о 03:00 (через 4 год)"


def test_no_more_outages_today():
    now = at(17, 21, 0)
    s = schedule(now, full_day((960, 1200)), [])
    assert formatting.next_outage_line(s, now) == "🟢 Сьогодні відключень більше не заплановано"


def test_updated_on_is_shown_in_kyiv_time():
    now = at(17, 13, 0)
    text = formatting.render_schedule(schedule(now, full_day((960, 1200)), []), now, "3.1")
    assert "Оновлено: 17.10.2026 08:35" in text  # 05:35 UTC
    assert "Без світла: 4 год" in text
    assert "📅 ЗАВТРА, 18.10 (нд):\nГрафік формується" in text


def test_date_from_api_has_priority_over_clock():
    now = at(18, 0, 5)
    raw = raw_api("2026-10-17", full_day((960, 1200)), "2026-10-18", [])
    s = yasno.parse_schedule(raw, "3.1", now)
    assert s.today.date.isoformat() == "2026-10-17"


def test_missing_group_lists_available():
    raw = raw_api("2026-10-17", [], "2026-10-18", [], group="1.1")
    try:
        yasno.parse_schedule(raw, "3.1", at(17, 10))
    except yasno.YasnoError as e:
        assert "1.1" in str(e)
    else:
        raise AssertionError("expected YasnoError")


def test_quiet_hours(cfg):
    assert parse_quiet_hours("off") is None
    assert parse_quiet_hours("23-7") == (23, 7)
    assert cfg.is_quiet(23) and cfg.is_quiet(3) and not cfg.is_quiet(7) and not cfg.is_quiet(12)


def test_config_from_env_defaults():
    c = Config.from_env({"BOT_TOKEN": "t", "QUIET_HOURS": ""})
    assert c.quiet_hours == (23, 7)
    assert str(c.db_file) == "bot_data.json"
    assert c.tz.key == "Europe/Kyiv"
