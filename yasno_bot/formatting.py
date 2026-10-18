"""Тексти повідомлень бота."""

from __future__ import annotations

from datetime import date, datetime, timedelta
from typing import List, Sequence, Tuple

from yasno_bot.history import History, PeriodStats
from yasno_bot.schedule import (
    DEFINITE,
    NOT_PLANNED,
    POSSIBLE,
    Day,
    Schedule,
    format_duration,
    minutes_to_hhmm,
    outage_periods,
)

WEEKDAYS = ("пн", "вт", "ср", "чт", "пт", "сб", "нд")

SLOT_LABELS = {
    NOT_PLANNED: "🟢 світло є",
    DEFINITE: "🔴 світла немає",
    POSSIBLE: "🟡 можливе відключення",
}

HELP_TEXT = (
    "Команди:\n"
    "/start — підписатися й отримати актуальний графік\n"
    "/stats — статистика відключень за 7 і 30 днів\n"
    "/history — історія змін графіка за останні дні\n"
    "/stop — відписатися\n\n"
    "Бот перевіряє Yasno приблизно раз на годину, тому відповідь на команду "
    "може прийти не одразу."
)

WELCOME_TEXT = (
    "👋 Вітаю! Я надсилатиму графік планових відключень і повідомлятиму, "
    "коли його змінять.\n\n" + HELP_TEXT
)

NO_DATA_TEXT = "⏳ Зараз не вдалося отримати графік від Yasno. Надішлю його, щойно він з'явиться."

STOP_TEXT = "Ви відписалися від оновлень. Щоб підписатися знову, надішліть /start."

DISCLAIMER = "Дані за графіком Yasno; фактичні відключення можуть відрізнятися."


def fmt_date(d: date) -> str:
    return f"{d:%d.%m} ({WEEKDAYS[d.weekday()]})"


def fmt_interval(start: int, end: int) -> str:
    return f"{minutes_to_hhmm(start)}–{minutes_to_hhmm(end)}"


def fmt_intervals(intervals: Sequence[Tuple[int, int]]) -> str:
    return ", ".join(fmt_interval(s, e) for s, e in intervals)


def fmt_day(title: str, day: Day) -> str:
    lines = [f"📅 {title}, {fmt_date(day.date)}:"]
    if not day.slots:
        lines.append("Графік формується")
        return "\n".join(lines)
    for slot in day.slots:
        label = SLOT_LABELS.get(slot.kind, slot.kind)
        lines.append(f"{minutes_to_hhmm(slot.start)} - {minutes_to_hhmm(slot.end)} {label}")
    minutes = day.outage_minutes
    lines.append(f"Без світла: {format_duration(timedelta(minutes=minutes))}" if minutes else "Відключень немає")
    if day.status == "WaitingForSchedule":
        lines.append("Графік може змінитися")
    return "\n".join(lines)


def fmt_moment(moment: datetime, now: datetime) -> str:
    if moment.date() == now.date():
        return f"о {moment:%H:%M}"
    if moment.date() == now.date() + timedelta(days=1):
        return f"завтра о {moment:%H:%M}"
    return f"{moment:%d.%m} о {moment:%H:%M}"


def next_outage_line(schedule: Schedule, now: datetime) -> str:
    """'Через скільки й на скільки' — найближче відключення відносно now."""
    for start, end in outage_periods(schedule.days, now.tzinfo):
        if end <= now:
            continue
        if start <= now:
            return (
                f"🔴 Зараз світла немає. Увімкнуть {fmt_moment(end, now)} "
                f"(через {format_duration(end - now)})"
            )
        return (
            f"⏳ Наступне відключення {fmt_moment(start, now)} "
            f"(через {format_duration(start - now)}), триватиме {format_duration(end - start)}"
        )
    if not schedule.tomorrow.slots:
        return "🟢 Сьогодні відключень більше не заплановано"
    return "🟢 До кінця завтрашнього дня відключень не заплановано"


def render_schedule(schedule: Schedule, now: datetime, group: str, stale: bool = False) -> str:
    parts = [
        f"💡 Графік відключень · група {group}",
        fmt_day("СЬОГОДНІ", schedule.today),
        fmt_day("ЗАВТРА", schedule.tomorrow),
    ]
    footer = [next_outage_line(schedule, now)]
    if schedule.updated_on:
        footer.append(f"Оновлено: {schedule.updated_on:%d.%m.%Y %H:%M}")
    footer.append(f"Перевірено ботом: {now:%d.%m %H:%M}")
    if stale:
        footer.append("⚠️ Yasno зараз не відповідає — показано останні отримані дані")
    parts.append("\n".join(footer))
    return "\n\n".join(parts)


def render_notification(changes: List[Tuple[str, Day, str]]) -> str:
    lines = []
    for title, day, kind in changes:
        head = "📅 З'явився графік" if kind == "new" else "🔔 Змінено графік"
        outages = fmt_intervals(day.outages)
        tail = f"без світла {outages}" if outages else "відключень немає"
        lines.append(f"{head} на {title}, {fmt_date(day.date)}: {tail}")
    return "\n".join(lines)


def _fmt_period(title: str, s: PeriodStats) -> str:
    if not s.days_with_data:
        return f"{title}: даних поки немає"
    avg = timedelta(minutes=s.minutes / s.days_with_data)
    lines = [
        f"{title}: без світла {format_duration(timedelta(minutes=s.minutes))} "
        f"(у середньому {format_duration(avg)} на добу)",
        f"Відключень: {s.outage_count}, змін графіка: {s.changes}",
    ]
    if s.longest:
        d, start, end = s.longest
        lines.append(
            f"Найдовше: {format_duration(timedelta(minutes=end - start))} "
            f"({d:%d.%m} {fmt_interval(start, end)})"
        )
    if s.days_with_data < s.days_total:
        lines.append(f"Дані є за {s.days_with_data} з {s.days_total} днів")
    return "\n".join(lines)


def render_stats(history: History, today: date, group: str, tz) -> str:
    parts = [
        f"📊 Статистика відключень · група {group}",
        _fmt_period("За 7 днів", history.period_stats(today, 7, tz)),
        _fmt_period("За 30 днів", history.period_stats(today, 30, tz)),
    ]
    days = []
    for i in range(7):
        s = history.day_stats(today - timedelta(days=i), tz)
        if s is None:
            continue
        if s.outages:
            days.append(
                f"{fmt_date(s.date)} — {fmt_intervals(s.outages)} · "
                f"{format_duration(timedelta(minutes=s.minutes))}"
            )
        else:
            days.append(f"{fmt_date(s.date)} — без відключень")
    if days:
        parts.append("Вимкнення / увімкнення світла:\n" + "\n".join(days))
    parts.append(DISCLAIMER)
    return "\n\n".join(parts)


def render_history(history: History, today: date, tz, days_back: int = 3) -> str:
    titles = {today + timedelta(days=1): "завтра", today: "сьогодні"}
    blocks = []
    for offset in range(-1, days_back):
        d = today - timedelta(days=offset)
        versions = history.versions(d, tz)
        if not versions:
            continue
        head = fmt_date(d) + (f", {titles[d]}" if d in titles else "")
        lines = [f"📅 {head}:"]
        for v in versions:
            if not v.day.slots:
                desc = "графік формується"
            elif v.day.outages:
                desc = fmt_intervals(v.day.outages)
            else:
                desc = "без відключень"
            lines.append(f"  {v.published_at:%d.%m %H:%M} — {desc}")
        blocks.append("\n".join(lines))
    if not blocks:
        return "🗂 Історія змін поки порожня — вона збирається з моменту запуску нової версії бота."
    return "🗂 Історія змін графіка (час публікації Yasno)\n\n" + "\n\n".join(blocks)


def truncate(text: str, limit: int = 4096) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"

