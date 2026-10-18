"""Архів графіків: кожна версія графіка на кожну дату, по файлу на місяць.

Структура файлу data/history/YYYY-MM.enc (після розшифрування):
    {"days": {"2026-10-17": {"status": "...", "versions": [
        {"seen_at": "<ISO>", "updated_on": "<ISO>|null", "slots": [[start, end, type], ...]}
    ]}}}

Помісячні файли, щоб щогодинні коміти змінювали лише невеликий поточний файл,
а не перезаписували всю історію (зашифрований файл git не стискає між версіями).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta, tzinfo
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from yasno_bot.schedule import EMPTY_SIGNATURE, Day, Schedule, slots_from_lists
from yasno_bot.storage import EncryptedStore


@dataclass(frozen=True)
class Version:
    seen_at: datetime
    updated_on: Optional[datetime]
    day: Day

    @property
    def published_at(self) -> datetime:
        return self.updated_on or self.seen_at


@dataclass(frozen=True)
class DayStats:
    date: date
    outages: List[Tuple[int, int]]
    minutes: int
    changes: int


@dataclass(frozen=True)
class PeriodStats:
    days_total: int
    days_with_data: int
    minutes: int
    outage_count: int
    longest: Optional[Tuple[date, int, int]]  # (дата, початок, кінець) у хвилинах
    changes: int


class History:
    def __init__(self, store: EncryptedStore, directory: Path) -> None:
        self._store = store
        self._dir = directory
        self._months: Dict[str, Dict[str, Any]] = {}

    def _path(self, month: str) -> Path:
        return self._dir / f"{month}.enc"

    def _month(self, d: date) -> Dict[str, Any]:
        key = d.strftime("%Y-%m")
        if key not in self._months:
            self._months[key] = self._store.load(self._path(key), lambda: {"days": {}})
        return self._months[key]

    def save(self) -> None:
        for key, data in self._months.items():
            self._store.save(self._path(key), data)

    # ------------------------------------------------------------------ запис

    def record(self, schedule: Schedule, seen_at: datetime) -> None:
        for day in schedule.days:
            self.record_day(day, seen_at, schedule.updated_on)

    def record_day(self, day: Day, seen_at: datetime, updated_on: Optional[datetime]) -> bool:
        """Додає нову версію, якщо слоти змінилися. Повертає True, якщо додано."""
        entry = self._month(day.date)["days"].setdefault(day.date.isoformat(), {"versions": []})
        entry["status"] = day.status
        versions = entry["versions"]
        if versions and _signature(versions[-1]) == day.signature:
            return False
        versions.append(
            {
                "seen_at": seen_at.isoformat(),
                "updated_on": updated_on.isoformat() if updated_on else None,
                "slots": [s.to_list() for s in day.slots],
            }
        )
        return True

    # ------------------------------------------------------------------ читання

    def versions(self, d: date, tz: tzinfo) -> List[Version]:
        entry = self._month(d)["days"].get(d.isoformat())
        if not entry:
            return []
        status = entry.get("status", "")
        return [
            Version(
                seen_at=datetime.fromisoformat(v["seen_at"]).astimezone(tz),
                updated_on=datetime.fromisoformat(v["updated_on"]).astimezone(tz) if v.get("updated_on") else None,
                day=Day(d, status, slots_from_lists(v["slots"])),
            )
            for v in entry.get("versions", [])
        ]

    def latest(self, d: date, tz: tzinfo) -> Optional[Version]:
        versions = self.versions(d, tz)
        return versions[-1] if versions else None

    def fallback_schedule(self, today: date, tz: tzinfo) -> Optional[Schedule]:
        """Останній відомий графік на сьогодні/завтра — коли Yasno не відповідає."""
        today_v = self.latest(today, tz)
        if today_v is None:
            return None
        tomorrow = today + timedelta(days=1)
        tomorrow_v = self.latest(tomorrow, tz)
        return Schedule(
            today=today_v.day,
            tomorrow=tomorrow_v.day if tomorrow_v else Day(tomorrow, "", ()),
            updated_on=max(v.published_at for v in (today_v, tomorrow_v) if v),
        )

    # ------------------------------------------------------------------ статистика

    def day_stats(self, d: date, tz: tzinfo) -> Optional[DayStats]:
        versions = self.versions(d, tz)
        if not versions:
            return None
        final = versions[-1].day
        return DayStats(d, final.outages, final.outage_minutes, count_changes(versions))

    def period_stats(self, end: date, days: int, tz: tzinfo) -> PeriodStats:
        stats = [self.day_stats(end - timedelta(days=i), tz) for i in range(days)]
        stats = [s for s in stats if s is not None]
        longest = None
        count = 0
        for s in stats:
            count += len(s.outages)
            for start, finish in s.outages:
                if longest is None or finish - start > longest[2] - longest[1]:
                    longest = (s.date, start, finish)
        return PeriodStats(
            days_total=days,
            days_with_data=len(stats),
            minutes=sum(s.minutes for s in stats),
            outage_count=count,
            longest=longest,
            changes=sum(s.changes for s in stats),
        )


def _signature(version: Dict[str, Any]) -> str:
    return Day(date.min, "", slots_from_lists(version["slots"])).signature


def count_changes(versions: List[Version]) -> int:
    """Скільки разів змінювали вже опублікований графік (поява графіка — не зміна)."""
    changes = 0
    published = False
    for v in versions:
        if v.day.signature == EMPTY_SIGNATURE:
            continue
        if published:
            changes += 1
        published = True
    return changes

