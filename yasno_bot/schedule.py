"""Модель графіка відключень і розрахунки часу."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, tzinfo
from typing import Any, Dict, Iterable, List, Optional, Tuple

DEFINITE = "Definite"
POSSIBLE = "Possible"
NOT_PLANNED = "NotPlanned"

EMPTY_SIGNATURE = "[]"


@dataclass(frozen=True)
class Slot:
    start: int  # хвилини від початку доби, 0..1440
    end: int
    kind: str

    def to_list(self) -> List[Any]:
        return [self.start, self.end, self.kind]


@dataclass(frozen=True)
class Day:
    date: date
    status: str
    slots: Tuple[Slot, ...]

    @property
    def signature(self) -> str:
        """Відбиток слотів: однаковий відбиток = графік на цю дату не змінився."""
        return json.dumps([s.to_list() for s in self.slots])

    @property
    def outages(self) -> List[Tuple[int, int]]:
        """Гарантовані відключення (хвилини), сусідні слоти об'єднано."""
        return merge_intervals((s.start, s.end) for s in self.slots if s.kind == DEFINITE)

    @property
    def outage_minutes(self) -> int:
        return sum(end - start for start, end in self.outages)


@dataclass(frozen=True)
class Schedule:
    today: Day
    tomorrow: Day
    updated_on: Optional[datetime]

    @property
    def days(self) -> Tuple[Day, Day]:
        return self.today, self.tomorrow

    def signatures(self) -> Dict[str, str]:
        return {d.date.isoformat(): d.signature for d in self.days}


def slots_from_lists(items: Iterable[Any]) -> Tuple[Slot, ...]:
    return tuple(Slot(int(s), int(e), str(k)) for s, e, k in items)


def merge_intervals(intervals: Iterable[Tuple[Any, Any]]) -> List[Tuple[Any, Any]]:
    merged: List[Tuple[Any, Any]] = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def day_start(d: date, tz: tzinfo) -> datetime:
    return datetime.combine(d, time(0), tzinfo=tz)


def outage_periods(days: Iterable[Day], tz: tzinfo) -> List[Tuple[datetime, datetime]]:
    """Відключення як інтервали дат; відключення через північ стає одним інтервалом."""
    periods = []
    for day in days:
        base = day_start(day.date, tz)
        for start, end in day.outages:
            periods.append((base + timedelta(minutes=start), base + timedelta(minutes=end)))
    return merge_intervals(periods)


def minutes_to_hhmm(minutes: int) -> str:
    return f"{minutes // 60:02d}:{minutes % 60:02d}"


def format_duration(delta: timedelta) -> str:
    minutes = max(0, round(delta.total_seconds() / 60))
    hours, mins = divmod(minutes, 60)
    if hours and mins:
        return f"{hours} год {mins} хв"
    if hours:
        return f"{hours} год"
    return f"{mins} хв"
