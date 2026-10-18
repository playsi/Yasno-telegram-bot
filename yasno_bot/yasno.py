"""Клієнт публічного API Yasno."""

from __future__ import annotations

import logging
from datetime import date, datetime, timedelta, tzinfo
from typing import Any, Dict, List, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from yasno_bot.schedule import Day, Schedule, Slot

logger = logging.getLogger(__name__)

HTTP_TIMEOUT = 20


class YasnoError(RuntimeError):
    pass


def create_session() -> requests.Session:
    # GET безпечно повторювати, тому тут ретраї робить urllib3.
    retry = Retry(total=3, backoff_factor=1, status_forcelist=(429, 500, 502, 503, 504))
    session = requests.Session()
    session.mount("https://", HTTPAdapter(max_retries=retry))
    return session


def fetch_raw(session: requests.Session, url: str) -> Dict[str, Any]:
    try:
        r = session.get(url, timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        data = r.json()
    except (requests.RequestException, ValueError) as e:
        raise YasnoError(f"Yasno API недоступне: {e}")
    if not isinstance(data, dict) or not data:
        raise YasnoError("Yasno API повернуло порожню відповідь")
    return data


def list_groups(raw: Dict[str, Any]) -> List[str]:
    return sorted(k for k, v in raw.items() if isinstance(v, dict))


def parse_datetime(value: Any, tz: tzinfo) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=tz)
    return dt.astimezone(tz)


def parse_day(raw: Any, fallback_date: date, tz: tzinfo) -> Day:
    raw = raw if isinstance(raw, dict) else {}
    # Дата з API надійніша за обчислену: біля півночі кеш Yasno може ще віддавати вчорашній день.
    parsed = parse_datetime(raw.get("date"), tz)
    slots = []
    for item in raw.get("slots") or []:
        try:
            slots.append(Slot(int(item["start"]), int(item["end"]), str(item.get("type", ""))))
        except (KeyError, TypeError, ValueError):
            logger.warning("Пропущено некоректний слот: %r", item)
    return Day(
        date=parsed.date() if parsed else fallback_date,
        status=str(raw.get("status") or ""),
        slots=tuple(sorted(slots, key=lambda s: s.start)),
    )


def parse_schedule(raw: Dict[str, Any], group: str, now: datetime) -> Schedule:
    data = raw.get(group)
    if not isinstance(data, dict):
        raise YasnoError(
            f"У відповіді Yasno немає групи {group!r}. Доступні групи: {', '.join(list_groups(raw))}"
        )
    tz = now.tzinfo
    today = now.date()
    return Schedule(
        today=parse_day(data.get("today"), today, tz),
        tomorrow=parse_day(data.get("tomorrow"), today + timedelta(days=1), tz),
        updated_on=parse_datetime(data.get("updatedOn") or data.get("updated_on"), tz),
    )
