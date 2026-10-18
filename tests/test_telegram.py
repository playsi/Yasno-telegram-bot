from __future__ import annotations

import pytest
import requests

from yasno_bot.telegram import BotBlockedError, TelegramClient, TelegramError


class FakeResponse:
    def __init__(self, data, status=200):
        self._data = data
        self.status_code = status

    def json(self):
        return self._data


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def post(self, url, json, timeout):
        self.calls.append((url, json))
        r = self.responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def client(responses):
    session = FakeSession(responses)
    return TelegramClient("123:SECRET", session=session, min_interval=0, sleep=lambda s: None), session


def test_retry_after_on_429():
    tg, session = client([
        FakeResponse({"ok": False, "error_code": 429, "parameters": {"retry_after": 3}}, 429),
        FakeResponse({"ok": True, "result": {"message_id": 9}}),
    ])
    assert tg.send_message("1", "hi") == 9
    assert len(session.calls) == 2


def test_send_is_not_retried_after_read_timeout():
    tg, session = client([requests.ReadTimeout("timeout"), FakeResponse({"ok": True, "result": {}})])
    with pytest.raises(TelegramError):
        tg.send_message("1", "hi")
    assert len(session.calls) == 1


def test_edit_is_retried_after_network_error():
    tg, session = client([requests.ConnectionError("reset"), FakeResponse({"ok": True, "result": True})])
    assert tg.edit_message("1", 5, "hi") is True


def test_blocked_and_not_modified():
    tg, _ = client([FakeResponse({"ok": False, "error_code": 403, "description": "Forbidden: bot was blocked by the user"}, 403)])
    with pytest.raises(BotBlockedError):
        tg.send_message("1", "hi")

    tg, _ = client([FakeResponse({"ok": False, "error_code": 400, "description": "Bad Request: message is not modified"}, 400)])
    assert tg.edit_message("1", 5, "hi") is True

    tg, _ = client([FakeResponse({"ok": False, "error_code": 400, "description": "Bad Request: message to edit not found"}, 400)])
    assert tg.edit_message("1", 5, "hi") is False


def test_token_is_hidden_in_errors():
    tg, _ = client([requests.ReadTimeout("url /bot123:SECRET/sendMessage")])
    with pytest.raises(TelegramError) as e:
        tg.send_message("1", "hi")
    assert "SECRET" not in str(e.value)
