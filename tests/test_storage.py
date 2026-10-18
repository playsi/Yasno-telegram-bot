from __future__ import annotations

import pytest

from yasno_bot.storage import EncryptedStore, StorageError


def test_roundtrip_and_no_rewrite_when_unchanged(tmp_path):
    store = EncryptedStore("key")
    path = tmp_path / "db.json"
    assert store.save(path, {"a": 1}) is True
    assert store.load(path, dict) == {"a": 1}
    assert store.save(path, {"a": 1}) is False
    assert store.save(path, {"a": 2}) is True
    assert list(tmp_path.iterdir()) == [path]  # тимчасових файлів не лишилося


def test_wrong_key_raises_instead_of_resetting(tmp_path):
    path = tmp_path / "db.json"
    EncryptedStore("key").save(path, {"users": {"1": {}}})
    with pytest.raises(StorageError):
        EncryptedStore("other").load(path, dict)


def test_missing_or_empty_file_gives_default(tmp_path):
    store = EncryptedStore("key")
    assert store.load(tmp_path / "nope", lambda: {"x": 1}) == {"x": 1}
    (tmp_path / "empty").write_bytes(b"")
    assert store.load(tmp_path / "empty", dict) == {}
