"""Зашифроване JSON-сховище (Fernet), яке зберігається прямо в репозиторії."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Callable, Dict

from cryptography.fernet import Fernet, InvalidToken


class StorageError(RuntimeError):
    pass


def make_fernet(raw_key: str) -> Fernet:
    """Fernet-ключ з довільного рядка (сумісно зі старою версією бота)."""
    digest = hashlib.sha256(raw_key.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


class EncryptedStore:
    def __init__(self, raw_key: str) -> None:
        self._fernet = make_fernet(raw_key)

    def load(self, path: Path, default: Callable[[], Dict[str, Any]]) -> Dict[str, Any]:
        """Читає файл. Відсутній або порожній файл -> default().

        Якщо файл є, але не розшифровується, кидаємо помилку замість того, щоб
        мовчки почати з порожньої бази й перезаписати всіх користувачів.
        """
        if not path.exists() or path.stat().st_size == 0:
            return default()
        try:
            raw = self._fernet.decrypt(path.read_bytes())
        except InvalidToken:
            raise StorageError(
                f"Не вдалося розшифрувати {path}: ENCRYPTION_KEY не збігається з тим, "
                "яким файл було зашифровано"
            )
        try:
            return json.loads(raw.decode("utf-8"))
        except ValueError as e:
            raise StorageError(f"{path} пошкоджено: {e}")

    def save(self, path: Path, data: Dict[str, Any]) -> bool:
        """Записує файл лише якщо дані змінилися. Повертає True, якщо був запис.

        Fernet щоразу дає інший шифротекст, тому порівнюємо розшифровані дані —
        інакше кожен запуск створював би коміт без змін.
        """
        if path.exists() and path.stat().st_size > 0:
            try:
                if self.load(path, dict) == data:
                    return False
            except StorageError:
                pass

        raw = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        encrypted = self._fernet.encrypt(raw.encode("utf-8"))

        path.parent.mkdir(parents=True, exist_ok=True)
        # Тимчасовий файл у тій самій теці: os.replace атомарний лише в межах однієї ФС.
        fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(encrypted)
            os.replace(tmp, path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
        return True
