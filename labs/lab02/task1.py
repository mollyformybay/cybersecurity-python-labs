"""Модель користувача й облікового запису (ООП в кібербезпеці)."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

PBKDF2_ITERATIONS = 100_000
SALT_SIZE = 16
SESSION_TIMEOUT_SEC = 900

EMAIL_REGEX = re.compile(r"^[a-zA-Z][a-zA-Z0-9._-]{2,63}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


class User:
    """Клас базового користувача системи."""

    def __init__(
        self,
        username: str,
        email: str,
        role: str = "user",
        active: bool = True,
    ) -> None:
        self.username = username
        self.role = role
        self.active = active
        self._email = ""
        self.email = email
        self.__password_salt = os.urandom(SALT_SIZE)
        self.__password_hash = b""

    @property
    def email(self) -> str:
        """Отримати email адресу."""
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        """Встановити email адресу з валідацією формату."""
        if not isinstance(value, str) or not EMAIL_REGEX.match(value):
            raise ValueError(f"Некоректний формат email адреси: {value}")
        self._email = value

    def set_password(self, password: str) -> None:
        """Встановити пароль із використанням pbkdf2_hmac та випадкової солі."""
        if not password:
            raise ValueError("Пароль не може бути порожнім.")
        self.__password_salt = os.urandom(SALT_SIZE)
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PBKDF2_ITERATIONS,
        )

    def check_password(self, password: str) -> bool:
        """Перевірити пароль методом constant-time comparison."""
        if not self.__password_hash or not password:
            return False
        computed_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PBKDF2_ITERATIONS,
        )
        return hmac.compare_digest(self.__password_hash, computed_hash)

    def deactivate(self) -> None:
        """Деактивувати обліковий запис."""
        self.active = False

    def __str__(self) -> str:
        status = "Active" if self.active else "Inactive"
        return f"User({self.username}, role={self.role}, email={self.email}, status={status})"


class Admin(User):
    """Клас адміністратора системи (успадковує User)."""

    def __init__(
        self,
        username: str,
        email: str,
        permissions: list[str] | set[str] | None = None,
        active: bool = True,
    ) -> None:
        super().__init__(username=username, email=email, role="admin", active=active)
        self.permissions: set[str] = (
            set(permissions) if permissions is not None else set()
        )

    def grant_permission(self, permission: str) -> None:
        """Надати права адміністратору."""
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        """Відкликати права."""
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        """Перевірити наявність права."""
        return permission in self.permissions

    def __str__(self) -> str:
        base_str = super().__str__()
        sorted_perms = sorted(self.permissions)
        perms_str = ", ".join(sorted_perms) if sorted_perms else "None"
        return f"{base_str} [Permissions: {perms_str}]"


class Session:
    """Клас сеансу користувача."""

    def __init__(self, ip: str) -> None:
        self.ip = ip
        now = datetime.now(timezone.utc)
        self.login_time = now
        self.last_activity = now

    def touch(self) -> None:
        """Оновити час останньої активності."""
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int = SESSION_TIMEOUT_SEC) -> bool:
        """Перевірити активність сесії за таймаутом."""
        if timeout_sec <= 0:
            raise ValueError("timeout_sec повинен бути додатним числом.")
        now = datetime.now(timezone.utc)
        return (now - self.last_activity).total_seconds() < timeout_sec


@dataclass(frozen=True)
class LogEntry:
    """Запис аудиту як незмінний dataclass."""

    timestamp: datetime
    username: str
    action: str


class AuditLog:
    """Клас журналу аудиту подій."""

    def __init__(self) -> None:
        self.logs: list[LogEntry] = []

    def add_log(self, username: str, action: str) -> None:
        """Додати новий запис аудиту з UTC-часом."""
        entry = LogEntry(
            timestamp=datetime.now(timezone.utc),
            username=username,
            action=action,
        )
        self.logs.append(entry)

    def show_all(self) -> list[LogEntry]:
        """Отримати всі записи."""
        return list(self.logs)


class UserAccount:
    """Композиція User, Session та AuditLog."""

    def __init__(
        self,
        user: User,
        audit_log: AuditLog | None = None,
    ) -> None:
        self.user = user
        self.session: Session | None = None
        self.audit_log = audit_log if audit_log is not None else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        """Виконати автентифікацію користувача."""
        if not self.user.active or self.user.username != username:
            self.audit_log.add_log(username, "login_failure")
            return False

        if self.user.check_password(password):
            self.session = Session(ip)
            self.session.touch()
            self.audit_log.add_log(username, "login_success")
            return True

        self.audit_log.add_log(username, "login_failure")
        return False

    def is_authenticated(self) -> bool:
        """Перевірити статус сесії без її штучного продовження."""
        if self.session is None:
            return False
        if self.session.is_active(SESSION_TIMEOUT_SEC):
            return True
        self.session = None
        return False

    def logout(self) -> None:
        """Завершити сесію та зафіксувати подію."""
        if self.session is not None:
            self.session = None
            self.audit_log.add_log(self.user.username, "logout")

    def __getitem__(self, key: str) -> Any:
        """Спеціальний метод доступу до атрибутів."""
        if key == "user":
            return self.user
        if key == "session":
            return self.session
        if key == "audit_log":
            return self.audit_log
        if key in (
            "password",
            "password_hash",
            "password_salt",
            "_password_hash",
            "__password_hash",
        ):
            raise KeyError("Доступ до хешу чи солі пароля заборонено.")
        raise KeyError(f"Невідомий ключ: {key}")

    def __setitem__(self, key: str, value: Any) -> None:
        """Спеціальний метод встановлення атрибутів з валідацією типів."""
        if key == "user":
            if not isinstance(value, User):
                raise TypeError("Значення для 'user' має бути екземпляром User.")
            self.user = value
        elif key == "session":
            if value is not None and not isinstance(value, Session):
                raise TypeError(
                    "Значення для 'session' має бути екземпляром Session або None."
                )
            self.session = value
        elif key == "audit_log":
            if not isinstance(value, AuditLog):
                raise TypeError(
                    "Значення для 'audit_log' має бути екземпляром AuditLog."
                )
            self.audit_log = value
        else:
            raise KeyError(f"Заборонено або невідомо для запису: {key}")
