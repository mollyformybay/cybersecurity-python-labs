"""Завдання 1. Користувачі, сесії та журнал аудиту."""

import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

PASSWORD_ITERATIONS = 100_000
SESSION_TIMEOUT_SEC = 900

EMAIL_PATTERN = re.compile(
    r"[A-Za-z][A-Za-z0-9_]{2,63}"
    r"@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+"
)


class User:
    """Користувач із перевіркою email та хешуванням пароля."""

    def __init__(self, username, email, role="user", active=True):
        if not isinstance(username, str) or not username.strip():
            raise ValueError("Ім'я користувача не може бути порожнім.")

        self.username = username
        self.email = email
        self.role = role
        self.active = active
        self.__password_hash = b""
        self.__password_salt = b""

    @property
    def email(self):
        return self._email

    @email.setter
    def email(self, value):
        if not isinstance(value, str) or not EMAIL_PATTERN.fullmatch(value):
            raise ValueError("Некоректний формат email.")
        self._email = value

    def set_password(self, password):
        if not isinstance(password, str) or not password:
            raise ValueError("Пароль має бути непорожнім рядком.")

        self.__password_salt = os.urandom(16)
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PASSWORD_ITERATIONS,
        )

    def check_password(self, password):
        if not isinstance(password, str) or not self.__password_hash:
            return False

        candidate = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PASSWORD_ITERATIONS,
        )
        return hmac.compare_digest(candidate, self.__password_hash)

    def deactivate(self):
        self.active = False

    def __str__(self):
        return (
            f"User(username={self.username}, email={self.email}, "
            f"role={self.role}, active={self.active})"
        )


class Admin(User):
    """Адміністратор із набором дозволів."""

    def __init__(self, username, email, permissions=None, active=True):
        super().__init__(username, email, role="admin", active=active)
        self.permissions = set(permissions) if permissions is not None else set()

    def grant_permission(self, permission):
        if not isinstance(permission, str) or not permission.strip():
            raise ValueError("Дозвіл має бути непорожнім рядком.")
        self.permissions.add(permission)

    def revoke_permission(self, permission):
        self.permissions.discard(permission)

    def has_permission(self, permission):
        return permission in self.permissions

    def __str__(self):
        return f"{super().__str__()}, permissions={sorted(self.permissions)}"


class Session:
    """Сесія з контролем часу останньої активності."""

    def __init__(self, ip):
        self.ip = ip
        self.login_time = datetime.now(timezone.utc)
        self.last_activity = self.login_time

    def touch(self):
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec):
        if timeout_sec <= 0:
            raise ValueError("Таймаут має бути додатним.")

        elapsed = datetime.now(timezone.utc) - self.last_activity
        return timedelta(0) <= elapsed < timedelta(seconds=timeout_sec)


@dataclass(frozen=True)
class LogEntry:
    """Окремий запис журналу аудиту."""

    timestamp: datetime
    username: str
    action: str


class AuditLog:
    """Журнал подій без збереження паролів."""

    def __init__(self):
        self.logs = []

    def add_log(self, username, action):
        self.logs.append(LogEntry(datetime.now(timezone.utc), username, action))

    def show_all(self):
        for entry in self.logs:
            timestamp = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
            print(f"[{timestamp}] {entry.username}: {entry.action}")


class UserAccount:
    """Композиція користувача, сесії та журналу аудиту."""

    def __init__(self, user, session=None, audit_log=None):
        self["user"] = user
        self["session"] = session
        self["audit_log"] = audit_log if audit_log is not None else AuditLog()

    def login(self, username, password, ip):
        if (
            username != self.user.username
            or not self.user.active
            or not self.user.check_password(password)
        ):
            self.audit_log.add_log(username, "login_failure")
            return False

        self.session = Session(ip)
        self.session.touch()
        self.audit_log.add_log(username, "login_success")
        return True

    def is_authenticated(self):
        return self.session is not None and self.session.is_active(SESSION_TIMEOUT_SEC)

    def logout(self):
        if self.session is not None:
            self.session = None
            self.audit_log.add_log(self.user.username, "logout")

    def __getitem__(self, key):
        if key not in {"user", "session", "audit_log"}:
            raise KeyError(f"Невідомий або заборонений ключ: {key}")
        return getattr(self, key)

    def __setitem__(self, key, value):
        allowed_types = {
            "user": User,
            "session": Session,
            "audit_log": AuditLog,
        }

        if key not in allowed_types:
            raise KeyError(f"Невідомий або заборонений ключ: {key}")

        if key == "session" and value is None:
            self.session = None
            return

        if not isinstance(value, allowed_types[key]):
            raise TypeError(f"Неправильний тип значення для {key}.")

        setattr(self, key, value)
