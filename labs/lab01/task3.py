"""Модуль безпечної реєстрації, автентифікації та логування подій безпеки.

Лабораторна робота 1, Завдання 3.
"""

import csv
import hashlib
import json
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

MIN_PASSWORD_LENGTH = 9
PERSONAL_SALT = f"{VARIANT_NUMBER:05d}"

DATA_DIR = Path(__file__).resolve().parent / "data"
CSV_FILE_PATH = DATA_DIR / "users.csv"
LOG_FILE_PATH = DATA_DIR / "log.json"

USERS_TO_REGISTER = (
    ("alice_admin", "Secur3P@ssw0rd!"),
    ("bob_analyst", "CryptoMaster#99"),
    ("carol_dev", "D3vOpsPassw0rd$"),
    ("dave_sec", "CyberGuard2026!"),
    ("eve_tester", "QATestSystem#12"),
    ("frank_ops", "CloudPlatform*9"),
    ("grace_lead", "TeamLeadP@ssw1"),
    ("heidi_audit", "AuditSafety2026"),
    ("ivan_net", "NetworkRouter#1"),
    ("judy_hr", "CorpHumanRes!99"),
)


class ValidationError(Exception):
    """Виняток для помилок валідації паролів."""


def generate_hash(password: str, salt: str = "00000") -> str:
    """Генерує SHA-1 шістнадцятковий хеш конкатенації пароля та солі."""
    if password is None or salt is None or password == "" or salt == "":
        raise ValueError("Пароль та сіль не можуть бути порожніми.")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Довжина пароля ({len(password)}) менша за мінімальну "
            f"({MIN_PASSWORD_LENGTH})."
        )

    salted_password = f"{password}{salt}".encode()
    return hashlib.sha1(salted_password).hexdigest()


def log_event(func):
    """Декоратор для логування спроб входу у файл log.json."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        username = kwargs.get("username") if "username" in kwargs else (
            args[0] if args else "unknown"
        )
        try:
            result = func(*args, **kwargs)
            status = "success" if result else "failure"
        except Exception:
            status = "failure"
            raise
        finally:
            log_entry = {
                "event": "login",
                "user": username,
                "result": status if "status" in locals() else "failure",
                "timestamp": datetime.now(timezone.utc).strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "args": list(args),
                "kwargs": kwargs,
            }
            _write_log(log_entry)

        return result

    return wrapper


def _write_log(entry: dict) -> None:
    """Записує запис аудиту до log.json."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    logs = []
    if LOG_FILE_PATH.exists():
        try:
            with open(LOG_FILE_PATH, "r", encoding="utf-8") as file:
                logs = json.load(file)
                if not isinstance(logs, list):
                    logs = []
        except (json.JSONDecodeError, OSError):
            logs = []

    logs.append(entry)
    with open(LOG_FILE_PATH, "w", encoding="utf-8") as file:
        json.dump(logs, file, indent=4, ensure_ascii=False)


def create_user(username: str, password: str) -> tuple[str, str]:
    """Створює запис користувача з хешованим паролем і сіллю варіанта."""
    pwd_hash = generate_hash(password, PERSONAL_SALT)
    return username, pwd_hash


def create_users(users_list: tuple[tuple[str, str], ...]) -> None:
    """Створює каталог data та записує користувачів у users.csv."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(CSV_FILE_PATH, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["username", "password_hash"])
        for username, password in users_list:
            user, hashed = create_user(username, password)
            writer.writerow([user, hashed])


def read_users_db() -> list[dict[str, str]]:
    """Зчитує список користувачів із CSV-файлу."""
    with open(CSV_FILE_PATH, "r", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        return list(reader)


@log_event
def login(username: str, password: str) -> bool:
    """Виконує аутентифікацію користувача за базою users.csv."""
    if not username or not password:
        raise ValueError("Логін та пароль не можуть бути порожніми.")

    users_db = read_users_db()
    try:
        calculated_hash = generate_hash(password, PERSONAL_SALT)
    except ValidationError:
        return False

    for record in users_db:
        if record["username"] == username:
            return record["password_hash"] == calculated_hash
    return False


def main() -> None:
    """Головна функція для виконання Завдання 3."""
    print("=" * 80)
    print(
        f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | "
        f"Варіант: {VARIANT_NUMBER}"
    )
    print(
        f"Алгоритм: SHA-1 | Сіль: {PERSONAL_SALT} | "
        f"Мін. довжина: {MIN_PASSWORD_LENGTH}"
    )
    print("=" * 80)

    try:
        # 1. Створення бази користувачів
        create_users(USERS_TO_REGISTER)
        print("[+] Базу користувачів успішно створено та збережено в CSV.")

        # 2. Зчитування та виведення бази
        db_records = read_users_db()
        print("\nЗміст бази даних користувачів (users.csv):")
        print(f"{'№':<3} | {'Логін':<16} | {'SHA-1 Хеш (із сіллю)'}")
        print("-" * 65)
        for i, row in enumerate(db_records, start=1):
            print(f"{i:<3} | {row['username']:<16} | {row['password_hash']}")

        # 3. Тестування аутентифікації та логування подій
        print("\nТестування аутентифікації та логування подій:")
        print("-" * 65)

        test_cases = [
            ("alice_admin", "Secur3P@ssw0rd!", "Вірний пароль"),
            ("bob_analyst", "WrongPassword123", "Невірний пароль"),
            ("unknown_user", "SomeSecretPass1", "Користувач відсутній"),
            ("carol_dev", "short", "Пароль менше мінімальної довжини"),
        ]

        for user, pwd, desc in test_cases:
            res = login(username=user, password=pwd)
            status_text = "Успішно" if res else "Відмовлено"
            print(f"Спроба: {user:<14} ({desc:<30}) -> {status_text}")

        # Демонстрація перехоплення винятків
        print("\nДемонстрація обробки винятків:")
        try:
            generate_hash("short", PERSONAL_SALT)
        except ValidationError as err:
            print(f"[ValidationError перехоплено]: {err}")

        try:
            login(username="", password="")
        except ValueError as err:
            print(f"[ValueError перехоплено]: {err}")

        print("\n[+] Усі події безпеки успішно залоговано в log.json.")

    except (FileNotFoundError, PermissionError, OSError) as err:
        print(f"[File/IO Error]: Помилка роботи з файловою системою: {err}")
    except (ValidationError, ValueError) as err:
        print(f"[Validation/Value Error]: Помилка даних: {err}")


if __name__ == "__main__":
    main()