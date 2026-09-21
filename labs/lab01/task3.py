"""Хешування, CSV та аудит логування (Лабораторна 1, Завдання 3)."""

import csv
import hashlib
import json
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

MIN_PASSWORD_LENGTH = 9
SALT = f"{VARIANT_NUMBER:05d}"
DATA_DIR = Path(__file__).resolve().parent / "data"
CSV_FILE = DATA_DIR / "users.csv"
LOG_FILE = DATA_DIR / "log.json"

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
    """Помилка валідації пароля."""


def generate_hash(pwd: str, salt: str = "00000") -> str:
    """Генерує SHA-1 хеш пароля із сіллю."""
    if not pwd or not salt:
        raise ValueError("Пароль та сіль не можуть бути порожніми.")
    if len(pwd) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Довжина ({len(pwd)}) менша за мінімальну ({MIN_PASSWORD_LENGTH})."
        )
    return hashlib.sha1(f"{pwd}{salt}".encode()).hexdigest()


def log_event(func):
    """Декоратор аудиту спроб автентифікації."""

    @wraps(func)
    def wrapper(user: str, pwd: str, *args, **kwargs):
        status = "failure"
        try:
            res = func(user, pwd, *args, **kwargs)
            status = "success" if res else "failure"
            return res
        finally:
            entry = {
                "event": "login",
                "user": user,
                "result": status,
                "timestamp": datetime.now(timezone.utc).strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
            }
            try:
                DATA_DIR.mkdir(parents=True, exist_ok=True)
                logs = []
                if LOG_FILE.exists():
                    try:
                        logs = json.loads(LOG_FILE.read_text(encoding="utf-8"))
                    except (json.JSONDecodeError, OSError):
                        logs = []
                logs.append(entry)
                LOG_FILE.write_text(
                    json.dumps(logs, indent=4, ensure_ascii=False),
                    encoding="utf-8",
                )
            except (FileNotFoundError, PermissionError, OSError) as err:
                print(f"[Помилка запису логів]: {err}")

    return wrapper


def create_users(users_list: tuple) -> None:
    """Створює базу users.csv з індивідуальною обробкою винятків."""
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        with open(CSV_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["username", "password_hash"])
            for u, p in users_list:
                writer.writerow([u, generate_hash(p, SALT)])
    except (FileNotFoundError, PermissionError, OSError) as err:
        print(f"[create_users] Помилка роботи з файлом: {err}")
    except (ValidationError, ValueError) as err:
        print(f"[create_users] Помилка валідації даних: {err}")


def read_users_db() -> list[dict[str, str]]:
    """Зчитує CSV-базу користувачів з автономною обробкою файлових винятків."""
    try:
        with open(CSV_FILE, "r", encoding="utf-8") as f:
            return list(csv.DictReader(f))
    except (FileNotFoundError, PermissionError, OSError) as err:
        print(f"[read_users_db] Помилка зчитування бази: {err}")
        return []


@log_event
def login(username: str, password: str) -> bool:
    """Перевіряє автентифікацію користувача."""
    if not username or not password:
        raise ValueError("Логін та пароль не можуть бути порожніми.")

    try:
        pwd_hash = generate_hash(password, SALT)
    except ValidationError:
        return False

    users_db = read_users_db()
    return any(
        r.get("username") == username and r.get("password_hash") == pwd_hash
        for r in users_db
    )


def main() -> None:
    """Головний цикл Завдання 3."""
    print("=" * 80)
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")
    print(f"SHA-1 | Сіль: {SALT} | Мін. довжина: {MIN_PASSWORD_LENGTH}")
    print("=" * 80)

    create_users(USERS_TO_REGISTER)
    db = read_users_db()
    print(f"[+] Створено записів у CSV: {len(db)}")

    test_cases = [
        ("alice_admin", "Secur3P@ssw0rd!", "Вірний пароль"),
        ("bob_analyst", "WrongPassword123", "Невірний пароль"),
        ("unknown_user", "SomeSecretPass1", "Відсутній юзер"),
        ("carol_dev", "short", "Короткий пароль"),
    ]
    for user, pwd, desc in test_cases:
        res = "Успішно" if login(user, pwd) else "Відмовлено"
        print(f"Спроба: {user:<14} ({desc:<22}) -> {res}")

    # Демонстрація генерації та перехоплення помилок валідації/входу
    print("\nДемонстрація валідації винятків:")
    try:
        generate_hash("short", SALT)
    except ValidationError as e:
        print(f"[ValidationError перехоплено]: {e}")

    try:
        login("", "")
    except ValueError as e:
        print(f"[ValueError перехоплено]: {e}")


if __name__ == "__main__":
    main()