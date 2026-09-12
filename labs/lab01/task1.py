"""Аналізатор надійності паролів (Лабораторна 1, Завдання 1)."""

import random
import string

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

PASSWORDS = [
    "IoT@S3curity",
    "standard",
    "Blockchain@Pr0tect",
    "typical123",
    "AI@Cybersec",
    "normal",
    "Quantum@Crypt0",
    "general123",
    "Edge@S3curity",
    "common",
]

CRITERIA = {
    "min_length": 8,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

FORBIDDEN = {
    "standard",
    "typical123",
    "normal",
    "general123",
    "common",
    "guest",
}


def evaluate_password_strength(
    pwd: str, criteria: dict, forbidden: set, count: int
) -> str:
    """Оцінює рівень захищеності пароля."""
    min_len = criteria["min_length"]
    if pwd in forbidden or len(pwd) < min_len:
        return "Заборонений"

    has_digit = any(c.isdigit() for c in pwd)
    has_upper = any(c.isupper() for c in pwd)
    has_special = any(c in string.punctuation for c in pwd)

    all_req = has_digit and has_upper and has_special
    if all_req:
        return "Дуже сильний" if len(pwd) >= min_len + 4 and count == 1 else "Сильний"

    has_lower = any(c.islower() for c in pwd)
    has_any = has_digit or has_upper or has_special or has_lower
    return "Середній" if len(pwd) >= min_len and has_any else "Слабкий"


def run_task1() -> None:
    """Запуск аналізу паролів."""
    print("=" * 75)
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")
    print("=" * 75)

    working_pwds = PASSWORDS + [random.choice(PASSWORDS) for _ in range(3)]
    counts = {p: working_pwds.count(p) for p in working_pwds}

    print(f"{'№':<4} | {'Пароль':<24} | {'Довжина':<8} | {'Унікальний':<11} | Оцінка")
    print("-" * 75)

    for i, pwd in enumerate(working_pwds, start=1):
        unique = "Так" if counts[pwd] == 1 else "Ні"
        res = evaluate_password_strength(pwd, CRITERIA, FORBIDDEN, counts[pwd])
        print(f"{i:<4} | {pwd:<24} | {len(pwd):<8} | {unique:<11} | {res}")


if __name__ == "__main__":
    run_task1()