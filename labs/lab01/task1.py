"""Модуль аналізу надійності паролів користувачів.

Лабораторна робота 1, Завдання 1.
"""

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

FORBIDDEN_PASSWORDS = {
    "standard",
    "typical123",
    "normal",
    "general123",
    "common",
    "guest",
}

SPECIAL_CHARACTERS = set(string.punctuation)


def evaluate_password_strength(
    password: str,
    criteria: dict,
    forbidden: set,
    occurrence_count: int,
) -> str:
    """Оцінює рівень захищеності пароля згідно з критеріями."""
    min_len = criteria["min_length"]

    if password in forbidden or len(password) < min_len:
        return "Заборонений"

    has_digit = any(char.isdigit() for char in password)
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_special = any(char in SPECIAL_CHARACTERS for char in password)

    all_criteria_met = (
        len(password) >= min_len
        and (not criteria["require_digits"] or has_digit)
        and (not criteria["require_upper"] or has_upper)
        and (not criteria["require_special"] or has_special)
    )

    if all_criteria_met:
        is_unique = occurrence_count == 1
        if len(password) >= min_len + 4 and is_unique:
            return "Дуже сильний"
        return "Сильний"

    at_least_one = has_digit or has_upper or has_lower or has_special
    if len(password) >= min_len and at_least_one:
        return "Середній"

    if at_least_one:
        return "Слабкий"

    return "Заборонений"


def run_task1() -> None:
    """Виконує логіку першого завдання."""
    print("=" * 75)
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")
    print("=" * 75)

    working_passwords = PASSWORDS.copy()
    random_indices = [random.randint(0, len(PASSWORDS) - 1) for _ in range(3)]
    for idx in random_indices:
        working_passwords.append(PASSWORDS[idx])

    counts = {}
    for pwd in working_passwords:
        counts[pwd] = counts.get(pwd, 0) + 1

    print(
        f"{'№':<4} | {'Пароль':<24} | {'Довжина':<8} | {'Унікальний':<11} | {'Оцінка'}"
    )
    print("-" * 75)

    for i, pwd in enumerate(working_passwords, start=1):
        is_unique = "Так" if counts[pwd] == 1 else "Ні"
        strength = evaluate_password_strength(
            password=pwd,
            criteria=CRITERIA,
            forbidden=FORBIDDEN_PASSWORDS,
            occurrence_count=counts[pwd],
        )
        print(
            f"{i:<4} | {pwd:<24} | {len(pwd):<8} | {is_unique:<11} | {strength}"
        )


if __name__ == "__main__":
    run_task1()