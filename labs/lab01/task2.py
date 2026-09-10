"""Модуль багаторівневої системи контролю доступу.

Лабораторна робота 1, Завдання 2.
"""

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

USERS = {
    "quantum_researcher": {
        "role": "quantum_security",
        "clearance": 4,
        "department": "Quantum Research",
        "active": True,
    },
    "post_quantum_dev": {
        "role": "pq_cryptographer",
        "clearance": 4,
        "department": "Post-Quantum",
        "active": True,
    },
    "network_security": {
        "role": "network_security",
        "clearance": 3,
        "department": "Network Security",
        "active": True,
    },
    "crypto_intern": {
        "role": "crypto_intern",
        "clearance": 1,
        "department": "Internship",
        "active": True,
    },
    "quantum_sim": {
        "role": "simulator",
        "clearance": 2,
        "department": "Simulation",
        "active": False,
    },
}

RESOURCES = [
    ("quantum_algorithms", 4),
    ("pq_implementations", 4),
    ("network_protocols", 3),
    ("learning_materials", 1),
    ("quantum_keys", 4),
    ("educational_content", 1),
    ("hybrid_systems", 3),
    ("quantum_computers", 4),
    ("crypto_libraries", 2),
    ("tutorials", 1),
]

SECURITY_LEVELS = (
    "Educational",
    "Research",
    "Classified Research",
    "Quantum Secure",
)

BLOCKED_USERS = {"quantum_sim", "quantum_attack", "algorithm_theft"}


def check_access(
    username: str,
    resource_name: str,
    resource_level: int,
    users: dict,
    blocked: set,
) -> tuple[str, str]:
    """Перевіряє права доступу користувача до ресурсу.

    Повертає статус ('ALLOW' або 'DENY') та причину відмови за наявності.
    """
    if username not in users:
        return "DENY", "User not found"

    if username in blocked:
        return "DENY", "User is blocked"

    user_data = users[username]
    if not user_data.get("active", False):
        return "DENY", "Account inactive"

    clearance = user_data.get("clearance", 0)
    if clearance >= resource_level:
        return "ALLOW", ""

    return "DENY", "Insufficient clearance"


def print_resources(resources: list[tuple[str, int]], levels: tuple) -> None:
    """Виводить список ресурсів із текстовим рівнем безпеки."""
    print("Список ресурсів системи:")
    print(f"{'№':<3} | {'Назва ресурсу':<24} | {'Рівень безпеки'}")
    print("-" * 55)
    for i, (name, level) in enumerate(resources, start=1):
        level_name = levels[level - 1]
        print(f"{i:<3} | {name:<24} | {level} ({level_name})")
    print()


def run_task2() -> None:
    """Виконує повний цикл перевірки системи контролю доступу."""
    print("=" * 80)
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")
    print("=" * 80)

    # 1. Виведення ресурсів із текстовими мітками
    print_resources(RESOURCES, SECURITY_LEVELS)

    # 2. Формування повного пулу користувачів для тестування (включно з неіснуючими)
    test_users = list(USERS.keys()) + [
        u for u in sorted(BLOCKED_USERS) if u not in USERS
    ]

    print("Результати перевірки доступу:")
    print("-" * 80)

    for username in test_users:
        for res_name, res_level in RESOURCES:
            status, reason = check_access(
                username=username,
                resource_name=res_name,
                resource_level=res_level,
                users=USERS,
                blocked=BLOCKED_USERS,
            )

            if status == "ALLOW":
                result_str = "ALLOW"
            else:
                result_str = f"DENY ({reason})"

            print(f"user={username:<20} resource={res_name:<20} -> {result_str}")


if __name__ == "__main__":
    run_task2()