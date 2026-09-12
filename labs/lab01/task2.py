"""Система контролю доступу (Лабораторна 1, Завдання 2)."""

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

USERS = {
    "quantum_researcher": {"clearance": 4, "active": True},
    "post_quantum_dev": {"clearance": 4, "active": True},
    "network_security": {"clearance": 3, "active": True},
    "crypto_intern": {"clearance": 1, "active": True},
    "quantum_sim": {"clearance": 2, "active": False},
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

SECURITY_LEVELS = ("Educational", "Research", "Classified Research", "Quantum Secure")
BLOCKED_USERS = {"quantum_sim", "quantum_attack", "algorithm_theft"}


def check_access(user: str, res_lvl: int) -> tuple[str, str]:
    """Перевіряє доступ користувача до ресурсу."""
    if user not in USERS:
        return "DENY", "User not found"
    if user in BLOCKED_USERS:
        return "DENY", "User is blocked"
    if not USERS[user]["active"]:
        return "DENY", "Account inactive"
    if USERS[user]["clearance"] >= res_lvl:
        return "ALLOW", ""
    return "DENY", "Insufficient clearance"


def run_task2() -> None:
    """Запуск перевірки системи доступу."""
    print("=" * 80)
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")
    print("=" * 80)

    print("Список ресурсів:")
    for i, (name, lvl) in enumerate(RESOURCES, start=1):
        print(f"{i:<3} | {name:<24} | {lvl} ({SECURITY_LEVELS[lvl - 1]})")

    print("\nРезультати перевірки доступу:")
    print("-" * 80)

    all_users = list(USERS.keys()) + [u for u in sorted(BLOCKED_USERS) if u not in USERS]
    for user in all_users:
        for res_name, res_lvl in RESOURCES:
            status, reason = check_access(user, res_lvl)
            msg = status if status == "ALLOW" else f"{status} ({reason})"
            print(f"user={user:<20} resource={res_name:<20} -> {msg}")


if __name__ == "__main__":
    run_task2()