"""Головний модуль запуску ЛР №2: демонстрація ООП (demo) та аналіз логів (analyze)."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

from labs.lab02.task1 import Admin, AuditLog, User, UserAccount
from labs.lab02.task2 import analyze_sudo


def run_demo() -> None:
    """Демонстраційний сценарій для Завдання 1 (ООП в кібербезпеці)."""
    print("=" * 65)
    print(" ДЕМОНСТРАЦІЯ ЗАВДАННЯ 1: СИСТЕМА ОБЛІКОВИХ ЗАПИСІВ ТА АУДИТУ")
    print("=" * 65)

    print("\n[1] Створення користувача та валідація email:")
    user = User("ostap_l", "user.sec@example.com")
    user.set_password("SuperSecret2026!")
    print(f"Створено користувача: {user}")

    try:
        print("Спроба встановити некоректний email 'invalid_mail'...")
        user.email = "invalid_mail"
    except ValueError as err:
        print(f"-> Успішно перехоплено ValueError: {err}")

    print("\n[2] Клас Admin та управління правами:")
    admin = Admin("sysadmin", "admin.audit@corp.ua", permissions=["read_logs"])
    admin.set_password("AdminRootKey999")
    print(f"Адміністратор: {admin}")
    print(f"Чи є дозвіл 'manage_users'?: {admin.has_permission('manage_users')}")
    print("Надаємо дозвіл 'manage_users'...")
    admin.grant_permission("manage_users")
    print(f"Після grant_permission: {admin}")

    print("\n[3] Тестування автентифікації та UserAccount:")
    shared_audit = AuditLog()
    account = UserAccount(user, audit_log=shared_audit)

    print("Спроба входу з хибним паролем...")
    res_fail = account.login("ostap_l", "WrongPassword", ip="192.168.1.50")
    print(
        f"-> Результат входу: {res_fail} | Сесія активна: {account.is_authenticated()}"
    )

    print("Спроба входу з вірним паролем...")
    res_ok = account.login("ostap_l", "SuperSecret2026!", ip="192.168.1.50")
    print(f"-> Результат входу: {res_ok} | Сесія активна: {account.is_authenticated()}")

    print("\n[4] Доступ через спеціальні методи __getitem__:")
    print(f"account['user'] : {account['user']}")
    if account["session"]:
        print(f"account['session'].ip : {account['session'].ip}")

    try:
        _ = account["password"]
    except KeyError as err:
        print(f"-> Захист конфіденційних полів спрацював: {err}")

    print("\n[5] Перевірка таймауту сесії (імітація завершення часу):")
    if account.session:
        account.session.last_activity = datetime(
            2020, 1, 1, 0, 0, 0, tzinfo=timezone.utc
        )
    print(f"Чи активна сесія після 900+ секунд?: {account.is_authenticated()}")

    print("\n[6] Завершення сесії та AuditLog:")
    account.login("ostap_l", "SuperSecret2026!", ip="192.168.1.50")
    account.logout()

    print("\n--- Записи AuditLog ---")
    for log in shared_audit.show_all():
        ts = log.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
        print(f"[{ts}] Користувач: {log.username:<10} | Подія: {log.action}")

    print("\n[+] Демонстрація Завдання 1 завершена успішно.")


def main() -> None:
    """Головний парсер аргументів CLI."""
    parser = argparse.ArgumentParser(
        description="ЛР №2: Консольні утиліти кібербезпеки (Варіант 15)"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Підкоманда demo
    subparsers.add_parser("demo", help="Запустити демонстрацію Завдання 1 (ООП)")

    # Підкоманда analyze (Завдання 2)
    analyze_parser = subparsers.add_parser(
        "analyze", help="Запустити аудит привілейованих команд (sudo.log)"
    )
    analyze_parser.add_argument(
        "--sudo-log",
        type=Path,
        default=Path("labs/lab02/data/data_v15/sudo.log"),
        help="Шлях до файлу sudo.log",
    )
    analyze_parser.add_argument(
        "--alert-commands",
        type=str,
        default="labs/lab02/data/data_v15/alert_commands.txt",
        help="Шлях до alert_commands.txt або команди через кому",
    )
    analyze_parser.add_argument(
        "--out-json",
        type=Path,
        default=Path("labs/lab02/data/sudo_audit_report.json"),
        help="Шлях для збереження JSON-звіту",
    )
    analyze_parser.add_argument(
        "--log-level",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Рівень логування",
    )

    args = parser.parse_args()

    if args.command == "demo":
        run_demo()
    elif args.command == "analyze":
        analyze_sudo(
            sudo_log=args.sudo_log,
            alert_commands=args.alert_commands,
            out_json=args.out_json,
            log_level=args.log_level,
        )


if __name__ == "__main__":
    main()
