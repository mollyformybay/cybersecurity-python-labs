"""Запуск демонстрації ООП та аналізу журналу sudo."""

import argparse
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

from labs.lab02.task1 import (
    SESSION_TIMEOUT_SEC,
    Admin,
    AuditLog,
    User,
    UserAccount,
)
from labs.lab02.task2 import analyze_sudo

LOGGER = logging.getLogger(__name__)


def run_demo():
    """Продемонструвати роботу класів першого завдання."""
    user = User("ostap", "ostap_ua@example.com")
    user.set_password("SafePassword2026!")

    audit = AuditLog()
    account = UserAccount(user, audit_log=audit)

    print("Користувач:", user)
    print(
        "Успішний вхід:",
        account.login("ostap", "SafePassword2026!", "192.0.2.10"),
    )
    print("Сесія активна:", account.is_authenticated())

    print(
        "Невдалий вхід:",
        account.login("ostap", "wrong_password", "192.0.2.10"),
    )

    print("\nПеревірка email:")
    try:
        user.email = "invalid_email"
    except ValueError as error:
        print("Помилка:", error)

    user.email = "ostap_new@example.com"
    print("Новий email:", user.email)

    print("\nПрава адміністратора:")
    admin = Admin("admin", "admin_ua@example.com")
    admin.grant_permission("read_logs")
    admin.grant_permission("manage_users")
    print(admin)
    print("Має manage_users:", admin.has_permission("manage_users"))

    admin.revoke_permission("manage_users")
    print("Після відкликання:", admin.has_permission("manage_users"))

    print("\nДоступ через ключі:")
    print(account["user"])
    account["user"] = user

    try:
        account["session"] = "incorrect_type"
    except TypeError as error:
        print("Помилка типу:", error)

    try:
        print(account["password_hash"])
    except KeyError as error:
        print("Захист приватних даних:", error)

    print("\nПеревірка таймауту:")
    if account.session is not None:
        account.session.last_activity = datetime.now(timezone.utc) - timedelta(
            seconds=SESSION_TIMEOUT_SEC + 1
        )

    print("Сесія активна:", account.is_authenticated())

    account.logout()
    print("Після виходу:", account.is_authenticated())

    print("\nЖурнал аудиту:")
    audit.show_all()


def build_parser():
    """Налаштувати аргументи командного рядка."""
    parser = argparse.ArgumentParser(description="Лабораторна робота №2. Варіант 15.")
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("demo", help="Демонстрація першого завдання")
    analyze = commands.add_parser("analyze", help="Аналіз журналу sudo")

    analyze.add_argument(
        "--sudo-log",
        type=Path,
        default=Path("labs/lab02/data/data_v15/sudo.log"),
    )
    analyze.add_argument(
        "--alert-commands",
        default="labs/lab02/data/data_v15/alert_commands.txt",
        help="Файл правил або список через кому",
    )
    analyze.add_argument(
        "--out-json",
        type=Path,
        default=Path("labs/lab02/data/sudo_audit_report.json"),
    )
    analyze.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
    )
    return parser


def main():
    """Запустити вибрану підкоманду."""
    args = build_parser().parse_args()

    if args.command == "demo":
        run_demo()
        return 0

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="[%(levelname)s] %(message)s",
    )

    try:
        analyze_sudo(args.sudo_log, args.alert_commands, args.out_json)
    except (OSError, ValueError) as error:
        LOGGER.error("Не вдалося виконати аналіз: %s", error)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
