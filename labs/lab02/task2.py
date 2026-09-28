"""Варіант 15: Аудитор логів використання привілейованих команд (Sudo / Privileged Access)."""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

# Регулярний вираз підтримує ISO 8601 (2026-09-27T08:10:00+03:00) та syslog (Sep 27 08:10:00)
SUDO_LOG_REGEX = re.compile(
    r"^(?P<timestamp>\S+)\s+"
    r"(?:\S+\s+)?"  # hostname
    r"sudo:\s+"
    r"(?P<user>\S+)\s*:\s*"
    r"TTY=(?P<tty>[^;\s]+)\s*;\s*"
    r"PWD=(?P<pwd>[^;\s]+)\s*;\s*"
    r"USER=(?P<target_user>[^;\s]+)\s*;\s*"
    r"COMMAND=(?P<command>.+)$"
)


@dataclass
class SudoEntry:
    """Структура розібраного рядка журналу sudo."""

    timestamp: str
    user: str
    tty: str
    pwd: str
    target_user: str
    command: str


@dataclass
class HighRiskAlert:
    """Структура виявленої підозрілої команди."""

    timestamp: str
    user: str
    target_user: str
    tty: str
    pwd: str
    command: str
    matched_rule: str


def load_alert_commands(alert_source: str) -> list[str]:
    """Завантажити шаблони підозрілих команд із файлу або списку."""
    path = Path(alert_source)
    if path.is_file():
        with path.open("r", encoding="utf-8") as f:
            return [
                line.strip() for line in f if line.strip() and not line.startswith("#")
            ]
    return [item.strip() for item in alert_source.split(",") if item.strip()]


def parse_sudo_log(log_path: Path) -> tuple[list[SudoEntry], int]:
    """Зчитати та розібрати файл логу sudo."""
    entries: list[SudoEntry] = []
    malformed_lines = 0

    with log_path.open("r", encoding="utf-8", errors="replace") as f:
        for line_num, line in enumerate(f, start=1):
            line_clean = line.strip()
            if not line_clean:
                continue
            match = SUDO_LOG_REGEX.search(line_clean)
            if match:
                data = match.groupdict()
                entries.append(
                    SudoEntry(
                        timestamp=data["timestamp"],
                        user=data["user"],
                        tty=data["tty"],
                        pwd=data["pwd"],
                        target_user=data["target_user"],
                        command=data["command"].strip(),
                    )
                )
            else:
                malformed_lines += 1
                logger.debug("Рядок %d не розпізнано: %s", line_num, line_clean)

    return entries, malformed_lines


def run_audit(log_path: Path, alert_rules: list[str]) -> dict:
    """Виконати аудит команд та виявити ризиковані запуски."""
    entries, malformed = parse_sudo_log(log_path)
    total_commands = len(entries)
    root_executions = sum(1 for e in entries if e.target_user == "root")

    alerts: list[HighRiskAlert] = []
    user_command_counter: Counter[str] = Counter()
    user_risk_counter: Counter[str] = Counter()

    for entry in entries:
        user_command_counter[entry.user] += 1
        cmd = entry.command

        matched_rule = None
        for rule in alert_rules:
            if rule in cmd or re.search(re.escape(rule), cmd, re.IGNORECASE):
                matched_rule = rule
                break

        if matched_rule:
            user_risk_counter[entry.user] += 1
            alerts.append(
                HighRiskAlert(
                    timestamp=entry.timestamp,
                    user=entry.user,
                    target_user=entry.target_user,
                    tty=entry.tty,
                    pwd=entry.pwd,
                    command=entry.command,
                    matched_rule=matched_rule,
                )
            )

    return {
        "total_commands": total_commands,
        "root_executions": root_executions,
        "malformed_lines": malformed,
        "user_command_counts": user_command_counter,
        "user_risk_counts": user_risk_counter,
        "alerts": alerts,
    }


def analyze_sudo(
    sudo_log: Path,
    alert_commands: str,
    out_json: Path | None = None,
    log_level: str = "INFO",
) -> None:
    """Головна логіка виконання аудиту та генерації звіту."""
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format="[%(levelname)s] %(message)s",
    )

    if not sudo_log.exists():
        logger.error("Файл журналу %s не знайдено!", sudo_log)
        sys.exit(1)

    logger.info("Parsing sudo usage logs from %s...", sudo_log)
    rules = load_alert_commands(alert_commands)
    results = run_audit(sudo_log, rules)

    logger.info(
        "Processed %s privileged execution entries.", f"{results['total_commands']:,}"
    )

    print("\n=== Privileged Execution Summary ===")
    print(f"Total Sudo Commands: {results['total_commands']:,}")
    print(f"Root Executions    : {results['root_executions']:,}")

    print("\n=== Suspicious / High-Risk Command Executions ===")
    for alert in results["alerts"]:
        print(
            f"[ALERT] User '{alert.user}' executed: 'sudo {alert.command}' on TTY={alert.tty}"
        )
        logger.warning(
            "User '%s' executed suspicious command: %s", alert.user, alert.command
        )

    print("\n=== Top Sudo Users ===")
    user_counts: Counter[str] = results["user_command_counts"]
    risk_counts: Counter[str] = results["user_risk_counts"]

    for idx, (username, count) in enumerate(user_counts.most_common(5), start=1):
        risks = risk_counts.get(username, 0)
        risk_suffix = f" (High risk commands: {risks})" if risks > 0 else ""
        print(f"{idx}. {username:<10}: {count} commands{risk_suffix}")

    if out_json:
        report_data = {
            "summary": {
                "total_commands": results["total_commands"],
                "root_executions": results["root_executions"],
                "malformed_lines": results["malformed_lines"],
            },
            "top_users": [
                {"username": u, "commands": c, "high_risk_count": risk_counts.get(u, 0)}
                for u, c in user_counts.most_common()
            ],
            "alerts": [asdict(a) for a in results["alerts"]],
        }
        out_json.parent.mkdir(parents=True, exist_ok=True)
        with out_json.open("w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4, ensure_ascii=False)
        logger.info("Privileged command audit saved to %s", out_json)


def build_parser() -> argparse.ArgumentParser:
    """Створення парсера CLI-аргументів."""
    parser = argparse.ArgumentParser(
        description="Аудитор логів використання привілейованих команд (sudo)."
    )
    parser.add_argument(
        "--sudo-log", type=Path, required=True, help="Шлях до файлу sudo.log"
    )
    parser.add_argument(
        "--alert-commands",
        type=str,
        default="chmod 777,nc,nmap,dd,/etc/shadow",
        help="Шлях до alert_commands.txt або перелік правил через кому",
    )
    parser.add_argument(
        "--out-json",
        type=Path,
        default=Path("labs/lab02/data/sudo_audit_report.json"),
        help="Шлях для збереження JSON-звіту",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Рівень деталізації логів",
    )
    return parser


def main() -> None:
    """Точка входу для прямого запуску модуля task2."""
    parser = build_parser()
    args = parser.parse_args()
    analyze_sudo(
        sudo_log=args.sudo_log,
        alert_commands=args.alert_commands,
        out_json=args.out_json,
        log_level=args.log_level,
    )


if __name__ == "__main__":
    main()
