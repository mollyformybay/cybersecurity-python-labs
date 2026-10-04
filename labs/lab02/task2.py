"""Завдання 2. Варіант 15 — аудит журналу sudo."""

import json
import logging
import re
import shlex
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

LOGGER = logging.getLogger(__name__)
DEFAULT_RULES = "chmod 777,nc,nmap,dd,/etc/shadow"

SUDO_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+"
    r"(?:\S+\s+)?sudo(?:\[\d+\])?:\s*"
    r"(?P<user>\S+)\s*:\s*"
    r"TTY=(?P<tty>[^;]+)\s*;\s*"
    r"PWD=(?P<pwd>[^;]+)\s*;\s*"
    r"USER=(?P<target_user>[^;]+)\s*;\s*"
    r"COMMAND=(?P<command>.+)$"
)


@dataclass
class SudoEntry:
    """Структура запису журналу sudo."""

    timestamp: str
    user: str
    tty: str
    pwd: str
    target_user: str
    command: str


def load_alert_commands(source):
    """Завантажити правила з файла або списку через кому."""
    path = Path(source)

    if path.is_file():
        rules = [
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
    elif (
        path.suffix.lower() == ".txt"
        or "/" in source
        and "," not in source
        or "\\" in source
        and "," not in source
    ):
        # /etc/shadow також може бути окремим правилом.
        if source == "/etc/shadow":
            rules = [source]
        else:
            raise FileNotFoundError(f"Файл правил не знайдено: {source}")
    else:
        rules = [item.strip() for item in source.split(",") if item.strip()]

    if not rules:
        raise ValueError("Список правил порожній.")

    return rules


def parse_sudo_log(path):
    """Розібрати журнал із часовими мітками ISO 8601."""
    entries = []
    malformed_lines = 0

    with path.open("r", encoding="utf-8") as file:
        for number, line in enumerate(file, start=1):
            line = line.strip()
            if not line:
                continue

            match = SUDO_PATTERN.fullmatch(line)
            if match is None:
                malformed_lines += 1
                LOGGER.warning("Рядок %d має некоректний формат.", number)
                continue

            data = {key: value.strip() for key, value in match.groupdict().items()}

            try:
                timestamp = datetime.fromisoformat(data["timestamp"])
                if timestamp.utcoffset() is None:
                    raise ValueError("Часова мітка без часового поясу.")
            except ValueError:
                malformed_lines += 1
                LOGGER.warning("Рядок %d містить некоректну дату.", number)
                continue

            entries.append(SudoEntry(**data))

    return entries, malformed_lines


def matches_rule(command, rule):
    """Перевірити правило за окремими аргументами команди."""
    try:
        tokens = shlex.split(command)
        rule_tokens = shlex.split(rule)
    except ValueError:
        return False

    if not tokens or not rule_tokens:
        return False

    executable = Path(tokens[0]).name

    # Знаходить також chmod -R 777 та chmod 0777.
    if rule == "chmod 777":
        return executable == "chmod" and any(
            token in {"777", "0777"} for token in tokens[1:]
        )

    # Назви інструментів перевіряються точно, а не як підрядки.
    if len(rule_tokens) == 1 and "/" not in rule_tokens[0]:
        return executable == rule_tokens[0]

    # Шлях на зразок /etc/shadow має бути окремим аргументом.
    if len(rule_tokens) == 1:
        return rule_tokens[0] in tokens

    normalized = [executable, *tokens[1:]]
    rule_tokens[0] = Path(rule_tokens[0]).name
    length = len(rule_tokens)

    return any(
        normalized[index : index + length] == rule_tokens
        for index in range(len(normalized) - length + 1)
    )


def analyze_sudo(sudo_log, alert_commands, out_json):
    """Виконати аудит і зберегти JSON-звіт."""
    LOGGER.info("Читання журналу: %s", sudo_log)
    rules = load_alert_commands(alert_commands)
    entries, malformed = parse_sudo_log(sudo_log)

    user_counts = Counter()
    risk_counts = Counter()
    alerts = []

    for entry in entries:
        user_counts[entry.user] += 1

        matched_rules = [rule for rule in rules if matches_rule(entry.command, rule)]
        if matched_rules:
            risk_counts[entry.user] += 1
            alerts.append(
                {
                    **asdict(entry),
                    "matched_rules": matched_rules,
                }
            )
            LOGGER.warning(
                "%s: %s — правила: %s",
                entry.user,
                entry.command,
                ", ".join(matched_rules),
            )

    report = {
        "summary": {
            "total_commands": len(entries),
            "root_executions": sum(entry.target_user == "root" for entry in entries),
            "malformed_lines": malformed,
            "high_risk_commands": len(alerts),
        },
        "top_users": [
            {
                "username": user,
                "commands": count,
                "high_risk_count": risk_counts[user],
            }
            for user, count in user_counts.most_common()
        ],
        "alerts": alerts,
    }

    print("\n=== Privileged Execution Summary ===")
    for key, value in report["summary"].items():
        print(f"{key}: {value}")

    print("\n=== Suspicious Commands ===")
    for alert in alerts:
        print(f"[ALERT] {alert['user']}: {alert['command']}")

    print("\n=== Top Sudo Users ===")
    for item in report["top_users"]:
        print(
            f"{item['username']}: {item['commands']} commands "
            f"(high risk: {item['high_risk_count']})"
        )

    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    LOGGER.info("Звіт збережено: %s", out_json)
    return report
