"""CLI для локального або мережевого аналізу CVE."""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from labs.lab04.analysis import build_report, extract_record
from labs.lab04.api_client import fetch_response
from shared.student import VARIANT_NUMBER

CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")


def load_response(path: str | Path) -> Any:
    """Прочитати UTF-8 JSON-відповідь із локального файла."""
    with Path(path).open(encoding="utf-8") as stream:
        return json.load(stream)


def main(argv: list[str] | None = None) -> int:
    """Обробити аргументи, отримати дані та надрукувати один JSON-звіт."""
    parser = argparse.ArgumentParser(description="Перегляд CVE через NVD API")
    parser.add_argument("--cve", required=True, help="ідентифікатор CVE")
    parser.add_argument(
        "--input", dest="input_path", help="локальний JSON-файл відповіді NVD"
    )
    args = parser.parse_args(argv)

    if (
        isinstance(VARIANT_NUMBER, bool)
        or not isinstance(VARIANT_NUMBER, int)
        or not 1 <= VARIANT_NUMBER <= 15
    ):
        parser.error("shared.student.VARIANT_NUMBER має бути цілим числом від 1 до 15")
    if CVE_PATTERN.fullmatch(args.cve) is None:
        parser.error("--cve має відповідати формату CVE-YYYY-NNNN")

    try:
        payload = (
            load_response(args.input_path)
            if args.input_path
            else fetch_response(args.cve)
        )
        record = extract_record(payload, args.cve)
        report = build_report(record, args.cve, VARIANT_NUMBER)
    except (OSError, json.JSONDecodeError) as error:
        print(f"Помилка читання даних: {error.__class__.__name__}.", file=sys.stderr)
        return 1
    except (RuntimeError, ValueError) as error:
        print(f"Помилка обробки даних: {error}", file=sys.stderr)
        return 1

    print(json.dumps(report, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
