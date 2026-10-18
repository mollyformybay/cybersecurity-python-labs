"""Перевірка JSON і початкове заповнення бази."""

import sqlite3
from contextlib import closing

from pydantic import ValidationError

from labs.lab03.database import (
    BASE_DIR,
    get_connection,
    initialize_database,
)
from labs.lab03.repository import INSERT_RECORD
from labs.lab03.schemas import SeedData


def seed_database() -> bool:
    """Заповнити порожню базу в одній транзакції."""
    initialize_database()

    with closing(get_connection()) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")

        category_count = connection.execute(
            "SELECT COUNT(*) FROM categories"
        ).fetchone()[0]

        record_count = connection.execute("SELECT COUNT(*) FROM records").fetchone()[0]

        if category_count > 0 or record_count > 0:
            return False

        json_text = (BASE_DIR / "data" / "seed.json").read_text(encoding="utf-8")
        data = SeedData.model_validate_json(json_text)

        connection.executemany(
            "INSERT INTO categories (id, name) VALUES (?, ?)",
            [(category.id, category.name) for category in data.categories],
        )

        connection.executemany(
            INSERT_RECORD,
            [
                (
                    record.code,
                    record.title,
                    record.category_id,
                    record.value,
                    record.status,
                )
                for record in data.records
            ],
        )

    return True


def main() -> int:
    """Запустити заповнення та повідомити результат."""
    try:
        created = seed_database()
    except (OSError, ValidationError, sqlite3.Error):
        print(
            "Не вдалося заповнити базу. "
            "Перевірте seed.json і доступ до файлів. "
            "Додавання даних скасовано."
        )
        return 1

    if created:
        print("Додано 3 категорії та 8 записів.")
    else:
        print("База непорожня. Дані не змінено.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
