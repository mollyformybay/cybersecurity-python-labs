"""Параметризовані SQL-операції та транзакції."""

from contextlib import closing
from typing import Any

from labs.lab03.database import get_connection


class NotFoundError(Exception):
    """Потрібний запис або категорію не знайдено."""


SELECT_RECORD = """
SELECT
    r.id,
    r.code,
    r.title,
    r.category_id,
    r.value,
    r.status,
    c.name AS category_name
FROM records AS r
JOIN categories AS c ON c.id = r.category_id
"""

INSERT_RECORD = """
INSERT INTO records
    (code, title, category_id, value, status)
VALUES (?, ?, ?, ?, ?)
"""


def list_categories() -> list[dict[str, Any]]:
    """Отримати всі категорії за зростанням id."""
    with closing(get_connection()) as connection:
        rows = connection.execute(
            "SELECT id, name FROM categories ORDER BY id"
        ).fetchall()

        return [dict(row) for row in rows]


def create_category(name: str) -> dict[str, Any]:
    """Створити категорію з автоматичним id."""
    with closing(get_connection()) as connection, connection:
        cursor = connection.execute(
            "INSERT INTO categories (name) VALUES (?)",
            (name,),
        )

        return {
            "id": cursor.lastrowid,
            "name": name,
        }


def delete_category(category_id: int) -> None:
    """Видалити порожню категорію."""
    with closing(get_connection()) as connection, connection:
        cursor = connection.execute(
            "DELETE FROM categories WHERE id = ?",
            (category_id,),
        )

        if cursor.rowcount == 0:
            raise NotFoundError("Категорію не знайдено")


def get_record(record_id: int) -> dict[str, Any]:
    """Отримати знахідку разом із назвою категорії."""
    with closing(get_connection()) as connection:
        row = connection.execute(
            SELECT_RECORD + " WHERE r.id = ?",
            (record_id,),
        ).fetchone()

        if row is None:
            raise NotFoundError("Запис не знайдено")

        return dict(row)


def list_records(
    category_id: int | None = None,
    status: str | None = None,
    min_value: float | None = None,
    q: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Отримати записи з фільтрами та поділом на сторінки."""
    conditions = []
    parameters = []

    if category_id is not None:
        conditions.append("r.category_id = ?")
        parameters.append(category_id)

    if status is not None:
        conditions.append("r.status = ?")
        parameters.append(status)

    if min_value is not None:
        conditions.append("r.value >= ?")
        parameters.append(min_value)

    if q is not None:
        conditions.append("instr(r.title, ?) > 0")
        parameters.append(q)

    sql = SELECT_RECORD

    if conditions:
        sql += " WHERE " + " AND ".join(conditions)

    sql += " ORDER BY r.id LIMIT ? OFFSET ?"
    parameters.extend((limit, offset))

    with closing(get_connection()) as connection:
        rows = connection.execute(sql, parameters).fetchall()

        return [dict(row) for row in rows]


def create_records(
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Додати весь пакет в одній транзакції."""
    result = []

    with closing(get_connection()) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")

        for record in records:
            category = connection.execute(
                "SELECT id FROM categories WHERE id = ?",
                (record["category_id"],),
            ).fetchone()

            if category is None:
                raise NotFoundError("Категорію не знайдено")

            cursor = connection.execute(
                INSERT_RECORD,
                (
                    record["code"],
                    record["title"],
                    record["category_id"],
                    record["value"],
                    record["status"],
                ),
            )

            row = connection.execute(
                SELECT_RECORD + " WHERE r.id = ?",
                (cursor.lastrowid,),
            ).fetchone()

            result.append(dict(row))

    return result


def create_record(record: dict[str, Any]) -> dict[str, Any]:
    """Створити одну знахідку через спільну операцію додавання."""
    return create_records([record])[0]


def replace_record(
    record_id: int,
    record: dict[str, Any],
) -> dict[str, Any]:
    """Замінити всі змінювані поля зі збереженням id."""
    with closing(get_connection()) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")

        existing = connection.execute(
            "SELECT id FROM records WHERE id = ?",
            (record_id,),
        ).fetchone()

        if existing is None:
            raise NotFoundError("Запис не знайдено")

        category = connection.execute(
            "SELECT id FROM categories WHERE id = ?",
            (record["category_id"],),
        ).fetchone()

        if category is None:
            raise NotFoundError("Категорію не знайдено")

        connection.execute(
            """
                UPDATE records
                SET code = ?, title = ?, category_id = ?,
                    value = ?, status = ?
                WHERE id = ?
                """,
            (
                record["code"],
                record["title"],
                record["category_id"],
                record["value"],
                record["status"],
                record_id,
            ),
        )

        row = connection.execute(
            SELECT_RECORD + " WHERE r.id = ?",
            (record_id,),
        ).fetchone()

        return dict(row)


def delete_record(record_id: int) -> None:
    """Видалити знахідку або повідомити про відсутній запис."""
    with closing(get_connection()) as connection, connection:
        cursor = connection.execute(
            "DELETE FROM records WHERE id = ?",
            (record_id,),
        )

        if cursor.rowcount == 0:
            raise NotFoundError("Запис не знайдено")
