"""Перевірка читання даних і фільтрації."""

from labs.lab03.repository import (
    NotFoundError,
    get_record,
    list_categories,
    list_records,
)


def main() -> None:
    """Продемонструвати читання даних із бази."""
    print("Категорії:")
    for category in list_categories():
        print(category)

    print("\nЗапис з id=1:")
    try:
        print(get_record(1))
    except NotFoundError as error:
        print(error)

    print("\nСпроба знайти відсутній запис:")
    try:
        print(get_record(99999))
    except NotFoundError as error:
        print(error)

    print("\nЗаписи з оцінкою від 8:")
    for record in list_records(min_value=8.0):
        print(record["code"], record["value"])

    print("\nКатегорія updates зі статусом new:")
    for record in list_records(category_id=1, status="new"):
        print(record["code"])

    print("\nДва записи після пропуску перших двох:")
    for record in list_records(limit=2, offset=2):
        print(record["code"])


if __name__ == "__main__":
    main()
