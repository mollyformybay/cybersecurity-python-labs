"""API реєстру ризиків налаштування робочих станцій."""

import logging
import sqlite3
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from labs.lab03.config import THRESHOLD, UNIT
from labs.lab03.database import initialize_database
from labs.lab03.repository import NotFoundError
from labs.lab03.routers import categories, records
from labs.lab03.schemas import StudentRead
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

LOGGER = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Створити відсутні таблиці під час запуску."""
    initialize_database()
    yield


app = FastAPI(
    title="Реєстр ризиків налаштування робочих станцій",
    description=(
        "Лабораторна робота №3. Варіант 15. "
        "Категорії: updates, permissions, protection. "
        f"Оцінка ризику від 0 до 10 {UNIT}. "
        f"Поріг ризику: {THRESHOLD}."
    ),
    lifespan=lifespan,
)

app.include_router(categories.router)
app.include_router(records.router)


@app.exception_handler(NotFoundError)
async def not_found_handler(
    request: Request,
    error: NotFoundError,
) -> JSONResponse:
    """Перетворити відсутній ресурс на HTTP 404."""
    return JSONResponse(
        status_code=404,
        content={"detail": str(error)},
    )


@app.exception_handler(sqlite3.IntegrityError)
async def integrity_handler(
    request: Request,
    error: sqlite3.IntegrityError,
) -> JSONResponse:
    """Повернути конфлікт без технічних подробиць."""
    LOGGER.warning(
        "Порушення цілісності даних",
        exc_info=error,
    )

    return JSONResponse(
        status_code=409,
        content={
            "detail": (
                "Конфлікт даних: код або назва вже існує, або категорія містить записи."
            )
        },
    )


@app.exception_handler(sqlite3.Error)
async def database_handler(
    request: Request,
    error: sqlite3.Error,
) -> JSONResponse:
    """Журналювати помилку бази без витоку деталей клієнту."""
    LOGGER.error(
        "Помилка роботи SQLite",
        exc_info=error,
    )

    return JSONResponse(
        status_code=500,
        content={"detail": "Не вдалося виконати операцію з базою даних."},
    )


@app.get(
    "/ping",
    summary="Перевірка доступності API",
)
def ping() -> dict[str, str]:
    """Підтвердити, що API працює."""
    return {"status": "ok"}


@app.get(
    "/student",
    response_model=StudentRead,
    summary="Дані студента",
)
def student() -> dict[str, str | int]:
    """Повернути дані зі спільного модуля."""
    return {
        "student_name": STUDENT_NAME,
        "group_name": GROUP_NAME,
        "variant_number": VARIANT_NUMBER,
    }
