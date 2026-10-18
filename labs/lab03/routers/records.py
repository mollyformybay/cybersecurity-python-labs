"""HTTP-маршрути для знахідок."""

from typing import Annotated, Any

from fastapi import APIRouter, Body, Path, Query, Response

from labs.lab03 import repository
from labs.lab03.config import MAX_VALUE, MIN_VALUE
from labs.lab03.schemas import (
    RecordCreate,
    RecordRead,
    RecordReplace,
    Status,
)

router = APIRouter(
    prefix="/records",
    tags=["Знахідки"],
)

RecordId = Annotated[
    int,
    Path(gt=0, description="Ідентифікатор знахідки"),
]

ERROR_RESPONSES = {
    404: {"description": "Запис або категорію не знайдено"},
    409: {"description": "Код запису вже існує"},
}


@router.get(
    "",
    response_model=list[RecordRead],
    summary="Отримати список знахідок",
)
def list_records(
    category_id: Annotated[
        int | None,
        Query(gt=0, description="Ідентифікатор категорії"),
    ] = None,
    status: Annotated[
        Status | None,
        Query(description="Стан опрацювання"),
    ] = None,
    min_value: Annotated[
        float | None,
        Query(
            ge=MIN_VALUE,
            le=MAX_VALUE,
            allow_inf_nan=False,
            description="Мінімальна оцінка ризику",
        ),
    ] = None,
    q: Annotated[
        str | None,
        Query(
            min_length=1,
            max_length=120,
            description="Підрядок назви з урахуванням регістру",
        ),
    ] = None,
    limit: Annotated[
        int,
        Query(ge=1, le=100, description="Кількість записів"),
    ] = 20,
    offset: Annotated[
        int,
        Query(ge=0, description="Кількість пропущених записів"),
    ] = 0,
) -> list[dict[str, Any]]:
    """Повернути записи за всіма заданими фільтрами."""
    return repository.list_records(
        category_id=category_id,
        status=status,
        min_value=min_value,
        q=q,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/bulk",
    response_model=list[RecordRead],
    status_code=201,
    summary="Додати пакет знахідок",
    responses=ERROR_RESPONSES,
)
def create_bulk(
    records: Annotated[
        list[RecordCreate],
        Body(min_length=1, max_length=100),
    ],
) -> list[dict[str, Any]]:
    """Додати весь пакет або скасувати всі його зміни."""
    return repository.create_records([record.model_dump() for record in records])


@router.post(
    "",
    response_model=RecordRead,
    status_code=201,
    summary="Створити знахідку",
    responses=ERROR_RESPONSES,
)
def create_record(record: RecordCreate) -> dict[str, Any]:
    """Перевірити дані та додати знахідку."""
    return repository.create_record(record.model_dump())


@router.get(
    "/{record_id}",
    response_model=RecordRead,
    summary="Отримати одну знахідку",
    responses={
        404: {"description": "Запис не знайдено"},
    },
)
def get_record(record_id: RecordId) -> dict[str, Any]:
    """Повернути знахідку разом із назвою категорії."""
    return repository.get_record(record_id)


@router.put(
    "/{record_id}",
    response_model=RecordRead,
    summary="Повністю оновити знахідку",
    responses=ERROR_RESPONSES,
)
def replace_record(
    record_id: RecordId,
    record: RecordReplace,
) -> dict[str, Any]:
    """Замінити всі змінювані поля зі збереженням id."""
    return repository.replace_record(
        record_id,
        record.model_dump(),
    )


@router.delete(
    "/{record_id}",
    status_code=204,
    response_class=Response,
    summary="Видалити знахідку",
    responses={
        404: {"description": "Запис не знайдено"},
    },
)
def delete_record(record_id: RecordId) -> Response:
    """Видалити знахідку та повернути відповідь без тіла."""
    repository.delete_record(record_id)

    return Response(status_code=204)
