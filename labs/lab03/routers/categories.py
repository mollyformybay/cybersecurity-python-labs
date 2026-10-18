"""HTTP-маршрути для категорій."""

from typing import Annotated, Any

from fastapi import APIRouter, Path, Response

from labs.lab03 import repository
from labs.lab03.schemas import CategoryCreate, CategoryRead

router = APIRouter(
    prefix="/categories",
    tags=["Категорії"],
)

CategoryId = Annotated[
    int,
    Path(gt=0, description="Ідентифікатор категорії"),
]


@router.get(
    "",
    response_model=list[CategoryRead],
    summary="Отримати список категорій",
)
def list_categories() -> list[dict[str, Any]]:
    """Повернути всі категорії за зростанням id."""
    return repository.list_categories()


@router.post(
    "",
    response_model=CategoryRead,
    status_code=201,
    summary="Створити категорію",
    responses={
        409: {"description": "Категорія з такою назвою вже існує"},
    },
)
def create_category(
    category: CategoryCreate,
) -> dict[str, Any]:
    """Створити категорію з унікальною назвою."""
    return repository.create_category(category.name)


@router.delete(
    "/{category_id}",
    status_code=204,
    response_class=Response,
    summary="Видалити порожню категорію",
    responses={
        404: {"description": "Категорію не знайдено"},
        409: {"description": "Категорія містить записи"},
    },
)
def delete_category(category_id: CategoryId) -> Response:
    """Видалити категорію, яка не містить записів."""
    repository.delete_category(category_id)

    return Response(status_code=204)
