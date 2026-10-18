"""Моделі запитів, відповідей і початкових даних."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from labs.lab03.config import MAX_VALUE, MIN_VALUE

Status = Literal["new", "in_progress", "done"]

Risk = Annotated[
    float,
    Field(
        ge=MIN_VALUE,
        le=MAX_VALUE,
        allow_inf_nan=False,
    ),
]


class InputModel(BaseModel):
    """Спільні правила перевірки вхідних даних."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="forbid",
    )


class CategoryCreate(InputModel):
    """Дані для створення категорії."""

    name: str = Field(min_length=2, max_length=40)


class CategoryRead(CategoryCreate):
    """Категорія з ідентифікатором."""

    id: int = Field(gt=0)


class RecordCreate(InputModel):
    """Дані для створення знахідки."""

    code: str = Field(min_length=3, max_length=40)
    title: str = Field(min_length=3, max_length=120)
    category_id: int = Field(gt=0)
    value: Risk
    status: Status


class RecordReplace(RecordCreate):
    """Повна заміна всіх змінюваних полів знахідки."""


class RecordRead(RecordCreate):
    """Знахідка з ідентифікатором і назвою категорії."""

    id: int = Field(gt=0)
    category_name: str


class SeedData(InputModel):
    """Початковий набір із трьох категорій і восьми записів."""

    categories: list[CategoryRead] = Field(
        min_length=3,
        max_length=3,
    )
    records: list[RecordCreate] = Field(
        min_length=8,
        max_length=8,
    )


class StudentRead(BaseModel):
    """Дані студента."""

    student_name: str
    group_name: str
    variant_number: int
