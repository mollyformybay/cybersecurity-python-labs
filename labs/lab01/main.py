"""Головний модуль запуску лабораторної роботи №1.

Послідовно викликає Завдання 1, Завдання 2 та Завдання 3.
"""

from labs.lab01.task1 import run_task1
from labs.lab01.task2 import run_task2
from labs.lab01.task3 import main as run_task3


def main() -> None:
    """Точка входу для виконання всіх завдань лабораторної роботи."""
    print("\n" + "#" * 80)
    print("ЗАПУСК ЗАВДАННЯ 1: АНАЛІЗАТОР НАДІЙНОСТІ ПАРОЛІВ")
    print("#" * 80 + "\n")
    run_task1()

    print("\n" + "#" * 80)
    print("ЗАПУСК ЗАВДАННЯ 2: БАГАТОРІВНЕВА СИСТЕМА КОНТРОЛЮ ДОСТУПУ")
    print("#" * 80 + "\n")
    run_task2()

    print("\n" + "#" * 80)
    print("ЗАПУСК ЗАВДАННЯ 3: ХЕШУВАННЯ, CSV-БАЗА ТА АУДИТ БЕЗПЕКИ")
    print("#" * 80 + "\n")
    run_task3()


if __name__ == "__main__":
    main()