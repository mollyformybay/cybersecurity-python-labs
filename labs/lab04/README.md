# Лабораторна робота №4

Тема: інтеграція із зовнішнім Web API та автоматизоване тестування Python-коду.

Виконав: Левинець Остап Юрійович
Група: КБ-206
Варіант: 15

## Правило варіанта

Для ручного огляду обираються записи, для яких `score >= 8.0` і
`cvssData.attackComplexity == "HIGH"`. Аналізується лише CVSS v3.1 і одна
вибрана оцінка: перша з типом `Primary`, або перша оцінка за його відсутності.

## Встановлення та запуск

```powershell
python -m pip install -r requirements.txt
python -m labs.lab04.main --cve CVE-2099-10001 --input labs/lab04/data/nvd_sample.json
python -m labs.lab04.main --cve CVE-2021-44228
```

Опція `--input` запускає повністю офлайн-режим. Без неї виконується один GET-запит
до NVD API; ключ `NVD_API_KEY`, якщо потрібен, передається тільки заголовком.
Успіх друкує один JSON-звіт у stdout, помилки — коротке повідомлення у stderr.

## Формат звіту

Звіт містить `cve_id`, `variant`, опис, статус NVD, версію CVSS, оцінку,
джерело, вектор, об'єкт `rule`, фактично спостережене значення `observed` і
рішення `decision`. `decision` може бути `not_found`, `rejected`,
`insufficient_data`, `review` або `other`. Відсутні значення подаються як `null`.

## Перевірки

```powershell
python -m pytest labs/lab04/tests -q
python -m ruff check labs/lab04
python -m ruff format --check labs/lab04
```

## Git

```powershell
git add requirements.txt labs/lab04 .gitignore
git diff --cached --check
git commit -m "Complete lab 04 validation and tests"
git push origin main
```

Синтетичний запис має `CVE-2099-10001`, оцінку 9.8 і дає рішення `other` для
варіанта 15, оскільки його `attackComplexity` дорівнює `LOW`. Тести окремо перевіряють нижче порога, рівність порогу, вище порога,
помилки даних, вибір Primary, клієнт HTTP та CLI.
