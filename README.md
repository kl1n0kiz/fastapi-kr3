# Контрольная работа №3 — FastAPI Authentication & Database

Дисциплина: Технологии разработки серверных приложений  
Семестр: 4, 2025/2026

---

## Задания

| Задание | Описание |
|---------|----------|
| 6.1 | `GET /login-basic` — защита базовой HTTP-аутентификацией (статичный пользователь) |
| 6.2 | `POST /register`, `GET /login` — bcrypt-хеширование + защита от тайминг-атак |
| 6.3 | Управление документацией: DEV → `/docs` за Basic Auth; PROD → 404 |
| 6.4 | `POST /login-jwt`, `GET /protected_resource` — JWT-аутентификация (PyJWT) |
| 6.5 | Rate Limiting: `/register` 1 req/min, `/login-jwt` 5 req/min (SlowAPI) |
| 7.1 | RBAC: роли `admin / user / guest`, защищённые эндпоинты по ролям |
| 8.1 | `POST /db/register` — сохранение пользователя в SQLite |
| 8.2 | CRUD `/todos` — создание, чтение, обновление, удаление (SQLite) |

---

## Установка и запуск

```bash
# 1. Клонировать репозиторий
git clone <repo-url>
cd kr3

# 2. Создать виртуальное окружение
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# 3. Установить зависимости
pip install -r requirements.txt

# 4. Настроить переменные окружения
cp .env.example .env
# Отредактируйте .env при необходимости

# 5. Запустить
uvicorn main:app --reload
```

Приложение будет доступно на `http://localhost:8000`.

---

## Переменные окружения

| Переменная | По умолчанию | Описание |
|---|---|---|
| `MODE` | `DEV` | Режим: `DEV` или `PROD` |
| `DOCS_USER` | `admin` | Логин для `/docs` (DEV) |
| `DOCS_PASSWORD` | `secret` | Пароль для `/docs` (DEV) |
| `JWT_SECRET` | `supersecretkey_change_in_prod` | Ключ подписи JWT |
| `DB_PATH` | `app.db` | Путь к SQLite-файлу |

> ⚠️ Файл `.env` в `.gitignore` — не публикуйте реальные секреты!

---

## Тестирование через curl

### Задание 6.1 — Basic Auth (статичный: admin/password)
```bash
# Успешно
curl -u admin:password http://localhost:8000/login-basic

# Неверный пароль → 401
curl -u admin:wrong http://localhost:8000/login-basic
```

### Задание 6.2 — Регистрация + bcrypt login
```bash
# Регистрация
curl -X POST -H "Content-Type: application/json" \
  -d '{"username":"user1","password":"correctpass"}' \
  http://localhost:8000/register

# Успешный логин
curl -u user1:correctpass http://localhost:8000/login

# Неверный пароль → 401
curl -u user1:wrongpass http://localhost:8000/login
```

### Задание 6.3 — Документация
```bash
# DEV-режим: доступ к /docs с паролем (из .env: DOCS_USER/DOCS_PASSWORD)
curl -u admin:secret http://localhost:8000/docs

# PROD-режим: 404
curl http://localhost:8000/docs
```

### Задание 6.4 / 6.5 — JWT
```bash
# Сначала зарегистрировать пользователя (если ещё не сделано)
curl -X POST -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"qwerty123"}' \
  http://localhost:8000/register

# Получить токен
TOKEN=$(curl -s -X POST -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"qwerty123"}' \
  http://localhost:8000/login-jwt | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Доступ к защищённому ресурсу
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/protected_resource
```

### Задание 7.1 — RBAC

Для тестирования RBAC нужно зарегистрировать пользователей, затем вручную задать им роль через переменную `JWT_SECRET` и payload. Либо в коде временно задать роль при регистрации.

```bash
# Получить токен от имени alice (роль user)
TOKEN=...  # из login-jwt выше

# Чтение — доступно всем ролям
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/resource

# Обновление — доступно user и admin
curl -X PUT -H "Authorization: Bearer $TOKEN" http://localhost:8000/resource

# Создание — только admin → 403 для user
curl -X POST -H "Authorization: Bearer $TOKEN" http://localhost:8000/admin/resource
```

### Задание 8.1 — SQLite Users
```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"username":"test_user","password":"12345"}' \
  http://localhost:8000/db/register
```

### Задание 8.2 — Todo CRUD
```bash
# Создать
curl -X POST -H "Content-Type: application/json" \
  -d '{"title":"Buy groceries","description":"Milk, eggs, bread"}' \
  http://localhost:8000/todos

# Получить
curl http://localhost:8000/todos/1

# Обновить
curl -X PUT -H "Content-Type: application/json" \
  -d '{"completed":true}' \
  http://localhost:8000/todos/1

# Удалить
curl -X DELETE http://localhost:8000/todos/1
```
