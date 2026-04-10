"""
Контрольная работа №3 — FastAPI Authentication & Database
Задания: 6.1, 6.2, 6.3, 6.4, 6.5, 7.1, 8.1, 8.2
"""

import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request, Security, status
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from passlib.context import CryptContext
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

# ---------------------------------------------------------------------------
# Environment / Config
# ---------------------------------------------------------------------------
from dotenv import load_dotenv

load_dotenv()

MODE = os.getenv("MODE", "DEV").upper()
DOCS_USER = os.getenv("DOCS_USER", "admin")
DOCS_PASSWORD = os.getenv("DOCS_PASSWORD", "secret")
JWT_SECRET = os.getenv("JWT_SECRET", "supersecretkey_change_in_prod")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 30

if MODE not in ("DEV", "PROD"):
    raise RuntimeError(f"Invalid MODE='{MODE}'. Allowed: DEV, PROD")

# ---------------------------------------------------------------------------
# Rate limiter  (Задание 6.5)
# ---------------------------------------------------------------------------
limiter = Limiter(key_func=get_remote_address, default_limits=[])

# ---------------------------------------------------------------------------
# FastAPI app  — docs disabled by default, we serve them manually (Задание 6.3)
# ---------------------------------------------------------------------------
app = FastAPI(
    title="KR3 FastAPI Auth",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ---------------------------------------------------------------------------
# Crypto  (Задание 6.2)
# ---------------------------------------------------------------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ---------------------------------------------------------------------------
# In-memory user DB  (fake_users_db)
# ---------------------------------------------------------------------------
# key: username  →  value: UserInDB
fake_users_db: dict = {}

# ---------------------------------------------------------------------------
# Pydantic models  (Задание 6.2)
# ---------------------------------------------------------------------------

class UserBase(BaseModel):
    username: str

class User(UserBase):
    password: str

class UserInDB(UserBase):
    hashed_password: str
    role: str = "user"          # used in Задание 7.1

# ---------------------------------------------------------------------------
# HTTP Basic security
# ---------------------------------------------------------------------------
security_basic = HTTPBasic()

# ---------------------------------------------------------------------------
# Helper: raise 401 with WWW-Authenticate header
# ---------------------------------------------------------------------------
def _unauthorized(detail: str = "Incorrect credentials") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Basic"},
    )

# ---------------------------------------------------------------------------
# Задание 6.3 — DEV: protect /docs & /openapi.json; PROD: return 404
# ---------------------------------------------------------------------------
def _verify_docs_credentials(credentials: HTTPBasicCredentials = Depends(security_basic)):
    ok_user = secrets.compare_digest(credentials.username.encode(), DOCS_USER.encode())
    ok_pass = secrets.compare_digest(credentials.password.encode(), DOCS_PASSWORD.encode())
    if not (ok_user and ok_pass):
        raise _unauthorized("Invalid docs credentials")
    return credentials


if MODE == "DEV":
    @app.get("/docs", include_in_schema=False)
    def custom_docs(credentials: HTTPBasicCredentials = Depends(_verify_docs_credentials)):
        return get_swagger_ui_html(openapi_url="/openapi.json", title="API Docs")

    @app.get("/openapi.json", include_in_schema=False)
    def custom_openapi(credentials: HTTPBasicCredentials = Depends(_verify_docs_credentials)):
        return get_openapi(title=app.title, version="1.0.0", routes=app.routes)

else:  # PROD
    @app.get("/docs", include_in_schema=False)
    @app.get("/openapi.json", include_in_schema=False)
    @app.get("/redoc", include_in_schema=False)
    def _hidden():
        raise HTTPException(status_code=404)

# ---------------------------------------------------------------------------
# Задание 6.1 — Basic-auth /login (GET)
# ---------------------------------------------------------------------------
STATIC_USER = "admin"
STATIC_PASS = "password"


def _check_basic_static(credentials: HTTPBasicCredentials = Depends(security_basic)):
    ok_u = secrets.compare_digest(credentials.username.encode(), STATIC_USER.encode())
    ok_p = secrets.compare_digest(credentials.password.encode(), STATIC_PASS.encode())
    if not (ok_u and ok_p):
        raise _unauthorized()
    return credentials


# ---------------------------------------------------------------------------
# Задание 6.2 — auth_user dependency (bcrypt, secrets)
# ---------------------------------------------------------------------------
def auth_user(credentials: HTTPBasicCredentials = Depends(security_basic)) -> UserInDB:
    # timing-safe username comparison
    found_user: Optional[UserInDB] = None
    for db_username, db_user in fake_users_db.items():
        if secrets.compare_digest(credentials.username.encode(), db_username.encode()):
            found_user = db_user
            break

    if found_user is None or not pwd_context.verify(credentials.password, found_user.hashed_password):
        raise _unauthorized()
    return found_user


# ---------------------------------------------------------------------------
# Задание 6.1 — endpoint
# ---------------------------------------------------------------------------
@app.get("/login-basic", tags=["6.1 Basic Auth"])
def login_basic(_: HTTPBasicCredentials = Depends(_check_basic_static)):
    """GET /login-basic — защищён базовой аутентификацией (статичный пользователь)."""
    return {"message": "You got my secret, welcome"}


# ---------------------------------------------------------------------------
# Задание 6.2 — /register + /login (bcrypt)
# ---------------------------------------------------------------------------
@app.post("/register", tags=["6.2 / 6.5 Register"], status_code=201)
@limiter.limit("1/minute")         # Задание 6.5 — rate limit
def register(request: Request, user: User):
    """POST /register — регистрация с хешированием пароля."""
    # Check duplicate (timing-safe)
    for existing in fake_users_db:
        if secrets.compare_digest(user.username.encode(), existing.encode()):
            raise HTTPException(status_code=409, detail="User already exists")

    hashed = pwd_context.hash(user.password)
    fake_users_db[user.username] = UserInDB(
        username=user.username,
        hashed_password=hashed,
        role="user",
    )
    return {"message": "New user created"}


@app.get("/login", tags=["6.2 Basic Auth with bcrypt"])
def login_bcrypt(current_user: UserInDB = Depends(auth_user)):
    """GET /login — базовая аутентификация + bcrypt-проверка пароля."""
    return {"message": f"Welcome, {current_user.username}!"}


# ---------------------------------------------------------------------------
# Задание 6.4 — JWT /login (POST) + /protected_resource
# ---------------------------------------------------------------------------
class LoginPayload(BaseModel):
    username: str
    password: str


def _create_jwt(username: str, role: str = "user") -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE_MINUTES)
    payload = {"sub": username, "role": role, "exp": expire}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def _decode_jwt(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def get_current_user_jwt(request: Request) -> dict:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = auth_header.split(" ", 1)[1]
    return _decode_jwt(token)


@app.post("/login-jwt", tags=["6.4 / 6.5 JWT Auth"])
@limiter.limit("5/minute")         # Задание 6.5 — rate limit
def login_jwt(request: Request, payload: LoginPayload):
    """POST /login-jwt — аутентификация, возвращает JWT-токен."""
    # Find user (timing-safe username)
    found: Optional[UserInDB] = None
    for db_username, db_user in fake_users_db.items():
        if secrets.compare_digest(payload.username.encode(), db_username.encode()):
            found = db_user
            break

    if found is None:
        raise HTTPException(status_code=404, detail="User not found")

    if not pwd_context.verify(payload.password, found.hashed_password):
        raise HTTPException(status_code=401, detail="Authorization failed")

    token = _create_jwt(found.username, found.role)
    return {"access_token": token, "token_type": "bearer"}


@app.get("/protected_resource", tags=["6.4 JWT Protected"])
def protected_resource(claims: dict = Depends(get_current_user_jwt)):
    """GET /protected_resource — требует валидный JWT в заголовке Authorization."""
    return {"message": "Access granted", "user": claims.get("sub")}


# ---------------------------------------------------------------------------
# Задание 7.1 — RBAC
# ---------------------------------------------------------------------------
ROLE_PERMISSIONS = {
    "admin": {"create", "read", "update", "delete"},
    "user":  {"read", "update"},
    "guest": {"read"},
}

def require_permission(permission: str):
    def dependency(claims: dict = Depends(get_current_user_jwt)):
        role = claims.get("role", "guest")
        allowed = ROLE_PERMISSIONS.get(role, set())
        if permission not in allowed:
            raise HTTPException(status_code=403, detail=f"Role '{role}' lacks '{permission}' permission")
        return claims
    return dependency


@app.post("/admin/resource", tags=["7.1 RBAC"], status_code=201)
def admin_create(claims: dict = Depends(require_permission("create"))):
    """Только admin может создавать ресурс."""
    return {"message": f"Resource created by {claims['sub']}"}


@app.get("/resource", tags=["7.1 RBAC"])
def read_resource(claims: dict = Depends(require_permission("read"))):
    """admin / user / guest могут читать."""
    return {"message": f"Hello, {claims['sub']} ({claims.get('role')}). Here is your resource."}


@app.put("/resource", tags=["7.1 RBAC"])
def update_resource(claims: dict = Depends(require_permission("update"))):
    """admin / user могут обновлять."""
    return {"message": f"Resource updated by {claims['sub']}"}


@app.delete("/resource", tags=["7.1 RBAC"])
def delete_resource(claims: dict = Depends(require_permission("delete"))):
    """Только admin может удалять."""
    return {"message": f"Resource deleted by {claims['sub']}"}


# ---------------------------------------------------------------------------
# Задание 8.1 & 8.2 — SQLite
# ---------------------------------------------------------------------------
DB_PATH = os.getenv("DB_PATH", "app.db")


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS todos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            completed INTEGER NOT NULL DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()


init_db()


# — 8.1 Register (SQLite)
class UserRegisterDB(BaseModel):
    username: str
    password: str


@app.post("/db/register", tags=["8.1 SQLite Users"])
def db_register(user: UserRegisterDB):
    """POST /db/register — сохраняет пользователя в SQLite."""
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        (user.username, user.password),
    )
    conn.commit()
    conn.close()
    return {"message": "User registered successfully!"}


# — 8.2 Todo CRUD
class TodoCreate(BaseModel):
    title: str
    description: Optional[str] = None


class TodoUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    completed: Optional[bool] = None


def _row_to_todo(row) -> dict:
    return {
        "id": row["id"],
        "title": row["title"],
        "description": row["description"],
        "completed": bool(row["completed"]),
    }


@app.post("/todos", tags=["8.2 Todo CRUD"], status_code=201)
def create_todo(todo: TodoCreate):
    conn = get_db_connection()
    cur = conn.execute(
        "INSERT INTO todos (title, description, completed) VALUES (?, ?, 0)",
        (todo.title, todo.description),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM todos WHERE id = ?", (cur.lastrowid,)).fetchone()
    conn.close()
    return _row_to_todo(row)


@app.get("/todos/{todo_id}", tags=["8.2 Todo CRUD"])
def get_todo(todo_id: int):
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM todos WHERE id = ?", (todo_id,)).fetchone()
    conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="Todo not found")
    return _row_to_todo(row)


@app.put("/todos/{todo_id}", tags=["8.2 Todo CRUD"])
def update_todo(todo_id: int, data: TodoUpdate):
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM todos WHERE id = ?", (todo_id,)).fetchone()
    if row is None:
        conn.close()
        raise HTTPException(status_code=404, detail="Todo not found")
    current = _row_to_todo(row)
    new_title = data.title if data.title is not None else current["title"]
    new_desc  = data.description if data.description is not None else current["description"]
    new_done  = int(data.completed) if data.completed is not None else int(current["completed"])
    conn.execute(
        "UPDATE todos SET title=?, description=?, completed=? WHERE id=?",
        (new_title, new_desc, new_done, todo_id),
    )
    conn.commit()
    updated = conn.execute("SELECT * FROM todos WHERE id = ?", (todo_id,)).fetchone()
    conn.close()
    return _row_to_todo(updated)


@app.delete("/todos/{todo_id}", tags=["8.2 Todo CRUD"])
def delete_todo(todo_id: int):
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM todos WHERE id = ?", (todo_id,)).fetchone()
    if row is None:
        conn.close()
        raise HTTPException(status_code=404, detail="Todo not found")
    conn.execute("DELETE FROM todos WHERE id = ?", (todo_id,))
    conn.commit()
    conn.close()
    return {"message": f"Todo {todo_id} deleted successfully"}