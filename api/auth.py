import re

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .database import PROJECT_ROOT, SessionLocal, get_db
from .models import User
from .security import hash_password, verify_password

router = APIRouter(tags=["auth"])

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,32}$")
PASSWORD_MIN = 8
DEMO_USERNAME = "demo"
DEMO_PASSWORD = "DemoPass123!"


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    username: str
    password: str


def validate_username(username: str) -> str:
    username = username.strip()
    if not USERNAME_RE.fullmatch(username):
        raise HTTPException(
            status_code=400,
            detail="Username must be 3-32 characters: letters, digits, underscore.",
        )
    return username


def seed_demo_user() -> None:
    db = SessionLocal()
    try:
        if db.query(User).filter(User.username == DEMO_USERNAME).first():
            return
        db.add(User(username=DEMO_USERNAME, password_hash=hash_password(DEMO_PASSWORD)))
        db.commit()
    finally:
        db.close()


def public_path(request: Request, path: str) -> str:
    if not path.startswith("/"):
        path = f"/{path}"
    prefix = request.headers.get("x-forwarded-prefix", "").rstrip("/")
    return f"{prefix}{path}" if prefix else path


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, error: str | None = None, ok: str | None = None):
    html_path = PROJECT_ROOT / "src" / "login.html"
    if not html_path.is_file():
        raise HTTPException(status_code=500, detail="Login template not found.")

    content = html_path.read_text(encoding="utf-8")
    logout_url = public_path(request, "/auth/logout")
    logged_in = request.session.get("username")
    if logged_in:
        banner = (
            f'<p class="banner success">Logado como <strong>{logged_in}</strong>. '
            f'<a href="{logout_url}">Sair</a></p>'
        )
    elif error == "invalid":
        banner = '<p class="banner error">Usuario ou senha invalidos.</p>'
    elif ok:
        banner = '<p class="banner success">Login realizado com sucesso.</p>'
    else:
        banner = ""

    content = content.replace("<!--BANNER-->", banner)
    return HTMLResponse(content)


@router.post("/auth/login")
def login_json(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    username = validate_username(body.username)
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    request.session["user_id"] = user.id
    request.session["username"] = user.username
    return {"ok": True, "username": user.username}


@router.post("/auth/login/form")
def login_form(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    username = validate_username(username)
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password_hash):
        return RedirectResponse(url=public_path(request, "/login?error=invalid"), status_code=303)

    request.session["user_id"] = user.id
    request.session["username"] = user.username
    return RedirectResponse(url=public_path(request, "/login?ok=1"), status_code=303)


@router.post("/auth/register")
def register(body: RegisterRequest, db: Session = Depends(get_db)):
    username = validate_username(body.username)
    if len(body.password) < PASSWORD_MIN:
        raise HTTPException(
            status_code=400,
            detail=f"Password must be at least {PASSWORD_MIN} characters.",
        )
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(status_code=409, detail="Username already taken.")

    user = User(username=username, password_hash=hash_password(body.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"ok": True, "username": user.username, "id": user.id}


@router.get("/auth/me")
def me(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated.")

    user = db.get(User, user_id)
    if not user:
        request.session.clear()
        raise HTTPException(status_code=401, detail="Not authenticated.")

    return {"id": user.id, "username": user.username}


@router.post("/auth/logout")
def logout_json(request: Request):
    request.session.clear()
    return {"ok": True}


@router.get("/auth/logout")
def logout_page(request: Request):
    request.session.clear()
    return RedirectResponse(url=public_path(request, "/login"), status_code=303)
