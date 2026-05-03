"""
物料管理系统 — CloudBase Run 适配版
"""

import json
import secrets
import sqlite3
import os
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Any, Optional

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ─────────────────────────────────────────────
# CloudBase 适配配置
# ─────────────────────────────────────────────
# CloudBase Run 默认注入 PORT 环境变量，默认 8080
PORT = int(os.getenv("PORT", "8080"))
# CFS 挂载点（CloudBase 控制台配置后挂载到 /cfs）
DB_DIR = os.getenv("DB_DIR", "/app/data")  # 本地开发用 /app/data
DB_PATH = os.path.join(DB_DIR, "mms_users.db")
# 前端域名（生产环境必须指定，不能再用 *）
ALLOW_ORIGINS = os.getenv("ALLOW_ORIGINS", "*").split(",")
TOKEN_TTL = 7
PASS_SALT = ""

app = FastAPI(title="物料管理系统 API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in ALLOW_ORIGINS if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────
# 数据库（SQLite 文件放到持久化目录）
# ─────────────────────────────────────────────
@contextmanager
def get_db():
    # 确保目录存在（CloudBase CFS 挂载 /cfs 或 /mnt）
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()

# ─────────────────────────────────────────────
# 初始化数据库（其余代码保持原逻辑）
# ─────────────────────────────────────────────
def init_db():
    with get_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                phone      TEXT PRIMARY KEY,
                name       TEXT NOT NULL,
                password   TEXT NOT NULL,
                role       TEXT NOT NULL DEFAULT 'user',
                expire_at  TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token      TEXT PRIMARY KEY,
                phone      TEXT NOT NULL,
                expire_at  TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
            );
            CREATE TABLE IF NOT EXISTS userdata (
                phone      TEXT PRIMARY KEY,
                data       TEXT NOT NULL DEFAULT '{}',
                updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
            );
        """)
        exists = db.execute("SELECT 1 FROM users WHERE phone = '13800000000'").fetchone()
        if not exists:
            db.execute(
                "INSERT INTO users (phone, name, password, role) VALUES (?,?,?,?)",
                ("13800000000", "超级管理员", "123456", "superadmin"),
            )
        else:
            db.execute(
                "UPDATE users SET password = '123456', role = 'superadmin' WHERE phone = '13800000000'"
            )

init_db()

# ─────────────────────────────────────────────
# 工具函数
# ─────────────────────────────────────────────
def hash_pass(password: str) -> str:
    return password  # 明文存储，不加密


def make_token(phone: str) -> str:
    token = secrets.token_hex(32)
    expire = (datetime.now() + timedelta(days=TOKEN_TTL)).isoformat()
    with get_db() as db:
        db.execute(
            "INSERT INTO sessions (token, phone, expire_at) VALUES (?,?,?)",
            (token, phone, expire),
        )
    return token


def user_row_to_dict(u) -> dict:
    return {
        "phone":     u["phone"],
        "name":      u["name"],
        "role":      u["role"],
        "expireAt":  u["expire_at"],
        "createdAt": u["created_at"],
    }


def verify_token(authorization: Optional[str] = Header(None)) -> str:
    """从 Authorization: Bearer <token> 中解析并验证 token，返回 phone"""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="未提供 Token，请先登录")
    token = authorization[7:]
    with get_db() as db:
        row = db.execute(
            "SELECT phone, expire_at FROM sessions WHERE token = ?", (token,)
        ).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Token 无效，请重新登录")
    if datetime.fromisoformat(row["expire_at"]) < datetime.now():
        raise HTTPException(status_code=401, detail="Token 已过期，请重新登录")
    return row["phone"]


# ─────────────────────────────────────────────
# 请求模型
# ─────────────────────────────────────────────
class RegisterReq(BaseModel):
    phone:    str
    name:     str
    password: str

class LoginReq(BaseModel):
    phone:    str
    password: str

class SetExpiryReq(BaseModel):
    days: int   # 0=永久, -1=立即停用, >0=延长天数

class SetRoleReq(BaseModel):
    role: str   # 'user' | 'admin'


# ─────────────────────────────────────────────
# 路由
# ─────────────────────────────────────────────

@app.post("/api/auth/register", summary="注册")
def register(req: RegisterReq):
    if not req.phone or len(req.phone) != 11 or not req.phone.isdigit():
        raise HTTPException(400, "手机号格式错误")
    if len(req.password) < 6:
        raise HTTPException(400, "密码不能少于 6 位")
    if not req.name.strip():
        raise HTTPException(400, "姓名不能为空")

    with get_db() as db:
        if db.execute("SELECT 1 FROM users WHERE phone=?", (req.phone,)).fetchone():
            raise HTTPException(409, "该手机号已注册")
        default_expire = (datetime.now() + timedelta(days=30)).isoformat()
        db.execute(
            "INSERT INTO users (phone, name, password, expire_at) VALUES (?,?,?,?)",
            (req.phone, req.name.strip(), hash_pass(req.password), default_expire),
        )
        user = db.execute("SELECT * FROM users WHERE phone=?", (req.phone,)).fetchone()

    token = make_token(req.phone)
    return {"token": token, "user": user_row_to_dict(user)}


@app.post("/api/auth/login", summary="登录")
def login(req: LoginReq):
    with get_db() as db:
        user = db.execute("SELECT * FROM users WHERE phone=?", (req.phone,)).fetchone()

    if not user:
        raise HTTPException(404, "手机号未注册，请先注册")
    if user["password"] != hash_pass(req.password):
        raise HTTPException(401, "密码错误，请重新输入")

    # 校验账号有效期
    if user["expire_at"]:
        if datetime.fromisoformat(user["expire_at"]) < datetime.now():
            exp_date = datetime.fromisoformat(user["expire_at"]).strftime("%Y-%m-%d")
            raise HTTPException(403, f"账号授权已于 {exp_date} 到期，请联系管理员续期")

    token = make_token(req.phone)
    return {"token": token, "user": user_row_to_dict(user)}


@app.get("/api/auth/verify", summary="验证当前 Token")
def verify(phone: str = Depends(verify_token)):
    with get_db() as db:
        user = db.execute("SELECT * FROM users WHERE phone=?", (phone,)).fetchone()
    if not user:
        raise HTTPException(404, "用户不存在")
    return user_row_to_dict(user)


@app.post("/api/auth/logout", summary="登出（删除 Token）")
def logout(authorization: Optional[str] = Header(None)):
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
        with get_db() as db:
            db.execute("DELETE FROM sessions WHERE token=?", (token,))
    return {"success": True}


@app.get("/api/users", summary="用户列表（管理员）")
def list_users(phone: str = Depends(verify_token)):
    with get_db() as db:
        me = db.execute("SELECT * FROM users WHERE phone=?", (phone,)).fetchone()
        if not me or me["role"] not in ("admin", "superadmin"):
            raise HTTPException(403, "无权限")
        if me["role"] == "superadmin":
            rows = db.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
        else:
            rows = db.execute(
                "SELECT * FROM users WHERE role='user' OR role IS NULL ORDER BY created_at DESC"
            ).fetchall()
    return [user_row_to_dict(u) for u in rows]


@app.put("/api/users/{target_phone}/expiry", summary="设置授权有效期")
def set_expiry(target_phone: str, req: SetExpiryReq, phone: str = Depends(verify_token)):
    with get_db() as db:
        me     = db.execute("SELECT * FROM users WHERE phone=?", (phone,)).fetchone()
        target = db.execute("SELECT * FROM users WHERE phone=?", (target_phone,)).fetchone()

        if not me or me["role"] not in ("admin", "superadmin"):
            raise HTTPException(403, "无权限")
        if not target:
            raise HTTPException(404, "用户不存在")
        if target["role"] == "superadmin":
            raise HTTPException(403, "超级管理员授权不可修改")
        if me["role"] == "admin" and target["role"] in ("admin", "superadmin"):
            raise HTTPException(403, "普通管理员无权修改管理员授权")

        if req.days == 0:
            new_expire = None
        elif req.days == -1:
            new_expire = (datetime.now() - timedelta(days=1)).isoformat()
        else:
            base = datetime.now()
            if target["expire_at"]:
                t = datetime.fromisoformat(target["expire_at"])
                if t > datetime.now():
                    base = t
            new_expire = (base + timedelta(days=req.days)).isoformat()

        db.execute("UPDATE users SET expire_at=? WHERE phone=?", (new_expire, target_phone))

    return {"success": True, "expireAt": new_expire}


@app.put("/api/users/{target_phone}/role", summary="设置用户角色（超管）")
def set_role(target_phone: str, req: SetRoleReq, phone: str = Depends(verify_token)):
    if req.role not in ("user", "admin"):
        raise HTTPException(400, "角色只能为 user 或 admin")

    with get_db() as db:
        me     = db.execute("SELECT * FROM users WHERE phone=?", (phone,)).fetchone()
        target = db.execute("SELECT * FROM users WHERE phone=?", (target_phone,)).fetchone()

        if not me or me["role"] != "superadmin":
            raise HTTPException(403, "仅超级管理员可修改角色")
        if not target:
            raise HTTPException(404, "用户不存在")
        if target["role"] == "superadmin":
            raise HTTPException(403, "超级管理员角色不可修改")
        if phone == target_phone:
            raise HTTPException(400, "不能修改自己的角色")

        db.execute("UPDATE users SET role=? WHERE phone=?", (req.role, target_phone))

    return {"success": True}


# ─────────────────────────────────────────────
# 用户物料数据读写（存储在 userdata 表）
# ─────────────────────────────────────────────

@app.get("/api/data", summary="读取当前用户物料数据")
def get_data(phone: str = Depends(verify_token)):
    with get_db() as db:
        row = db.execute(
            "SELECT data FROM userdata WHERE phone=?", (phone,)
        ).fetchone()
    if not row:
        return {
            "materials": [],
            "transactions": [],
            "logs": [],
            "codeCounter": 0,
            "customTypeRules": [],
            "customUnits": ["个","片","条","套","卷","批","根","块"],
            "materialPresets": []
        }
    return json.loads(row["data"])


@app.put("/api/data", summary="保存当前用户物料数据")
async def save_data(request: Request, phone: str = Depends(verify_token)):
    body = await request.json()
    now  = datetime.now().isoformat()
    with get_db() as db:
        db.execute(
            """INSERT INTO userdata (phone, data, updated_at) VALUES (?,?,?)
               ON CONFLICT(phone) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at""",
            (phone, json.dumps(body, ensure_ascii=False), now),
        )
    return {"success": True, "savedAt": now}


# ─────────────────────────────────────────────
# 健康检查
# ─────────────────────────────────────────────
@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "time": datetime.now().isoformat(),
        "env": "cloudbase-run",,
        "db_path": DB_PATH
    }


# ─────────────────────────────────────────────
# 启动入口（CloudBase Run 需要）
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=PORT)