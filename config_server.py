#!/usr/bin/env python3
# 客满中心 AI 应用统一工作台 —— 增强版服务端（含登录认证 + 人员权限）
# 同一进程同时托管：网页(index.html) + 应用配置接口(/modules) + 认证/人员接口(/api/*)
# 关键点：网页与接口同源(同一 host:port)，浏览器不再触发"混合内容"拦截，
#         所有业务数据（应用配置、人员）均存于服务器本地 json 文件，全员实时一致。
# 用法：
#   python3 config_server.py
# 访问： http://<服务器IP>:8080/   （全员用这个地址）
import json, os, re, time, secrets
from urllib.parse import urlparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", "8080"))
ROOT = os.path.dirname(os.path.abspath(__file__))
MODULES_FILE = os.path.join(ROOT, "modules.json")
USERS_FILE   = os.path.join(ROOT, "users.json")
# 以下文件禁止通过 HTTP 直接访问（含业务数据/日志）
BLOCK_FILES = {"modules.json", "users.json", "server.log", "config_server.py"}

CORS = {"Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type,Authorization"}

# ===== 通用 json 读写 =====
def load_json(path, default):
    if os.path.exists(path):
        try:
            return json.load(open(path, encoding="utf-8"))
        except Exception:
            return default
    return default

def save_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)   # 原子写，避免半截文件

# ===== 人员数据 =====
def load_users():
    return load_json(USERS_FILE, None)   # None 表示文件不存在

def save_users(arr):
    save_json(USERS_FILE, arr)

def find_user(pred):
    for u in load_users() or []:
        if pred(u):
            return u
    return None

def find_by_token(tok):
    return find_user(lambda u: u.get("token") == tok) if tok else None

def find_by_name(name):
    return find_user(lambda u: u.get("name") == name)

def find_by_id(uid):
    return find_user(lambda u: u.get("id") == uid)

def is_admin(u):
    return bool(u) and u.get("role") in ("super_admin", "admin")

def safe_user(u):
    """对外返回的人员信息（剔除 token）"""
    return {k: v for k, v in u.items() if k != "token"}

def init_users():
    """首次启动：若人员表为空/不存在，自动初始化默认人员"""
    users = load_users()
    if users is not None:        # 文件已存在（即使是空列表），不再初始化
        return
    modules = load_json(MODULES_FILE, [])
    staff_ids = [m.get("id") for m in modules if m.get("perm") == "staff"]
    now = time.strftime("%Y-%m-%d %H:%M")
    seed = [
        {"id": "u_admin", "name": "admin", "role": "super_admin",
         "visibleApps": [], "remark": "超级管理员", "token": None, "createTime": now},
        {"id": "u_yiduo", "name": "鼠一多", "role": "admin",
         "visibleApps": [], "remark": "管理员", "token": None, "createTime": now},
        {"id": "u_lele", "name": "鼠乐乐", "role": "employee",
         "visibleApps": list(staff_ids), "remark": "", "token": None, "createTime": now},
        {"id": "u_dingdong", "name": "鼠叮咚", "role": "employee",
         "visibleApps": list(staff_ids), "remark": "", "token": None, "createTime": now},
        {"id": "u_yaoyao", "name": "鼠摇摇", "role": "employee",
         "visibleApps": list(staff_ids), "remark": "", "token": None, "createTime": now},
        {"id": "u_xingzi", "name": "鼠杏子", "role": "employee",
         "visibleApps": list(staff_ids), "remark": "", "token": None, "createTime": now},
        {"id": "u_qingshang", "name": "鼠清商", "role": "employee",
         "visibleApps": list(staff_ids), "remark": "", "token": None, "createTime": now},
        {"id": "u_shengsheng", "name": "鼠笙笙", "role": "employee",
         "visibleApps": list(staff_ids), "remark": "", "token": None, "createTime": now},
    ]
    save_users(seed)

_EXT = {".html": "text/html; charset=utf-8", ".png": "image/png", ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg", ".css": "text/css", ".js": "application/javascript",
        ".json": "application/json", ".svg": "image/svg+xml", ".ico": "image/x-icon"}

def ok(body, ctype="application/json; charset=utf-8"):
    return body if isinstance(body, (bytes, str)) else json.dumps(body, ensure_ascii=False)

class Handler(BaseHTTPRequestHandler):
    def _send(self, code, ctype, body, cors=True):
        data = body if isinstance(body, bytes) else str(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        if cors:
            for k, v in CORS.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _json(self, code, obj):
        self._send(code, "application/json; charset=utf-8", json.dumps(obj, ensure_ascii=False))

    def _body_json(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        if n <= 0:
            return {}
        try:
            return json.loads(self.rfile.read(n))
        except Exception:
            return {}

    def _token(self):
        auth = self.headers.get("Authorization", "")
        m = re.match(r"Bearer\s+(\S+)", auth)
        return m.group(1) if m else None

    def _user(self):
        return find_by_token(self._token())

    def do_OPTIONS(self):
        self._send(204, "text/plain", b"")

    # ===== 认证 / 人员 API =====
    def api_auth_login(self, data):
        name = (data.get("name") or "").strip()
        if not name:
            return 400, {"code": 1, "message": "请输入姓名"}
        arr = load_users() or []
        u = next((x for x in arr if x.get("name") == name), None)
        if not u:
            return 200, {"code": 1, "message": "姓名不存在，请联系管理员"}
        if not u.get("token"):
            u["token"] = secrets.token_hex(16)
        save_users(arr)   # arr 与 u 同引用，保存即持久化 token
        return 200, {"code": 0, "data": {"id": u["id"], "name": u["name"], "role": u["role"],
                                          "visibleApps": u.get("visibleApps", []),
                                          "token": u["token"]}, "message": ""}

    def api_auth_me(self):
        u = self._user()
        if not u:
            return 401, {"code": 401, "message": "未授权或登录已失效"}
        return 200, {"code": 0, "data": safe_user(u), "message": ""}

    def api_users_list(self):
        u = self._user()
        if not is_admin(u):
            return 401, {"code": 401, "message": "无权限"}
        return 200, {"code": 0, "data": [safe_user(x) for x in load_users()], "message": ""}

    def api_users_create(self, data):
        u = self._user()
        if not is_admin(u):
            return 401, {"code": 401, "message": "无权限"}
        name = (data.get("name") or "").strip()
        role = data.get("role")
        if not name:
            return 400, {"code": 1, "message": "姓名必填"}
        if role not in ("admin", "employee"):
            return 400, {"code": 1, "message": "角色只能是 管理员 或 员工"}
        if find_by_name(name):
            return 400, {"code": 1, "message": "该姓名已存在"}
        visible = data.get("visibleApps") or []
        visible = [str(x) for x in visible if x] if isinstance(visible, list) else []
        new_id = "u_" + secrets.token_hex(6)
        rec = {"id": new_id, "name": name, "role": role,
               "visibleApps": [] if role == "admin" else visible,
               "remark": (data.get("remark") or "").strip(),
               "token": None, "createTime": time.strftime("%Y-%m-%d %H:%M")}
        arr = load_users() or []
        arr.append(rec)
        save_users(arr)
        return 200, {"code": 0, "data": {"id": new_id}, "message": "创建成功"}

    def api_users_update(self, uid, data):
        u = self._user()
        if not is_admin(u):
            return 401, {"code": 401, "message": "无权限"}
        arr = load_users() or []
        target = next((x for x in arr if x.get("id") == uid), None)
        if not target:
            return 404, {"code": 1, "message": "人员不存在"}
        if target.get("role") == "super_admin":
            return 400, {"code": 1, "message": "超级管理员不可编辑"}
        name = (data.get("name") or "").strip()
        role = data.get("role")
        if not name:
            return 400, {"code": 1, "message": "姓名必填"}
        if role not in ("admin", "employee"):
            return 400, {"code": 1, "message": "角色只能是 管理员 或 员工"}
        # 重名检测（排除自己）
        dup = next((x for x in arr if x.get("name") == name and x.get("id") != uid), None)
        if dup:
            return 400, {"code": 1, "message": "该姓名已存在"}
        target["name"] = name
        target["role"] = role
        target["remark"] = (data.get("remark") or "").strip()
        if role == "admin":
            target["visibleApps"] = []
        else:
            visible = data.get("visibleApps") or []
            target["visibleApps"] = [str(x) for x in visible if x] if isinstance(visible, list) else []
        save_users(arr)
        return 200, {"code": 0, "data": {}, "message": "更新成功"}

    def api_users_delete(self, uid):
        u = self._user()
        if not is_admin(u):
            return 401, {"code": 401, "message": "无权限"}
        target = find_by_id(uid)
        if not target:
            return 404, {"code": 1, "message": "人员不存在"}
        if target.get("role") == "super_admin":
            return 400, {"code": 1, "message": "超级管理员不可删除"}
        if target.get("id") == u.get("id"):
            return 400, {"code": 1, "message": "不能删除当前登录账号"}
        arr = [x for x in (load_users() or []) if x.get("id") != uid]
        save_users(arr)
        return 200, {"code": 0, "data": {}, "message": "删除成功"}

    # ===== 路由 =====
    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            fp = os.path.join(ROOT, "index.html")
            if os.path.isfile(fp):
                self._send(200, "text/html; charset=utf-8", open(fp, "rb").read())
            else:
                self._send(404, "text/plain", "index.html 不存在，请先放到本目录")
            return
        if path == "/modules":
            self._json(200, load_json(MODULES_FILE, []))
            return
        if path == "/api/auth/me":
            code, obj = self.api_auth_me()
            self._json(code, obj); return
        if path == "/api/users":
            code, obj = self.api_users_list()
            self._json(code, obj); return
        # 静态文件（图片等）—— 禁止访问数据/脚本文件
        fp = os.path.normpath(os.path.join(ROOT, path.lstrip("/")))
        base = os.path.basename(fp)
        if fp.startswith(ROOT) and base not in BLOCK_FILES and os.path.isfile(fp):
            self._send(200, _EXT.get(os.path.splitext(fp)[1], "application/octet-stream"),
                       open(fp, "rb").read())
        else:
            self._send(404, "text/plain", "Not Found")

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/modules":
            # 写应用配置：需管理员（带 token 则校验，无 token 兼容旧部署）
            u = self._user()
            if u is not None and not is_admin(u):
                self._json(403, {"ok": False, "error": "无权限"}); return
            data = self._body_json()
            arr = data.get("modules", [])
            if not isinstance(arr, list):
                self._json(400, {"ok": False, "error": "modules 必须是数组"}); return
            save_json(MODULES_FILE, arr)
            self._json(200, {"ok": True, "count": len(arr)}); return
        if path == "/api/auth/login":
            code, obj = self.api_auth_login(self._body_json())
            self._json(code, obj); return
        if path == "/api/users":
            code, obj = self.api_users_create(self._body_json())
            self._json(code, obj); return
        self._json(404, {"code": 1, "message": "Not Found"})

    def do_PUT(self):
        path = urlparse(self.path).path
        m = re.match(r"^/api/users/([^/]+)$", path)
        if m:
            code, obj = self.api_users_update(m.group(1), self._body_json())
            self._json(code, obj); return
        self._json(404, {"code": 1, "message": "Not Found"})

    def do_DELETE(self):
        path = urlparse(self.path).path
        m = re.match(r"^/api/users/([^/]+)$", path)
        if m:
            code, obj = self.api_users_delete(m.group(1))
            self._json(code, obj); return
        self._json(404, {"code": 1, "message": "Not Found"})

    def log_message(self, *a):
        pass

if __name__ == "__main__":
    init_users()
    os.chdir(ROOT)
    with ThreadingHTTPServer(("0.0.0.0", PORT), Handler) as httpd:
        print(f"客满工作台已启动： http://0.0.0.0:{PORT}/  (Ctrl+C 退出)")
        httpd.serve_forever()
