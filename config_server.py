#!/usr/bin/env python3
# 客满中心 AI 应用统一工作台 —— 增强版服务端
# 权限模型：权限(permission) - 角色(role) - 人员(user) 三级 RBAC
# 同一进程托管：网页(index.html) + 应用配置(/modules) + 认证/人员/权限接口(/api/*)
# 关键点：网页与接口同源(同一 host:port)，避免混合内容拦截；
#         所有业务数据存服务器本地 json，全员实时一致；所有鉴权计算在后端完成。
# 用法： python3 config_server.py
# 访问： http://<服务器IP>:8080/
import json, os, re, time, secrets, hashlib
from urllib.parse import urlparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", "8080"))
ROOT = os.path.dirname(os.path.abspath(__file__))
MODULES_FILE = os.path.join(ROOT, "modules.json")
USERS_FILE   = os.path.join(ROOT, "users.json")
ROLES_FILE   = os.path.join(ROOT, "roles.json")
PERMS_FILE   = os.path.join(ROOT, "permissions.json")
NAV_FILE     = os.path.join(ROOT, "nav.json")
# 以下文件禁止通过 HTTP 直接访问（含业务数据/日志）
BLOCK_FILES = {"modules.json", "users.json", "roles.json", "permissions.json",
               "nav.json", "server.log", "config_server.py"}

# 固定的 4 个一级目录（不可删除，可改名/图标/排序）
DEFAULT_NAV = [
    {"id": "d_overview", "name": "数据总览", "icon": "kanban", "order": 1, "fixed": True},
    {"id": "d_train",    "name": "培训平台", "icon": "train",  "order": 2, "fixed": True},
    {"id": "d_qc",       "name": "质检平台", "icon": "qc",     "order": 3, "fixed": True},
    {"id": "d_tool",     "name": "日常工具", "icon": "tool",   "order": 4, "fixed": True},
]

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
    os.replace(tmp, path)   # 原子写

# ===== 密码 =====
def hash_pw(pw, salt=None):
    salt = salt or secrets.token_hex(8)
    d = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt.encode("utf-8"), 100000).hex()
    return f"{d}${salt}"

def verify_pw(pw, stored):
    if not stored or "$" not in stored:
        return False
    h, salt = stored.split("$", 1)
    return hash_pw(pw, salt).split("$")[0] == h

# ===== 数据加载/保存 =====
def load_users():  return load_json(USERS_FILE, None)
def load_roles():  return load_json(ROLES_FILE, [])
def load_perms():  return load_json(PERMS_FILE, [])
def load_nav():
    nav = load_json(NAV_FILE, None)
    if nav is None:
        return DEFAULT_NAV
    by_id = {d["id"]: d for d in nav if isinstance(d, dict)}
    merged = []
    for d in DEFAULT_NAV:
        if d["id"] in by_id:
            cur = by_id[d["id"]]
            merged.append({"id": d["id"], "name": cur.get("name", d["name"]),
                           "icon": cur.get("icon", d["icon"]),
                           "order": cur.get("order", d["order"]), "fixed": True})
        else:
            merged.append(dict(d))
    for d in nav:
        if isinstance(d, dict) and d.get("id") not in {x["id"] for x in DEFAULT_NAV}:
            merged.append(d)
    return merged
def save_perms(a): save_json(PERMS_FILE, a)
def save_nav(a): save_json(NAV_FILE, a)
def save_users(a): save_json(USERS_FILE, a)
def save_roles(a): save_json(ROLES_FILE, a)
def save_perms(a): save_json(PERMS_FILE, a)

def find_user(pred):
    for u in load_users() or []:
        if pred(u):
            return u
    return None
def find_by_token(t): return find_user(lambda u: u.get("token") == t) if t else None
def find_by_name(n):  return find_user(lambda u: u.get("name") == n)
def find_by_id(i):    return find_user(lambda u: u.get("id") == i)

def load_roles_map():
    return {r["id"]: r for r in load_roles()}

def is_admin(u):
    """角色中含 isAdmin 标记即视为管理员"""
    if not u:
        return False
    rm = load_roles_map()
    return any(rm.get(rid, {}).get("isAdmin") for rid in u.get("roleIds", []))

def is_super(u):
    """仅超级管理员角色（用于权限/角色配置这类最高权限）"""
    if not u:
        return False
    rm = load_roles_map()
    return any(rm.get(rid, {}).get("isAdmin") and rm.get(rid, {}).get("name") == "超级管理员"
               for rid in u.get("roleIds", []))

def perm_union(role_ids):
    """后端计算：角色权限并集（去重，保持顺序）"""
    rm = load_roles_map()
    out, seen = [], set()
    for rid in role_ids or []:
        for pid in rm.get(rid, {}).get("permIds", []):
            if pid not in seen:
                out.append(pid); seen.add(pid)
    return out

def role_need_pw(u):
    rm = load_roles_map()
    return any(rm.get(rid, {}).get("needPassword") for rid in u.get("roleIds", []))

def safe_user(u):
    """对外返回的人员信息（剔除 token / 密码）"""
    return {k: v for k, v in u.items() if k not in ("token", "pw")}

# ===== 种子与迁移 =====
def init_permissions():
    if os.path.exists(PERMS_FILE):
        return
    modules = load_json(MODULES_FILE, [])
    perms = [{"id": m.get("id"), "name": m.get("name", m.get("id")),
              "page": m.get("url") or "", "desc": f"应用权限：{m.get('name','')}"}
             for m in modules if m.get("id")]
    save_perms(perms)

def init_roles():
    if os.path.exists(ROLES_FILE):
        return
    modules = load_json(MODULES_FILE, [])
    perm_by_module = {m.get("id"): m.get("perm", "staff") for m in modules}
    perms = load_perms()
    all_ids = [p["id"] for p in perms]
    staff_ids = [p["id"] for p in perms if perm_by_module.get(p["id"]) == "staff"]
    now = time.strftime("%Y-%m-%d %H:%M")
    roles = [
        {"id": "r_super_admin", "name": "超级管理员", "permIds": list(all_ids),
         "needPassword": False, "isAdmin": True, "remark": "系统最高权限", "createTime": now},
        {"id": "r_admin", "name": "管理员", "permIds": list(all_ids),
         "needPassword": False, "isAdmin": True, "remark": "可管理人员与配置", "createTime": now},
        {"id": "r_employee", "name": "员工", "permIds": list(staff_ids),
         "needPassword": False, "isAdmin": False, "remark": "一线坐席", "createTime": now},
    ]
    save_roles(roles)

def init_users():
    if load_users() is not None:     # 文件已存在（即使空列表）不再初始化
        return
    now = time.strftime("%Y-%m-%d %H:%M")
    seed = [
        {"id": "u_admin",   "name": "admin",   "roleIds": ["r_super_admin"], "pw": {}, "remark": "超级管理员", "token": None, "createTime": now},
        {"id": "u_yiduo",   "name": "鼠一多", "roleIds": ["r_admin"],       "pw": {}, "remark": "管理员",     "token": None, "createTime": now},
        {"id": "u_lele",    "name": "鼠乐乐", "roleIds": ["r_employee"],    "pw": {}, "remark": "",           "token": None, "createTime": now},
        {"id": "u_dingdong","name": "鼠叮咚", "roleIds": ["r_employee"],    "pw": {}, "remark": "",           "token": None, "createTime": now},
        {"id": "u_yaoyao",  "name": "鼠摇摇", "roleIds": ["r_employee"],    "pw": {}, "remark": "",           "token": None, "createTime": now},
        {"id": "u_xingzi",  "name": "鼠杏子", "roleIds": ["r_employee"],    "pw": {}, "remark": "",           "token": None, "createTime": now},
        {"id": "u_qingshang","name":"鼠清商", "roleIds": ["r_employee"],    "pw": {}, "remark": "",           "token": None, "createTime": now},
        {"id": "u_shengsheng","name":"鼠笙笙","roleIds": ["r_employee"],    "pw": {}, "remark": "",           "token": None, "createTime": now},
    ]
    save_users(seed)

def migrate():
    """兼容旧部署：确保 roles/perms 存在，并把旧单角色用户转为 roleIds 模型"""
    init_permissions()
    init_roles()
    users = load_users()
    if users is None:
        init_users()
        return
    if not isinstance(users, list):
        return
    changed = False
    role_map = {"super_admin": "r_super_admin", "admin": "r_admin", "employee": "r_employee"}
    for u in users:
        if "roleIds" not in u and "role" in u:
            u["roleIds"] = [role_map.get(u["role"], "r_employee")]
            changed = True
        if "pw" not in u:
            u["pw"] = {}; changed = True
        if "token" not in u:
            u["token"] = None; changed = True
    if changed:
        save_users(users)

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

    # ===== 认证 / 人员 / 角色 / 权限 API =====
    def api_auth_login(self, data):
        name = (data.get("name") or "").strip()
        if not name:
            return 400, {"code": 1, "message": "请输入姓名"}
        arr = load_users() or []
        u = next((x for x in arr if x.get("name") == name), None)
        if not u:
            return 200, {"code": 1, "message": "姓名不存在，请联系管理员"}
        # 需密码角色校验
        rm = load_roles_map()
        pwmap = data.get("pw") or {}
        need = []
        for rid in u.get("roleIds", []):
            r = rm.get(rid)
            if r and r.get("needPassword"):
                provided = pwmap.get(rid)
                if not provided:
                    need.append({"id": rid, "name": r.get("name", "")})
                elif not verify_pw(provided, u.get("pw", {}).get(rid, "")):
                    return 200, {"code": 1, "message": f"[{r.get('name','')}]密码错误"}
        if need:
            return 200, {"code": 2, "message": "需要密码", "needPwd": need}
        # 签发 token（同引用持久化）
        if not u.get("token"):
            u["token"] = secrets.token_hex(16)
        save_users(arr)
        return 200, {"code": 0, "data": {
            "id": u["id"], "name": u["name"], "roleIds": u.get("roleIds", []),
            "permIds": perm_union(u.get("roleIds", [])), "token": u["token"]
        }, "message": ""}

    def api_auth_me(self):
        u = self._user()
        if not u:
            return 401, {"code": 401, "message": "未授权或登录已失效"}
        d = safe_user(u)
        d["permIds"] = perm_union(u.get("roleIds", []))
        return 200, {"code": 0, "data": d, "message": ""}

    # ---- 人员 ----
    def _build_user(self, data, arr, target=None):
        """校验并构造/更新人员记录（后端完成全部规则计算）"""
        name = (data.get("name") or "").strip()
        if not name:
            return 400, "姓名必填"
        role_ids = data.get("roleIds") or []
        if not isinstance(role_ids, list) or not role_ids:
            return 400, "至少分配一个角色"
        rm = load_roles_map()
        for rid in role_ids:
            if rid not in rm:
                return 400, f"角色 {rid} 不存在"
        if target is None and find_by_name(name):
            return 400, "该姓名已存在"
        # 密码策略：需密码角色必须同步设置密码（明文仅在此函数内使用，存 hash）
        pw_in = data.get("pw") or {}
        pw_store = {}
        for rid in role_ids:
            r = rm[rid]
            if r.get("needPassword"):
                raw = pw_in.get(rid)
                if not raw:
                    return 400, f"角色[{r['name']}]需要设置登录密码"
                pw_store[rid] = hash_pw(raw)
        if target is not None:
            # 更新：保留未被修改的密码
            old_pw = target.get("pw", {})
            for rid in role_ids:
                if rid in pw_store:
                    old_pw[rid] = pw_store[rid]
                elif rm.get(rid, {}).get("needPassword"):
                    if rid not in old_pw:
                        return 400, f"角色[{rm[rid]['name']}]需要设置登录密码"
            target["name"] = name
            target["roleIds"] = role_ids
            target["remark"] = (data.get("remark") or "").strip()
            return 200, None
        rec = {"id": "u_" + secrets.token_hex(6), "name": name, "roleIds": role_ids,
               "pw": pw_store, "remark": (data.get("remark") or "").strip(),
               "token": None, "createTime": time.strftime("%Y-%m-%d %H:%M")}
        return 200, rec

    def api_users_list(self):
        u = self._user()
        if not is_admin(u):
            return 401, {"code": 401, "message": "无权限"}
        return 200, {"code": 0, "data": [safe_user(x) for x in load_users()], "message": ""}

    def api_users_create(self, data):
        u = self._user()
        if not is_admin(u):
            return 401, {"code": 401, "message": "无权限"}
        code, payload = self._build_user(data, load_users())
        if code != 200:
            return 400, {"code": 1, "message": payload}
        arr = load_users() or []
        arr.append(payload)
        save_users(arr)
        return 200, {"code": 0, "data": {"id": payload["id"]}, "message": "创建成功"}

    def api_users_update(self, uid, data):
        u = self._user()
        if not is_admin(u):
            return 401, {"code": 401, "message": "无权限"}
        arr = load_users() or []
        target = next((x for x in arr if x.get("id") == uid), None)
        if not target:
            return 404, {"code": 1, "message": "人员不存在"}
        if is_super(target):
            return 400, {"code": 1, "message": "超级管理员不可编辑"}
        # 重名检测（排除自己）
        name = (data.get("name") or "").strip()
        dup = next((x for x in arr if x.get("name") == name and x.get("id") != uid), None)
        if dup:
            return 400, {"code": 1, "message": "该姓名已存在"}
        code, _ = self._build_user(data, arr, target)
        if code != 200:
            return 400, {"code": 1, "message": _}
        save_users(arr)
        return 200, {"code": 0, "data": {}, "message": "更新成功"}

    def api_users_delete(self, uid):
        u = self._user()
        if not is_admin(u):
            return 401, {"code": 401, "message": "无权限"}
        target = find_by_id(uid)
        if not target:
            return 404, {"code": 1, "message": "人员不存在"}
        if is_super(target):
            return 400, {"code": 1, "message": "超级管理员不可删除"}
        if target.get("id") == u.get("id"):
            return 400, {"code": 1, "message": "不能删除当前登录账号"}
        arr = [x for x in (load_users() or []) if x.get("id") != uid]
        save_users(arr)
        return 200, {"code": 0, "data": {}, "message": "删除成功"}

    # ---- 角色 ----
    def api_roles_list(self):
        u = self._user()
        if not u:
            return 401, {"code": 401, "message": "未授权"}
        return 200, {"code": 0, "data": load_roles(), "message": ""}

    def api_roles_create(self, data):
        u = self._user()
        if not is_admin(u):
            return 401, {"code": 401, "message": "无权限"}
        name = (data.get("name") or "").strip()
        if not name:
            return 400, {"code": 1, "message": "角色名称必填"}
        rid = (data.get("id") or "").strip() or ("r_" + secrets.token_hex(5))
        roles = load_roles()
        if any(r["id"] == rid for r in roles):
            return 400, {"code": 1, "message": "角色ID已存在"}
        perm_ids = [str(x) for x in (data.get("permIds") or []) if x]
        rec = {"id": rid, "name": name, "permIds": perm_ids,
               "needPassword": bool(data.get("needPassword", False)),
               "isAdmin": bool(data.get("isAdmin", False)),
               "remark": (data.get("remark") or "").strip(),
               "createTime": time.strftime("%Y-%m-%d %H:%M")}
        roles.append(rec); save_roles(roles)
        return 200, {"code": 0, "data": {"id": rid}, "message": "创建成功"}

    def api_roles_update(self, rid, data):
        u = self._user()
        if not is_admin(u):
            return 401, {"code": 401, "message": "无权限"}
        roles = load_roles()
        t = next((r for r in roles if r["id"] == rid), None)
        if not t:
            return 404, {"code": 1, "message": "角色不存在"}
        if (data.get("name") or "").strip():
            t["name"] = data["name"].strip()
        if "permIds" in data:
            t["permIds"] = [str(x) for x in (data["permIds"] or []) if x]
        if "needPassword" in data:
            t["needPassword"] = bool(data["needPassword"])
        if "isAdmin" in data:
            t["isAdmin"] = bool(data["isAdmin"])
        if "remark" in data:
            t["remark"] = (data["remark"] or "").strip()
        save_roles(roles)
        return 200, {"code": 0, "data": {}, "message": "更新成功"}

    def api_roles_delete(self, rid):
        u = self._user()
        if not is_admin(u):
            return 401, {"code": 401, "message": "无权限"}
        roles = load_roles()
        if not any(r["id"] == rid for r in roles):
            return 404, {"code": 1, "message": "角色不存在"}
        # 清理人员对该角色的引用与密码
        users = load_users() or []
        changed = False
        for x in users:
            if rid in x.get("roleIds", []):
                x["roleIds"] = [r for r in x["roleIds"] if r != rid]
                if rid in x.get("pw", {}):
                    del x["pw"][rid]
                changed = True
        if changed:
            save_users(users)
        save_roles([r for r in roles if r["id"] != rid])
        return 200, {"code": 0, "data": {}, "message": "删除成功"}

    # ---- 权限（网页级） ----
    def api_perms_list(self):
        u = self._user()
        if not u:
            return 401, {"code": 401, "message": "未授权"}
        return 200, {"code": 0, "data": load_perms(), "message": ""}

    def api_perms_create(self, data):
        u = self._user()
        if not is_admin(u):
            return 401, {"code": 401, "message": "无权限"}
        name = (data.get("name") or "").strip()
        if not name:
            return 400, {"code": 1, "message": "权限名称必填"}
        pid = (data.get("id") or "").strip() or ("p_" + secrets.token_hex(5))
        perms = load_perms()
        if any(p["id"] == pid for p in perms):
            return 400, {"code": 1, "message": "权限ID已存在"}
        rec = {"id": pid, "name": name, "page": (data.get("page") or "").strip(),
               "desc": (data.get("desc") or "").strip()}
        perms.append(rec); save_perms(perms)
        return 200, {"code": 0, "data": {"id": pid}, "message": "创建成功"}

    def api_perms_update(self, pid, data):
        u = self._user()
        if not is_admin(u):
            return 401, {"code": 401, "message": "无权限"}
        perms = load_perms()
        t = next((p for p in perms if p["id"] == pid), None)
        if not t:
            return 404, {"code": 1, "message": "权限不存在"}
        if (data.get("name") or "").strip():
            t["name"] = data["name"].strip()
        if "page" in data:
            t["page"] = (data["page"] or "").strip()
        if "desc" in data:
            t["desc"] = (data["desc"] or "").strip()
        save_perms(perms)
        return 200, {"code": 0, "data": {}, "message": "更新成功"}

    def api_perms_delete(self, pid):
        u = self._user()
        if not is_admin(u):
            return 401, {"code": 401, "message": "无权限"}
        perms = load_perms()
        if not any(p["id"] == pid for p in perms):
            return 404, {"code": 1, "message": "权限不存在"}
        # 从角色中移除该权限引用
        roles = load_roles()
        for r in roles:
            r["permIds"] = [x for x in r.get("permIds", []) if x != pid]
        save_roles(roles)
        save_perms([p for p in perms if p["id"] != pid])
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
            self._json(200, load_json(MODULES_FILE, [])); return
        if path == "/nav":
            self._json(200, load_nav()); return
        if path == "/api/auth/me":
            code, obj = self.api_auth_me(); self._json(code, obj); return
        if path == "/api/users":
            code, obj = self.api_users_list(); self._json(code, obj); return
        if path == "/api/roles":
            code, obj = self.api_roles_list(); self._json(code, obj); return
        if path == "/api/permissions":
            code, obj = self.api_perms_list(); self._json(code, obj); return
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
            u = self._user()
            if u is not None and not is_admin(u):
                self._json(403, {"ok": False, "error": "无权限"}); return
            data = self._body_json()
            arr = data.get("modules", [])
            if not isinstance(arr, list):
                self._json(400, {"ok": False, "error": "modules 必须是数组"}); return
            save_json(MODULES_FILE, arr)
            self._json(200, {"ok": True, "count": len(arr)}); return
        if path == "/nav":
            u = self._user()
            if not (u is not None and is_admin(u)):
                self._json(403, {"ok": False, "error": "无权限"}); return
            data = self._body_json()
            arr = data.get("nav") if isinstance(data, dict) else (data if isinstance(data, list) else None)
            if not isinstance(arr, list):
                self._json(400, {"ok": False, "error": "nav 必须是数组"}); return
            save_nav(arr)
            self._json(200, {"ok": True, "count": len(arr)}); return
        if path == "/api/auth/login":
            code, obj = self.api_auth_login(self._body_json()); self._json(code, obj); return
        if path == "/api/users":
            code, obj = self.api_users_create(self._body_json()); self._json(code, obj); return
        if path == "/api/roles":
            code, obj = self.api_roles_create(self._body_json()); self._json(code, obj); return
        if path == "/api/permissions":
            code, obj = self.api_perms_create(self._body_json()); self._json(code, obj); return
        self._json(404, {"code": 1, "message": "Not Found"})

    def _item_put_delete(self, method):
        path = urlparse(self.path).path
        m = re.match(r"^/api/users/([^/]+)$", path)
        if m:
            if method == "PUT":
                code, obj = self.api_users_update(m.group(1), self._body_json())
            else:
                code, obj = self.api_users_delete(m.group(1))
            self._json(code, obj); return True
        m = re.match(r"^/api/roles/([^/]+)$", path)
        if m:
            if method == "PUT":
                code, obj = self.api_roles_update(m.group(1), self._body_json())
            else:
                code, obj = self.api_roles_delete(m.group(1))
            self._json(code, obj); return True
        m = re.match(r"^/api/permissions/([^/]+)$", path)
        if m:
            if method == "PUT":
                code, obj = self.api_perms_update(m.group(1), self._body_json())
            else:
                code, obj = self.api_perms_delete(m.group(1))
            self._json(code, obj); return True
        return False

    def do_PUT(self):
        if not self._item_put_delete("PUT"):
            self._json(404, {"code": 1, "message": "Not Found"})

    def do_DELETE(self):
        if not self._item_put_delete("DELETE"):
            self._json(404, {"code": 1, "message": "Not Found"})

    def log_message(self, *a):
        pass

if __name__ == "__main__":
    migrate()   # 确保 roles/perms 存在并迁移旧用户
    os.chdir(ROOT)
    with ThreadingHTTPServer(("0.0.0.0", PORT), Handler) as httpd:
        print(f"客满工作台已启动： http://0.0.0.0:{PORT}/  (Ctrl+C 退出)")
        httpd.serve_forever()
