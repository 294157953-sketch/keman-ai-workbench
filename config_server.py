#!/usr/bin/env python3
# 客满中心 AI 应用统一工作台 —— 增强版服务端
# 同一进程同时托管：网页(index.html) + 配置接口(/modules)
# 关键点：网页与 /modules 同源(同一 host:port)，浏览器不再触发"混合内容"拦截，
#         因此"打开即拉取 / 保存即推送 / 增删改全员实时一致"全部生效。
# 用法：
#   python3 config_server.py
# 访问： http://<服务器IP>:8080/   （全员用这个地址）
import json, os, socketserver
from urllib.parse import urlparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 8080
ROOT = os.path.dirname(os.path.abspath(__file__))
MODULES_FILE = os.path.join(ROOT, "modules.json")
CORS = {"Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type"}

def load_modules():
    if os.path.exists(MODULES_FILE):
        try:
            return json.load(open(MODULES_FILE, encoding="utf-8"))
        except Exception:
            return []
    return []

def save_modules(arr):
    with open(MODULES_FILE, "w", encoding="utf-8") as f:
        json.dump(arr, f, ensure_ascii=False, indent=2)

_EXT = {".html":"text/html; charset=utf-8",".png":"image/png",".jpg":"image/jpeg",
        ".jpeg":"image/jpeg",".css":"text/css",".js":"application/javascript",
        ".json":"application/json",".svg":"image/svg+xml",".ico":"image/x-icon"}

class Handler(BaseHTTPRequestHandler):
    def _send(self, code, ctype, body, cors=True):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        if cors:
            for k, v in CORS.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self):
        self._send(204, "text/plain", b"")

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
            self._send(200, "application/json; charset=utf-8",
                       json.dumps(load_modules(), ensure_ascii=False))
            return
        # 静态文件（图片等）
        fp = os.path.normpath(os.path.join(ROOT, path.lstrip("/")))
        if fp.startswith(ROOT) and os.path.isfile(fp):
            self._send(200, _EXT.get(os.path.splitext(fp)[1], "application/octet-stream"),
                       open(fp, "rb").read())
        else:
            self._send(404, "text/plain", "Not Found")

    def do_POST(self):
        path = urlparse(self.path).path
        if path != "/modules":
            self._send(404, "text/plain", "Not Found"); return
        try:
            n = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(n)
            data = json.loads(raw)
            arr = data.get("modules", [])
            if not isinstance(arr, list):
                raise ValueError("modules 必须是数组")
            save_modules(arr)
            self._send(200, "application/json; charset=utf-8",
                       json.dumps({"ok": True, "count": len(arr)}, ensure_ascii=False))
        except Exception as e:
            self._send(400, "application/json; charset=utf-8",
                       json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False))

    def log_message(self, *a):
        pass

if __name__ == "__main__":
    os.chdir(ROOT)
    with ThreadingHTTPServer(("0.0.0.0", PORT), Handler) as httpd:
        print(f"客满工作台已启动： http://0.0.0.0:{PORT}/  (Ctrl+C 退出)")
        httpd.serve_forever()
