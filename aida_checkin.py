#!/usr/bin/env python3
"""
Aida Mochi Hosting 自动续期脚本
无需 Selenium/Playwright，使用 Better Auth session cookie 直调 API
依赖: curl + Python 3 标准库
"""

import base64
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import urllib.parse
from datetime import datetime

# ============ 配置 ============
AIDA_SESSION_TOKEN = os.getenv("AIDA_SESSION_TOKEN", "")
TG_BOT_TOKEN = os.getenv("TG_BOT_TOKEN", "")
TG_CHAT_ID = os.getenv("TG_CHAT_ID", "")
SOCKS5_PROXY = os.getenv("SOCKS5_PROXY", "")

AUTH_ISSUER = "https://auth.aida0710.work/api/auth"
API_BASE = "https://hosting.aida0710.work/api"
CLIENT_ID = "mochi-portal"
REDIRECT_URI = "https://hosting.aida0710.work/auth/callback"
REPO_URL = "https://github.com/btpp03/agentrouter-checkin/blob/main/aida_checkin.py"


def send_tg(message):
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        print("[TG] ⚠️ 未配置 TG_BOT_TOKEN 或 TG_CHAT_ID")
        return
    try:
        data = json.dumps({
            "chat_id": TG_CHAT_ID, "text": message,
            "parse_mode": "HTML", "disable_web_page_preview": True,
        })
        r = subprocess.run(
            ["curl", "-s", "-X", "POST",
             f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage",
             "-H", "Content-Type: application/json", "-d", data,
             "--max-time", "10"],
            capture_output=True, text=True, timeout=15)
        if r.returncode != 0:
            print(f"[TG] ❌ curl 失败: {r.stderr}")
        elif '"ok":false' in r.stdout:
            print(f"[TG] ❌ API 错误: {r.stdout[:200]}")
        else:
            print(f"[TG] ✅ 通知已发送")
    except Exception as e:
        print(f"[TG] ❌ 异常: {e}")


def _curl(args, timeout=35):
    """Run curl, return (stdout_lines, returncode)"""
    cmd = ["curl", "-s", "--max-time", str(timeout)]
    if SOCKS5_PROXY:
        cmd.extend(["--socks5-hostname", SOCKS5_PROXY])
    cmd.extend(args)
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
    return r.stdout, r.stderr, r.returncode


def curl_get(url, headers=None, cookies=None, include_headers=False):
    """GET request"""
    args = []
    if include_headers:
        args.extend(["-D", "-"])
    if headers:
        for k, v in headers.items():
            args.extend(["-H", f"{k}: {v}"])
    if cookies:
        args.extend(["-H", f"Cookie: {'; '.join(f'{k}={v}' for k, v in cookies.items())}"])
    args.append(url)
    return _curl(args)


def curl_post(url, data, headers=None):
    """POST request with form data"""
    args = ["-X", "POST"]
    if headers:
        for k, v in headers.items():
            args.extend(["-H", f"{k}: {v}"])
    args.extend(["-d", data, url])
    return _curl(args)


def generate_pkce():
    v = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    d = hashlib.sha256(v.encode()).digest()
    return v, base64.urlsafe_b64encode(d).decode().rstrip("=")


def get_auth_code(session_token, code_challenge):
    """OIDC silent auth → auth code"""
    params = urllib.parse.urlencode({
        "response_type": "code", "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI, "prompt": "none",
        "scope": "openid profile email offline_access",
        "code_challenge": code_challenge, "code_challenge_method": "S256",
    })
    headers = {"Cookie": f"__Secure-better-auth.session_token={session_token}"}
    out, err, rc = curl_get(f"{AUTH_ISSUER}/oauth2/authorize?{params}",
                            headers=headers, include_headers=True)

    # Location header could be in stdout (headers) or stderr
    m = re.search(r"^location:\s*(.*)$", out, re.I | re.M)
    if not m:
        m = re.search(r"^location:\s*(.*)$", err, re.I | re.M)
    if not m:
        return None
    code_m = re.search(r"code=([^&\s]+)", m.group(1))
    return code_m.group(1) if code_m else None


def exchange_token(code, code_verifier):
    """Auth code → id_token"""
    data = (f"grant_type=authorization_code&code={code}"
            f"&redirect_uri={REDIRECT_URI}&client_id={CLIENT_ID}"
            f"&code_verifier={code_verifier}")
    out, err, rc = curl_post(f"{AUTH_ISSUER}/oauth2/token", data,
                             headers={"Content-Type": "application/x-www-form-urlencoded"})
    # Check if output is JSON (might have headers before)
    try:
        return json.loads(out).get("id_token", "")
    except json.JSONDecodeError:
        # Try to parse from the JSON part
        m = re.search(r"\{.*\}", out, re.DOTALL)
        if m:
            return json.loads(m.group()).get("id_token", "")
        return None


def get_id_token():
    v, c = generate_pkce()
    code = get_auth_code(AIDA_SESSION_TOKEN, c)
    if not code:
        return None
    return exchange_token(code, v)


def api_call(method, path, auth_token, body=None):
    """Generic API call, returns (body, http_code)"""
    args = ["-w", "\n%{http_code}"]
    if method != "GET":
        args.extend(["-X", method])
    args.extend(["-H", f"Authorization: Bearer {auth_token}"])
    if body is not None:
        args.extend(["-H", "Content-Type: application/json", "-d", body])
    args.append(f"{API_BASE}{path}")

    out, err, rc = _curl(args)
    parts = out.strip().rsplit("\n", 1)
    body = parts[0] if len(parts) == 2 else out
    code = int(parts[1]) if len(parts) == 2 else 0
    return body, code


def main():
    dt = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("=" * 50)
    print(f"🇯🇵 Aida 自动续期 - {dt}")
    print("=" * 50)

    if not AIDA_SESSION_TOKEN:
        print("❌ 未设置 AIDA_SESSION_TOKEN")
        sys.exit(1)

    if SOCKS5_PROXY:
        host = SOCKS5_PROXY.split("@")[-1] if "@" in SOCKS5_PROXY else SOCKS5_PROXY
        print(f"🔌 代理: {host}")

    print("🔄 获取 ID Token...")
    id_token = get_id_token()
    if not id_token:
        msg = "❌ Aida 续期失败: session 已过期"
        print(msg)
        send_tg(msg)
        sys.exit(1)
    print("✅ Token 获取成功")

    # 获取服务器
    body, code = api_call("GET", "/servers", id_token)
    if code != 200:
        msg = f"❌ Aida 续期失败: 无法获取服务器列表 (HTTP {code})"
        print(msg)
        send_tg(msg)
        sys.exit(1)

    servers = json.loads(body)
    total = len(servers)
    print(f"📦 找到 {total} 个服务器")

    results = []
    for srv in servers:
        name = srv.get("name", "?")
        sid = srv.get("id", "")
        status = srv.get("status", "?")
        print(f"\n📦 {name} ({sid[:8]}...) [{status}]")

        # 获取状态
        sbody, scode = api_call("GET", f"/servers/{sid}/stats", id_token)
        if scode == 200:
            s = json.loads(sbody)
            print(f"   📊 CPU: {s.get('cpuPercent','?')}% 内存: {s.get('memoryUsageMB','?')}MB")

        # 续期
        rbody, rcode = api_call("POST", f"/servers/{sid}/extend-uptime", id_token, body="{}")
        if rcode == 200:
            print(f"   ✅ 续期成功!")
            results.append((name, True, status))
        else:
            err = rbody[:150] if rbody else f"HTTP {rcode}"
            print(f"   ❌ {err}")
            results.append((name, False, err))

    # Telegram 通知
    ok = sum(1 for r in results if r[1])
    lines = ["🇯🇵 Aida 续期通知", ""]
    for name, success, extra in results:
        icon = "✅" if success else "❌"
        lines.append(f"{icon} [{name}] {'续期成功' if success else f'失败: {extra}'}")
    lines.append("")
    lines.append(f"📊 {ok}/{total} 成功")
    lines.append(f"⏱️ {dt}")
    lines.append(f"🔗 {REPO_URL}")

    msg = "\n".join(lines)
    print(f"\n{'=' * 50}")
    print(f"📊 {ok}/{total} 成功")
    print("=" * 50)
    send_tg(msg)

    if ok < total:
        sys.exit(1)


if __name__ == "__main__":
    main()