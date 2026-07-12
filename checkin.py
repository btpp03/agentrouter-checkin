#!/usr/bin/env python3
"""
AgentRouter 自动签到脚本
通过 SOCKS5 代理绕过阿里云 WAF，无需 Playwright 浏览器
"""

import base64
import json
import os
import sys
import time
from datetime import datetime

import httpx

# Telegram 通知配置
TG_BOT_TOKEN = os.getenv("TG_BOT_TOKEN", "")
TG_CHAT_ID = os.getenv("TG_CHAT_ID", "")

# 代理配置（从环境变量读取）
SOCKS5_PROXY = os.getenv("SOCKS5_PROXY", "")
# 签到账号配置（JSON 格式）
ACCOUNTS_JSON = os.getenv("AGENTROUTER_ACCOUNTS", "")

API_BASE = "https://agentrouter.org/console/api"
REPO_URL = "https://github.com/btpp03/agentrouter-checkin"


def send_tg_notification(message):
    """发送 Telegram 通知"""
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        return
    try:
        httpx.post(
            f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage",
            json={
                "chat_id": TG_CHAT_ID,
                "text": message,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            },
            timeout=10,
        )
    except Exception as e:
        print(f"[通知] ❌ Telegram 发送失败: {e}")


def decode_session(session_str):
    """尝试解码 session cookie，提取过期时间"""
    try:
        # NewAPI 的 session 可能是 JWT 格式
        parts = session_str.split(".")
        if len(parts) == 3:
            # JWT: header.payload.signature
            payload = parts[1]
            # 补全 base64 padding
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += "=" * padding
            decoded = base64.urlsafe_b64decode(payload)
            data = json.loads(decoded)
            if "exp" in data:
                exp_ts = data["exp"]
                remaining = exp_ts - time.time()
                if remaining > 0:
                    days = int(remaining // 86400)
                    hours = int((remaining % 86400) // 3600)
                    return f"{days}d {hours}h"
                return "已过期"
    except Exception:
        pass
    return "≈30天"


def get_proxy_client():
    """创建带代理的 httpx 客户端"""
    if SOCKS5_PROXY:
        return httpx.Client(
            proxy=SOCKS5_PROXY,
            http2=True,
            timeout=30.0,
            follow_redirects=True,
        )
    return httpx.Client(http2=True, timeout=30.0)


def get_waf_cookies(client):
    """通过访问首页获取 WAF cookies（走代理时不会被拦截）"""
    client.get("https://agentrouter.org/console/login")
    waf_cookies = {}
    for cookie in client.cookies:
        if cookie.name in ("acw_tc", "acw_sc__v2", "cdn_sec_tc"):
            waf_cookies[cookie.name] = cookie.value
    return waf_cookies


def get_session_str(cookies):
    """从不同格式的 cookies 中提取 session 值"""
    if isinstance(cookies, dict):
        return cookies.get("session", "")
    elif isinstance(cookies, str):
        for part in cookies.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                if k == "session":
                    return v
    return ""


def check_in(account):
    """对单个账号执行签到，返回 (是否成功, 账号名, 额度, 错误信息)"""
    name = account.get("name", "Account")
    cookies = account.get("cookies", {})
    api_user = account.get("api_user", "")

    if not api_user or not cookies:
        return False, name, 0, "缺少 api_user 或 cookies"

    session_cookie = get_session_str(cookies)
    if not session_cookie:
        return False, name, 0, "未找到 session cookie"

    # 解析 session 过期时间
    session_expiry = decode_session(session_cookie)

    client = get_proxy_client()

    try:
        client.cookies.set("session", session_cookie, domain="agentrouter.org")

        waf = get_waf_cookies(client)
        if waf:
            print(f"[{name}] ✅ WAF cookies: {list(waf.keys())}")

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Referer": "https://agentrouter.org/console/",
            "Origin": "https://agentrouter.org",
            "new-api-user": api_user,
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "application/json",
        }

        # 查询用户信息（获取额度）
        quota = 0
        quota_display = "未知"
        user_resp = client.get(f"{API_BASE}/user/self", headers=headers)
        if user_resp.status_code == 200:
            user_data = user_resp.json()
            if user_data.get("success") and user_data.get("data"):
                quota_raw = user_data["data"].get("quota", 0)
                # 通常 quota 以 500000 为单位换算成美元
                quota = round(quota_raw / 500000, 2) if quota_raw > 0 else 0
                quota_display = f"${quota}"
                print(f"[{name}] 💰 额度: {quota_display}")

        # 执行签到
        checkin_resp = client.post(
            f"{API_BASE}/user/sign_in",
            headers=headers,
            json={},
        )

        if checkin_resp.status_code == 200:
            result = checkin_resp.json()
            ret = result.get("ret", result.get("code", -1))
            msg = result.get("msg", result.get("message", ""))

            if ret == 1 or ret == 0 or result.get("success"):
                print(f"[{name}] ✅ 签到成功! {msg}")
                return True, name, quota_display, session_expiry
            else:
                print(f"[{name}] ❌ 签到失败: {msg}")
                return False, name, quota_display, msg
        else:
            err = f"HTTP {checkin_resp.status_code}"
            print(f"[{name}] ❌ {err}")
            return False, name, quota_display, err

    except Exception as e:
        print(f"[{name}] ❌ 异常: {e}")
        return False, name, 0, str(e)
    finally:
        client.close()


def main():
    print("=" * 50)
    print(f"🤖 AgentRouter 自动签到 - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 50)

    if not ACCOUNTS_JSON:
        print("❌ 未设置 AGENTROUTER_ACCOUNTS 环境变量")
        sys.exit(1)

    try:
        accounts = json.loads(ACCOUNTS_JSON)
    except json.JSONDecodeError as e:
        print(f"❌ AGENTROUTER_ACCOUNTS JSON 解析失败: {e}")
        sys.exit(1)

    if not isinstance(accounts, list):
        accounts = [accounts]

    if SOCKS5_PROXY:
        host = SOCKS5_PROXY.split("@")[-1] if "@" in SOCKS5_PROXY else SOCKS5_PROXY
        print(f"🔌 代理: {host}")
    else:
        print("⚠️  未配置代理，直接连接（可能被 WAF 拦截）")

    # 执行签到，收集每个账号的结果
    results = []
    for i, account in enumerate(accounts):
        print(f"\n--- 账号 {i+1} ---")
        ok, name, quota, extra = check_in(account)
        results.append((ok, name, quota, extra))

    success_count = sum(1 for r in results if r[0])

    # 构建 TG 通知
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    emoji = "✅" if success_count == len(accounts) else "⚠️"

    tg_lines = [f"{emoji} <b>AgentRouter 签到</b>"]
    tg_lines.append(f"🕐 {now}")
    tg_lines.append("")

    for ok, name, quota, extra in results:
        icon = "✅" if ok else "❌"
        status = "签到成功" if ok else f"失败: {extra}"
        tg_lines.append(f"{icon} <b>{name}</b>")
        tg_lines.append(f"   💰 额度: {quota}")
        tg_lines.append(f"   🔑 Session: {extra}")
        tg_lines.append(f"   📌 {status}")
        tg_lines.append("")

    tg_lines.append(f"📊 <b>{success_count}/{len(accounts)}</b> 账号签到成功")
    tg_lines.append(f"🔗 <a href='{REPO_URL}'>GitHub 仓库</a>")

    tg_msg = "\n".join(tg_lines)
    print(f"\n{'=' * 50}")
    print(f"📊 结果: {success_count}/{len(accounts)} 成功")
    print(f"{'=' * 50}")
    send_tg_notification(tg_msg)

    if success_count < len(accounts):
        sys.exit(1)


if __name__ == "__main__":
    main()