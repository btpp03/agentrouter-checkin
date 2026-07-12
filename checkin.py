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
        name = getattr(cookie, "name", None)
        value = getattr(cookie, "value", None)
        if name is None and isinstance(cookie, str):
            # httpx 代理模式下 cookies 可能是字符串
            continue
        if name in ("acw_tc", "acw_sc__v2", "cdn_sec_tc"):
            waf_cookies[name] = value
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
    """对单个账号执行签到，返回 (是否成功, 账号名, 原始额度, 错误/session过期, 获得额度, 签到后额度)"""
    name = account.get("name", "Account")
    cookies = account.get("cookies", {})
    api_user = account.get("api_user", "")

    if not api_user or not cookies:
        return False, name, 0, "缺少 api_user 或 cookies", 0, 0

    session_cookie = get_session_str(cookies)
    if not session_cookie:
        return False, name, 0, "未找到 session cookie", 0, 0

    # 解析 session 过期时间
    session_expiry = decode_session(session_cookie)

    client = get_proxy_client()

    try:
        # 先拿 WAF cookie（通过代理不会被拦）
        waf_session = httpx.Client(proxy=SOCKS5_PROXY, http2=True, timeout=15.0) if SOCKS5_PROXY else httpx.Client(http2=True, timeout=15.0)
        try:
            waf_resp = waf_session.get("https://agentrouter.org/console/login", follow_redirects=True)
            acw_tc_val = ""
            for c in waf_session.cookies:
                if c.name == "acw_tc":
                    acw_tc_val = c.value
                    break
            if acw_tc_val:
                print(f"[{name}] ✅ 获取到 acw_tc cookie")
        except Exception:
            acw_tc_val = ""
        finally:
            waf_session.close()

        # 构建 Cookie 头
        cookie_header = f"session={session_cookie}"
        if acw_tc_val:
            cookie_header += f"; acw_tc={acw_tc_val}"

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Referer": "https://agentrouter.org/console/",
            "Origin": "https://agentrouter.org",
            "Cookie": cookie_header,
            "new-api-user": api_user,
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "application/json",
        }

        # 查询用户信息（获取额度）
        quota_raw = 0
        user_resp = client.get(f"{API_BASE}/user/self", headers=headers)
        print(f"[{name}] 🔍 user/self → HTTP {user_resp.status_code}, body[:200]: {user_resp.text[:200]}")
        if user_resp.status_code == 200:
            try:
                user_data = user_resp.json()
            except json.JSONDecodeError:
                print(f"[{name}] ⚠️ user/self 返回非 JSON: {user_resp.text[:200]}")
                user_data = {}
            if user_data.get("success") and user_data.get("data"):
                quota_raw = user_data["data"].get("quota", 0)
                quota_display = f"${round(quota_raw/500000, 2)}" if quota_raw > 0 else "$0"
                print(f"[{name}] 💰 当前额度: {quota_display}")

        # 执行签到
        checkin_resp = client.post(
            f"{API_BASE}/user/sign_in",
            headers=headers,
            json={},
        )
        print(f"[{name}] 🔍 sign_in → HTTP {checkin_resp.status_code}, body[:200]: {checkin_resp.text[:200]}")

        earned = 0
        after_quota_raw = 0

        if checkin_resp.status_code == 200:
            try:
                result = checkin_resp.json()
            except json.JSONDecodeError:
                print(f"[{name}] ⚠️ sign_in 返回非 JSON: {checkin_resp.text[:200]}")
                result = {}
            ret = result.get("ret", result.get("code", -1))
            msg = result.get("msg", result.get("message", ""))

            # 解析签到数据
            data = result.get("data", {})
            if data:
                earned = data.get("quota", 0)
                after_quota_raw = quota_raw + earned

            if ret == 1 or ret == 0 or result.get("success"):
                earned_display = f"${round(earned/500000, 2)}" if earned else "?"
                print(f"[{name}] ✅ 签到成功! +{earned_display}")
                return True, name, quota_raw, session_expiry, earned, after_quota_raw
            else:
                print(f"[{name}] ❌ 签到失败: {msg}")
                return False, name, quota_raw, msg, 0, quota_raw
        else:
            err = f"HTTP {checkin_resp.status_code}"
            print(f"[{name}] ❌ {err}")
            return False, name, quota_raw, err, 0, quota_raw

    except Exception as e:
        print(f"[{name}] ❌ 异常: {e}")
        import traceback
        traceback.print_exc()
        return False, name, 0, str(e), 0, 0
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
        ok, name, quota_raw, extra, earned, after_raw = check_in(account)
        results.append((ok, name, quota_raw, extra, earned, after_raw))

    success_count = sum(1 for r in results if r[0])

    # 构建 TG 通知
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    emoji = "✅" if success_count == len(accounts) else "⚠️"

    tg_lines = [f"{emoji} AgentRouter 签到通知"]
    tg_lines.append("")

    for ok, name, quota_raw, extra, earned, after_raw in results:
        before_display = f"${round(quota_raw/500000, 2)}"
        earned_display = f"${round(earned/500000, 2)}" if earned else "$0"
        after_display = f"${round(after_raw/500000, 2)}"

        icon = "✅" if ok else "❌"
        tg_lines.append(f"{icon} 签到{'成功' if ok else '失败'}" + (f",本次签到获得{earned_display}" if ok else f": {extra}"))
        tg_lines.append(f"👤 登录账户: {name}")
        tg_lines.append(f"💰 昨日余额: {before_display}")
        tg_lines.append(f"💰 当前余额: {after_display}")
        tg_lines.append(f"🔑 Session: {extra}")
        tg_lines.append(f"⏱️ 签到时间: {now}")
        tg_lines.append("")

    tg_lines.append(f"📊 {success_count}/{len(accounts)} 账号签到成功")
    tg_lines.append(f"🔗 {REPO_URL}")

    tg_msg = "\n".join(tg_lines)
    print(f"\n{'=' * 50}")
    print(f"📊 结果: {success_count}/{len(accounts)} 成功")
    print(f"{'=' * 50}")
    send_tg_notification(tg_msg)

    if success_count < len(accounts):
        sys.exit(1)


if __name__ == "__main__":
    main()