# AgentRouter 自动签到

轻量版 AgentRouter 每日签到脚本，通过 SOCKS5 代理绕过阿里云 WAF，无需 Playwright 浏览器。

## 特点

- 🚀 **轻量** — 只需 `httpx`，无需 Playwright/Chromium
- 🔌 **代理绕 WAF** — 使用 SOCKS5 代理绕过阿里云验证码
- 👥 **多账号** — 支持多个账号同时签到
- ⏰ **自动** — GitHub Actions 每 6 小时自动执行

## 使用方法

### 1. Fork 本仓库

点击右上角 Fork 按钮。

### 2. 获取签到信息

1. 打开浏览器，访问 [https://agentrouter.org/console](https://agentrouter.org/console)
2. 登录你的账号
3. 按 F12 打开开发者工具
4. 切换到 **Application** → **Cookies** → `agentrouter.org`
5. 复制 `session` 的值
6. 切换到 **Network** 标签，刷新页面
7. 找一个 API 请求，在请求头里找到 `new-api-user` 的值（一般是 5 位数字）

### 3. 配置 GitHub Secrets

在仓库的 **Settings** → **Secrets and variables** → **Actions** → **New repository secret** 中添加：

| Secret 名称 | 说明 |
|---|---|
| `AGENTROUTER_ACCOUNTS` | 账号配置 JSON（见下方） |
| `SOCKS5_PROXY` | SOCKS5 代理地址，如 `socks5://user:pass@host:port` |
| `TG_BOT_TOKEN` | Telegram Bot Token（可选，用于通知） |
| `TG_CHAT_ID` | Telegram Chat ID（可选，用于通知） |

**AGENTROUTER_ACCOUNTS 格式：**

单个账号：
```json
{
  "cookies": {"session": "你的session值"},
  "api_user": "你的api_user",
  "name": "主账号"
}
```

多个账号：
```json
[
  {
    "cookies": {"session": "账号1的session"},
    "api_user": "账号1的api_user",
    "name": "账号1"
  },
  {
    "cookies": {"session": "账号2的session"},
    "api_user": "账号2的api_user",
    "name": "账号2"
  }
]
```

### 4. 启用 Actions

- 进入 **Actions** 标签页
- 找到 **AgentRouter 自动签到** workflow
- 点击 **Enable workflow**
- 可以点 **Run workflow** 手动测试一次

### 5. 查看结果

每次执行后，在 Actions 页面查看运行日志。

## 注意事项

- Session 有效期约 1 个月，失效后需重新获取
- 签到频率每 6 小时一次（实际有 1h 左右延迟）
- 签到按 24h 重置，不是零点重置