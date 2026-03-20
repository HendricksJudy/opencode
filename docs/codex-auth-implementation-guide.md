# OpenCode Codex Auth 实现调查文档

## 概述

本文档详细分析 OpenCode 中 Codex Auth（OpenAI ChatGPT OAuth 认证）的完整实现，供在其他项目中复用参考。

Codex Auth 允许用户通过 ChatGPT Pro/Plus 订阅使用 OpenAI 的 Codex 模型，无需单独的 API Key。核心流程是标准的 OAuth 2.0 Authorization Code + PKCE，附加了 Device Flow 作为 headless 环境的备选方案。

---

## 架构总览

```
┌─────────────────────────────────────────────────────────┐
│                     Plugin 系统                          │
│  plugin/index.ts → 加载 CodexAuthPlugin                  │
│  plugin/codex.ts → 核心实现（OAuth、Token、Fetch 拦截）     │
├─────────────────────────────────────────────────────────┤
│                     Auth 存储层                           │
│  auth/effect.ts  → Effect Schema 定义 + 文件读写          │
│  auth/index.ts   → Zod Schema + 公共异步 API             │
│  存储位置: ~/.opencode/data/auth.json (权限 0o600)        │
├─────────────────────────────────────────────────────────┤
│                     Provider Auth 服务                    │
│  provider/auth-service.ts → 统一 auth 方法管理 + callback  │
│  provider/auth.ts         → 公共命名空间                  │
└─────────────────────────────────────────────────────────┘
```

---

## 1. 核心常量与配置

```typescript
const CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
const ISSUER = "https://auth.openai.com"
const CODEX_API_ENDPOINT = "https://chatgpt.com/backend-api/codex/responses"
const OAUTH_PORT = 1455  // 本地 OAuth 回调服务器端口
const OAUTH_POLLING_SAFETY_MARGIN_MS = 3000  // Device Flow 轮询安全间隔
```

**说明：**
- `CLIENT_ID` 是在 OpenAI 注册的 OAuth 应用 ID
- `ISSUER` 是 OpenAI 的 OAuth 授权服务器
- `CODEX_API_ENDPOINT` 是最终 API 请求目标，所有模型调用都重写到此 URL
- 本地回调服务器监听 `localhost:1455`

---

## 2. PKCE 实现 (RFC 7636)

PKCE（Proof Key for Code Exchange）防止授权码被拦截攻击。

```typescript
// 生成 PKCE 验证器和挑战码
async function generatePKCE(): Promise<{ verifier: string; challenge: string }> {
  // 1. 生成 43 字符随机字符串作为 verifier
  const verifier = generateRandomString(43)
  // 字符集: A-Z a-z 0-9 - . _ ~

  // 2. 对 verifier 做 SHA-256 哈希
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))

  // 3. Base64URL 编码哈希值作为 challenge
  const challenge = base64UrlEncode(hash)
  // base64url: 标准 base64 中 + → -, / → _, 去掉尾部 =

  return { verifier, challenge }
}
```

**要点：**
- 使用 `crypto.subtle` (Web Crypto API)，浏览器和 Node/Bun 都支持
- `code_challenge_method` 必须是 `S256`
- verifier 保存在内存中，仅在 token exchange 时发送

---

## 3. OAuth 2.0 Authorization Code Flow（浏览器方式）

### 3.1 构建授权 URL

```typescript
function buildAuthorizeUrl(redirectUri: string, pkce: PkceCodes, state: string): string {
  const params = new URLSearchParams({
    response_type: "code",
    client_id: CLIENT_ID,                    // OAuth 客户端 ID
    redirect_uri: redirectUri,                // http://localhost:1455/auth/callback
    scope: "openid profile email offline_access",  // 请求的权限范围
    code_challenge: pkce.challenge,           // PKCE challenge
    code_challenge_method: "S256",            // SHA-256 方法
    id_token_add_organizations: "true",       // 返回组织信息（用于提取 account_id）
    codex_cli_simplified_flow: "true",        // OpenAI 特定：简化登录流程
    state,                                    // CSRF 防护随机值
    originator: "opencode",                   // 标识请求来源
  })
  return `${ISSUER}/oauth/authorize?${params.toString()}`
}
```

**scope 说明：**
- `openid` – 启用 OpenID Connect
- `profile` – 获取用户资料
- `email` – 获取邮箱
- `offline_access` – 获取 refresh_token 以支持离线刷新

### 3.2 本地 OAuth 回调服务器

使用 Bun 内置 HTTP 服务器监听回调：

```typescript
async function startOAuthServer(): Promise<{ port: number; redirectUri: string }> {
  oauthServer = Bun.serve({
    port: OAUTH_PORT,  // 1455
    fetch(req) {
      const url = new URL(req.url)

      if (url.pathname === "/auth/callback") {
        // 1. 检查 error 参数
        // 2. 检查 code 是否存在
        // 3. 验证 state 匹配（防 CSRF）
        // 4. 用 code 换取 tokens
        // 5. 返回成功 HTML 页面（2秒后自动关闭）
      }

      if (url.pathname === "/cancel") {
        // 取消登录
      }

      return new Response("Not found", { status: 404 })
    },
  })
}
```

**关键安全检查：**
- `state` 验证：回调中的 state 必须匹配发起请求时生成的 state，否则拒绝（防 CSRF）
- 超时机制：5 分钟无回调则超时失败

### 3.3 完整浏览器 OAuth 流程

```
用户选择 "ChatGPT Pro/Plus (browser)"
    │
    ├─► 启动本地 HTTP 服务器 (localhost:1455)
    ├─► 生成 PKCE (verifier + challenge)
    ├─► 生成随机 state
    ├─► 构建授权 URL
    ├─► 打开浏览器访问授权 URL
    │
    │   [用户在浏览器中登录 ChatGPT 并授权]
    │
    ├─► OpenAI 重定向到 localhost:1455/auth/callback?code=xxx&state=yyy
    ├─► 验证 state
    ├─► 用 code + verifier 换取 tokens
    ├─► 从 id_token/access_token 中提取 account_id
    ├─► 保存到 auth.json
    └─► 关闭服务器
```

---

## 4. Device Flow（Headless 方式）

适用于无浏览器的环境（如 SSH 远程服务器）。

### 4.1 流程

```
用户选择 "ChatGPT Pro/Plus (headless)"
    │
    ├─► POST https://auth.openai.com/api/accounts/deviceauth/usercode
    │   Body: { client_id: CLIENT_ID }
    │   响应: { device_auth_id, user_code, interval }
    │
    ├─► 显示 URL: https://auth.openai.com/codex/device
    │   显示 code: XXXX-XXXX （让用户在另一台设备上输入）
    │
    │   [轮询等待用户完成授权]
    │
    ├─► POST https://auth.openai.com/api/accounts/deviceauth/token
    │   Body: { device_auth_id, user_code }
    │   ├─ 403/404 → 用户尚未完成，继续轮询（间隔 = max(server_interval, 1s) + 3s 安全余量）
    │   └─ 200 → 返回 { authorization_code, code_verifier }
    │
    ├─► POST https://auth.openai.com/oauth/token
    │   用 authorization_code + code_verifier 换取最终 tokens
    │   redirect_uri: https://auth.openai.com/deviceauth/callback
    │
    ├─► 从 tokens 中提取 account_id
    └─► 保存到 auth.json
```

**要点：**
- Device flow 不需要本地服务器
- 轮询间隔遵循服务端返回的 `interval` 字段，额外加 3 秒安全余量
- `code_verifier` 由服务端生成并返回（与浏览器 PKCE 不同）
- redirect_uri 是 OpenAI 托管的 `https://auth.openai.com/deviceauth/callback`

---

## 5. Token 管理

### 5.1 Token Exchange（授权码换 Token）

```typescript
async function exchangeCodeForTokens(
  code: string,
  redirectUri: string,
  pkce: PkceCodes
): Promise<TokenResponse> {
  const response = await fetch(`${ISSUER}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: CLIENT_ID,
      code_verifier: pkce.verifier,  // PKCE 验证器
    }).toString(),
  })
  return response.json()
  // 返回: { id_token, access_token, refresh_token, expires_in }
}
```

### 5.2 Token Refresh（刷新 Token）

```typescript
async function refreshAccessToken(refreshToken: string): Promise<TokenResponse> {
  const response = await fetch(`${ISSUER}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: CLIENT_ID,
    }).toString(),
  })
  return response.json()
}
```

### 5.3 Token 数据结构

```typescript
interface TokenResponse {
  id_token: string       // JWT，包含用户身份信息
  access_token: string   // JWT，用于 API 调用
  refresh_token: string  // 用于刷新 access_token
  expires_in?: number    // 过期时间（秒），默认 3600
}
```

---

## 6. JWT 解析与 Account ID 提取

### 6.1 JWT 解析

```typescript
function parseJwtClaims(token: string): IdTokenClaims | undefined {
  const parts = token.split(".")
  if (parts.length !== 3) return undefined
  return JSON.parse(Buffer.from(parts[1], "base64url").toString())
}
```

### 6.2 Account ID 提取（三个可能位置）

```typescript
interface IdTokenClaims {
  chatgpt_account_id?: string
  organizations?: Array<{ id: string }>
  email?: string
  "https://api.openai.com/auth"?: {
    chatgpt_account_id?: string
  }
}

function extractAccountIdFromClaims(claims: IdTokenClaims): string | undefined {
  return (
    claims.chatgpt_account_id ||                                  // 位置1: 顶级字段
    claims["https://api.openai.com/auth"]?.chatgpt_account_id ||  // 位置2: 嵌套在命名空间下
    claims.organizations?.[0]?.id                                 // 位置3: 组织列表的第一个
  )
}

// 提取优先级: id_token > access_token
function extractAccountId(tokens: TokenResponse): string | undefined {
  if (tokens.id_token) {
    const claims = parseJwtClaims(tokens.id_token)
    const accountId = claims && extractAccountIdFromClaims(claims)
    if (accountId) return accountId
  }
  if (tokens.access_token) {
    const claims = parseJwtClaims(tokens.access_token)
    return claims ? extractAccountIdFromClaims(claims) : undefined
  }
  return undefined
}
```

**为什么需要 Account ID：**
- 用于设置 `ChatGPT-Account-Id` 请求头
- OpenAI 通过此 header 确认用户的 ChatGPT 订阅（Pro/Plus）
- 支持组织级别的订阅关联

---

## 7. Auth 持久化存储

### 7.1 存储位置

```
~/.opencode/data/auth.json
```

文件权限 `0o600`（仅所有者可读写），防止其他用户访问敏感 token。

### 7.2 数据结构（三种认证类型）

```typescript
// OAuth 认证（Codex 使用此类型）
{
  type: "oauth",
  refresh: string,          // refresh_token
  access: string,           // access_token
  expires: number,          // 过期时间戳 (ms)
  accountId?: string,       // ChatGPT Account ID
  enterpriseUrl?: string    // 企业版 URL（可选）
}

// API Key 认证
{
  type: "api",
  key: string               // API Key
}

// WellKnown 认证
{
  type: "wellknown",
  key: string,
  token: string
}
```

### 7.3 存储 API

```typescript
// 按 provider ID 存取
await Auth.get("openai")              // 读取
await Auth.set("openai", authInfo)    // 写入
await Auth.remove("openai")           // 删除
await Auth.all()                      // 读取全部
```

**Key 规范化：** 写入时会去掉 key 尾部的 `/`，并清理可能的重复条目（有/无尾部斜杠的版本）。

### 7.4 OAUTH_DUMMY_KEY

```typescript
export const OAUTH_DUMMY_KEY = "opencode-oauth-dummy-key"
```

OAuth 模式下无真实 API Key，但 AI SDK 框架要求提供一个 apiKey。这个占位值会在自定义 fetch 中被移除，替换为 Bearer token。

---

## 8. 请求拦截与 URL 重写

核心的 fetch 拦截器，实现 3 个功能：

```typescript
async fetch(requestInput: RequestInfo | URL, init?: RequestInit) {
  // ① 移除 dummy API key 的 Authorization header
  // 支持 Headers 对象、数组、普通对象三种格式
  if (init?.headers) {
    // delete authorization/Authorization from all header formats
  }

  // ② 自动刷新过期 token
  if (!currentAuth.access || currentAuth.expires < Date.now()) {
    const tokens = await refreshAccessToken(currentAuth.refresh)
    // 保存新 token 到 auth.json
    // 更新内存中的 access token
  }

  // ③ 设置正确的请求头
  headers.set("authorization", `Bearer ${currentAuth.access}`)
  if (authWithAccount.accountId) {
    headers.set("ChatGPT-Account-Id", authWithAccount.accountId)
  }

  // ④ URL 重写: 将 /v1/responses 或 /chat/completions 重写到 Codex 端点
  const url = parsed.pathname.includes("/v1/responses") ||
              parsed.pathname.includes("/chat/completions")
    ? new URL("https://chatgpt.com/backend-api/codex/responses")
    : parsed

  return fetch(url, { ...init, headers })
}
```

**关键设计：**
- 拦截所有到 OpenAI 的请求
- 自动处理 token 过期和刷新（对上层透明）
- URL 重写确保请求发送到 ChatGPT 的 Codex API（而非标准 OpenAI API）

---

## 9. 模型过滤与注册

### 9.1 OAuth 模式下的模型白名单

```typescript
const allowedModels = new Set([
  "gpt-5.1-codex",
  "gpt-5.1-codex-max",
  "gpt-5.1-codex-mini",
  "gpt-5.2",
  "gpt-5.2-codex",
  "gpt-5.3-codex",
  "gpt-5.4",
  "gpt-5.4-mini",
])

// 删除不在白名单中的非 codex 模型
for (const modelId of Object.keys(provider.models)) {
  if (modelId.includes("codex")) continue
  if (allowedModels.has(modelId)) continue
  delete provider.models[modelId]
}
```

### 9.2 动态注册模型

如果 `gpt-5.3-codex` 不存在，插件会动态注册：

```typescript
const model = {
  id: "gpt-5.3-codex",
  providerID: "openai",
  api: {
    id: "gpt-5.3-codex",
    url: "https://chatgpt.com/backend-api/codex",
    npm: "@ai-sdk/openai",
  },
  name: "GPT-5.3 Codex",
  capabilities: {
    temperature: false,
    reasoning: true,
    attachment: true,
    toolcall: true,
    input: { text: true, image: true },
    output: { text: true },
  },
  cost: { input: 0, output: 0, cache: { read: 0, write: 0 } },
  limit: { context: 400_000, input: 272_000, output: 128_000 },
}
```

### 9.3 成本清零

所有 Codex 模型的费用设为 0（包含在 ChatGPT 订阅中）：

```typescript
for (const model of Object.values(provider.models)) {
  model.cost = { input: 0, output: 0, cache: { read: 0, write: 0 } }
}
```

---

## 10. 请求头注入

对所有 OpenAI provider 的请求，额外注入以下 headers：

```typescript
"chat.headers": async (input, output) => {
  if (input.model.providerID !== "openai") return
  output.headers.originator = "opencode"
  output.headers["User-Agent"] = `opencode/${VERSION} (${platform} ${release}; ${arch})`
  output.headers.session_id = input.sessionID
}
```

---

## 11. 插件加载机制

```typescript
// plugin/index.ts
const INTERNAL_PLUGINS = [CodexAuthPlugin, CopilotAuthPlugin, GitlabAuthPlugin]

// 加载顺序：
// 1. 加载内置插件（CodexAuthPlugin 等）
// 2. 加载配置中的外部插件
// 3. 跳过已废弃的旧版插件 ("opencode-openai-codex-auth", "opencode-copilot-auth")
```

每个插件返回 `Hooks` 对象，包含：
- `auth` – 认证方法定义（provider、loader、methods）
- `chat.headers` – 请求头注入
- `event` – 事件订阅
- 其他 hooks...

---

## 12. Provider Auth Service（统一管理层）

`provider/auth-service.ts` 提供跨 provider 的认证管理：

```typescript
interface Interface {
  // 列出所有 provider 的认证方法
  methods(): Record<ProviderID, Method[]>

  // 发起授权（返回 URL 和说明）
  authorize(input: {
    providerID: ProviderID
    method: number      // methods 数组中的索引
    inputs?: Record<string, string>
  }): Authorization | undefined

  // 处理回调（保存 token）
  callback(input: {
    providerID: ProviderID
    method: number
    code?: string       // device flow 的 code
  }): void
}
```

**流程：**
1. UI 调用 `methods()` 获取可选的认证方式列表
2. 用户选择后调用 `authorize()` → 返回 URL + 说明
3. 用户完成授权后调用 `callback()` → 保存 token

---

## 13. 错误处理

```typescript
// 四种错误类型
ProviderAuth.OauthMissing        // 无待处理的 OAuth 请求
ProviderAuth.OauthCodeMissing    // code 方式缺少 code
ProviderAuth.OauthCallbackFailed // callback 返回失败
ProviderAuth.ValidationFailed    // 输入验证失败

// ChatGPT 订阅错误提示
"To use Codex with your ChatGPT plan, upgrade to Plus: https://chatgpt.com/explore/plus."
```

---

## 14. 在其他项目中复用的实现要点

### 最小实现清单

1. **PKCE 生成器** – `generatePKCE()` + `generateState()`
2. **授权 URL 构建** – 拼接 OAuth 参数
3. **本地回调服务器** – HTTP 服务器监听 `/auth/callback`
4. **Token Exchange** – 用 code + verifier 换 token
5. **Token 刷新** – 用 refresh_token 获取新 access_token
6. **Token 持久化** – 安全存储（文件权限 0o600 或系统 keychain）
7. **请求拦截** – 自定义 fetch，注入 Bearer token + 重写 URL
8. **JWT 解析** – 提取 account_id

### 关键 API 端点

| 用途 | 方法 | URL |
|------|------|-----|
| 授权页面 | GET | `https://auth.openai.com/oauth/authorize?...` |
| Token 交换/刷新 | POST | `https://auth.openai.com/oauth/token` |
| Device Flow 获取 code | POST | `https://auth.openai.com/api/accounts/deviceauth/usercode` |
| Device Flow 轮询 token | POST | `https://auth.openai.com/api/accounts/deviceauth/token` |
| Device Flow 用户页面 | 浏览器 | `https://auth.openai.com/codex/device` |
| Codex API 调用 | POST | `https://chatgpt.com/backend-api/codex/responses` |

### 安全注意事项

1. **PKCE 必须实现** – 无 client_secret 的公开客户端必须用 PKCE
2. **State 必须验证** – 防止 CSRF 攻击
3. **Token 文件权限** – `0o600`，仅所有者可读写
4. **Token 不要硬编码** – refresh_token 等效于密码
5. **HTTPS** – 除了 localhost 回调外，所有通信必须 HTTPS
6. **超时** – 设置合理的 OAuth 回调超时（OpenCode 用 5 分钟）

### 替代实现建议

- **非 Bun 环境**：用 Node.js `http.createServer()` 或 Express 替代 `Bun.serve()`
- **非 CLI 环境**：可省略 Device Flow，仅保留浏览器 OAuth
- **桌面应用**：可用 Electron 的 `shell.openExternal()` 打开授权 URL
- **Web 应用**：不需要本地服务器，直接用标准 redirect_uri

---

## 15. 源文件索引

| 文件路径 | 用途 |
|----------|------|
| `packages/opencode/src/plugin/codex.ts` | 核心实现：OAuth、PKCE、Token、Fetch 拦截 |
| `packages/opencode/src/auth/effect.ts` | Auth 数据模型（Effect Schema）+ 文件存储 |
| `packages/opencode/src/auth/index.ts` | Auth 公共 API（Zod Schema）|
| `packages/opencode/src/plugin/index.ts` | 插件加载系统 |
| `packages/opencode/src/provider/auth-service.ts` | Provider Auth 统一管理服务 |
| `packages/opencode/src/provider/auth.ts` | Provider Auth 公共命名空间 |
| `packages/opencode/src/provider/transform.ts` | 模型 reasoning effort 配置 |
| `packages/opencode/src/provider/error.ts` | 错误消息定义 |
| `packages/opencode/test/plugin/codex.test.ts` | JWT 解析与 Account ID 提取测试 |
| `packages/opencode/test/auth/auth.test.ts` | Auth 存储规范化测试 |
