# 本地身份会话与令牌轮换（identity-session-rotation-java）

基于 Spring Boot 的本地身份会话与访问控制示例：登录签发短期访问令牌 + 一次性刷新令牌，
刷新令牌单次轮换并带复用检测，密码变更/登出/停用即时撤销，按角色与权限范围做授权判定，
所有安全事件写入可查询的审计记录。

## 1. 令牌与会话模型

令牌为不透明随机串，仅保存在服务端内存中：

- **访问令牌（access token）**：短期有效，绑定到唯一会话（session）。
- **刷新令牌（refresh token）**：一次性使用，每次刷新换发新令牌（轮换），
  同一次登录产生的所有令牌构成一条**轮换链**，共享一个会话。
- **会话（session）**：承载链上全部令牌的生命周期；撤销会话即整条链失效。

### 会话状态机

```
                 登录成功
                    │
                    ▼
                ┌────────┐   刷新令牌 TTL 到期未使用    ┌──────────┐
                │ ACTIVE │ ─────────────────────────▶ │ EXPIRED  │
                └───┬────┘                            └──────────┘
                    │ 登出 / 改密 / 停用 / 复用检测
                    ▼
                ┌─────────┐
                │ REVOKED │  （保留撤销原因，见下）
                └─────────┘
```

`REVOKED` 与 `EXPIRED` 是**不同的终态**：撤销始终携带原因
（`LOGOUT` / `PASSWORD_CHANGED` / `ACCOUNT_DISABLED` / `REFRESH_TOKEN_REUSE_DETECTED`），
对外错误载荷的 `message` 字段会带上该原因，因此“被撤销”与“自然过期”永远可区分。

### 刷新令牌轮换与复用检测

- 每次 `/auth/refresh` 原子地**消费**当前刷新令牌并签发链上下一环节；
  旧令牌不会再次成功。
- **并发刷新同一令牌**：按令牌条目加锁，恰好一个请求成功；其余请求在
  **竞态宽限窗口**（`security.refresh-reuse-grace-seconds`，默认 5s）内收到
  `REFRESH_TOKEN_RACE`（HTTP 409），胜者的后继链**不受影响**。
- **窗口之外再次出现已消费的刷新令牌**判定为复用/泄露：整条会话链以
  `REFRESH_TOKEN_REUSE_DETECTED` 撤销，请求返回 `REFRESH_TOKEN_REUSED`，
  链上最新的访问令牌与刷新令牌立即全部失效。
  （协议层无法区分“良性并发重试”与“攻击者重放”，宽限窗口是业界标准折中。）

### 即时失效

密码变更（`tokenVersion` 递增）与账户停用会**同步**撤销该账户的全部会话；
登出撤销当前会话。撤销后下一个请求即失败，无需等待令牌过期。

## 2. 授权规则

受保护端点先做令牌认证，再做角色/权限判定：

| 端点 | 要求 |
| --- | --- |
| `POST /auth/login` | 公开；失败一律 `INVALID_CREDENTIALS`，不泄露账户是否存在 |
| `POST /auth/refresh` | 公开；有效刷新令牌 |
| `POST /auth/logout` | 有效访问令牌（幂等） |
| `GET /api/me` | 任意有效会话 |
| `GET /api/read` | 权限 `read` |
| `GET /api/admin` | 角色 `admin` |
| `POST /api/password` | 有效会话，且只能改自己的密码 |
| `POST /api/admin/disable` | 权限 `admin:disable` |
| `GET /api/audit` | 权限 `admin:audit`，支持 `type`、`accountId` 过滤 |

访问令牌校验的判定顺序（保证错误分类稳定）：
`TOKEN_INVALID` → `SESSION_REVOKED`（含原因）→ `ACCOUNT_STATE_INVALID` → `TOKEN_EXPIRED` → 通过。

## 3. 错误分类（对外稳定契约）

错误响应统一为 `{"error": "<CODE>", "message": "...", "timestamp": "..."}`：

| error | HTTP | 含义 |
| --- | --- | --- |
| `INVALID_CREDENTIALS` | 401 | 登录失败（未知用户/错密码/停用账户，对外不区分） |
| `TOKEN_INVALID` | 401 | 缺失/未知/畸形的访问令牌 |
| `TOKEN_EXPIRED` | 401 | 访问令牌自然过期 |
| `SESSION_REVOKED` | 401 | 会话被显式撤销，`message` 含撤销原因 |
| `ACCOUNT_STATE_INVALID` | 401 | 令牌签发后账户状态失效 |
| `REFRESH_TOKEN_INVALID` | 401 | 未知/缺失的刷新令牌 |
| `REFRESH_TOKEN_EXPIRED` | 401 | 刷新令牌过期 |
| `REFRESH_TOKEN_REUSED` | 401 | 宽限窗口外重放已消费的刷新令牌（链已撤销） |
| `REFRESH_TOKEN_RACE` | 409 | 并发轮换中落败；客户端应改用最新令牌重试 |
| `PERMISSION_DENIED` | 403 | 已认证但缺少角色/权限 |

## 4. 审计

登录成功/失败、令牌轮换、刷新失败、复用检测、会话撤销、登出、改密、
授权拒绝都会写入审计记录（同时输出到 INFO 日志）。
查询：`GET /api/audit?type=SESSION_REVOKED&accountId=acc-reader`（需 `admin:audit` 权限）。

## 5. 可配置项（`application.properties`）

| 配置 | 默认 | 说明 |
| --- | --- | --- |
| `security.access-token-ttl-seconds` | 300 | 访问令牌有效期 |
| `security.refresh-token-ttl-seconds` | 3600 | 刷新令牌/会话有效期 |
| `security.refresh-reuse-grace-seconds` | 5 | 并发竞态宽限窗口；窗口内重复出现按竞态处理不烧链 |

## 6. 本地验证

```bash
mvn test          # 全部测试（含 20 线程并发刷新、重放、撤销、权限不足等场景）
mvn spring-boot:run
```

种子账户：`admin / admin-password`（角色 admin，权限 read、admin:disable、admin:audit）、
`reader / reader-password`（权限 read）。

```bash
# 登录
curl -s -X POST localhost:8080/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"reader","password":"reader-password"}'

# 访问受保护资源（替换 $AT）
curl -s localhost:8080/api/read -H "Authorization: Bearer $AT"

# 轮换刷新令牌（替换 $RT）；再次提交同一刷新令牌将触发复用检测
curl -s -X POST localhost:8080/auth/refresh \
  -H 'Content-Type: application/json' -d "{\"refreshToken\":\"$RT\"}"

# 查询审计（需 admin 令牌 $ADMIN_AT）
curl -s "localhost:8080/api/audit?accountId=acc-reader" \
  -H "Authorization: Bearer $ADMIN_AT"
```

## 7. 测试覆盖

- `LoginAndRevocationTest`：登录失败不泄露存在性；令牌绑定会话；过期 vs 撤销可区分；
  改密/登出/停用即时失效。
- `RefreshRotationTest`：单次轮换；20 线程并发刷新同一令牌恰好一个成功且链路存活；
  宽限窗口外重放烧链并审计；刷新令牌过期分类。
- `AuthorizationAndAuditTest`：权限不足 403；四类受保护入口错误互相可区分；
  各类事件均可审计查询。
- `WebLayerTest`：HTTP 层稳定错误载荷、种子账户、受保护端点、轮换/登出/停用、审计端点。

测试日志中以 `[输入]` / `[判定依据]` / `[结论]` 打印关键输入与判定依据。

> 说明：密码哈希为演示级 SHA-256，存储为内存实现，仅用于本地验证，不可直接用于生产。
