# 本地身份会话与访问控制（令牌轮换 / 撤销 / 授权判定）

在 Spring Boot Web 服务上实现的一套**本地账户**身份能力：登录签发、访问令牌绑定会话、
刷新令牌**单次轮换**与**复用检测**、按角色/权限的授权判定、以及在并发刷新与账户状态
变化下保持一致且可解释的失效分类。令牌只在内存中以**哈希**存储，原文仅在签发响应中
返回给客户端一次。

> 适用于本地演示与集成验证；存储为内存实现，重启数据消失（可改用持久化存储而不改变
> 状态机与判定语义）。

---

## 1. 整体结构

```
domain/    账户/会话/令牌记录、权限角色枚举、撤销原因、审计事件
security/  PBKDF2 口令哈希、SecureRandom 令牌生成、SHA-256 令牌哈希
store/     线程安全内存存储 + 按 family 互斥锁 + 只追加审计存储
service/   AuthService（登录/轮换/登出）、AccessTokenService（授权判定）、
           AccountService（改密/启停）、SessionRevocationService（级联撤销）
web/       控制器、授权拦截器、路由权限表、requestId 过滤器、全局错误处理
bootstrap/ 按配置初始化演示账户
```

涉及的关键标识符：

- **session**：一次登录或一次轮换后的“代”。`id` 唯一，`familyId` 标识整条会话链。
- **family（会话链）**：登录时创建，之后每次刷新在**同一条 family 内**建立新一代 session。
  整链撤销（登出/改密/停用/重放）对链上所有 session、所有 access/refresh 令牌生效。
- **access token**：不透明随机串（`vat_` 前缀），通过 `familyId + sessionId` 绑定会话，
  服务端只存 SHA-256 哈希。
- **refresh token**：不透明随机串（`vrt_` 前缀），**一次性**，服务端只存哈希。

---

## 2. 会话与令牌状态机

### 2.1 刷新令牌状态

```
                 登录/轮换 签发
                      │
                      ▼
                 ┌─────────┐  再次使用（已消费）  ┌──────────────┐
                 │ ACTIVE  │ ───────────────────▶ │ REUSE(重放)  │
                 └─────────┘                      └──────────────┘
            正常轮换│    │过期                      │
                  ▼    ▼                          ▼
             ┌────────┐ ┌──────────┐      撤销整条 family
             │CONSUMED│ │ EXPIRED  │      （含全部后继令牌）
             └────────┘ └──────────┘
   正常轮换│    │链路被登出/改密/停用/重放级联撤销
          ▼    ▼
     ┌────────────┐
     │  REVOKED   │  错误码随撤销原因细分（见第 4 节）
     └────────────┘
```

- **CONSUMED**：一次成功轮换的终态。旧刷新令牌永不再次成功。
- **REUSE 检测**：对一个已经 CONSUMED 的令牌再次发起刷新，判定为重放，
  立即**撤销整条 family**（当前及全部后继 access/refresh 令牌都失效），返回
  `refresh_token_reused`。
- **EXPIRED**：在被消费前自然到期，与被撤销严格区分（`refresh_token_expired`）。
- 并发刷新同一令牌：刷新逻辑在**该 family 的锁**内完成「校验 → 标记消费 → 签发后继」，
  因此并发请求线性化——**恰好一个成功**；落败者要么观测到“已消费”（第一个落败者，
  触发整链撤销，`refresh_token_reused`），要么观测到“链已因重放撤销”
  （后到者，`session_revoked_refresh_reuse`）。二者都明确指向重放，且系统中不会
  存在多个并行有效的后继令牌（获胜者的后继也会因随后检测到重放而被整链撤销）。

> 并发下“第一个成功刷新者”与“第一个检测到重放并撤销整条链者”可能不是同一个线程：
> 取胜者完成轮换后，落败者把该 family 标记为 REFRESH_REUSE，获胜者刚签发的后继也会
> 随之失效。这是“检测到重放即吊销整条链”标准语义，目的是在无法区分被窃令牌的持有
> 者与合法客户端时，优先保证不保留任何可能已泄露的凭据。

### 2.2 访问令牌 / 会话状态

访问令牌本身有 `ACTIVE / EXPIRED / REVOKED`，其绑定的 session 与 family 也有撤销状态。
授权判定按固定顺序解析（见第 3 节）。family 的撤销原因是**终态、取首次值**，权威地
解释“为什么这条链失效”：

| 触发动作 | family 撤销原因 | 影响范围 |
|---|---|---|
| 主动登出 `POST /api/auth/logout` | `LOGOUT` | 整链：当前及历史 access/refresh |
| 修改密码 `POST /api/account/password` | `PASSWORD_CHANGED` | 该账户**全部** family |
| 管理员停用账户 | `ACCOUNT_DISABLED` | 该账户**全部** family |
| 刷新令牌重放 | `REFRESH_REUSE` | 该 family（含全部后继） |
| 刷新令牌自然过期清理 | `LOGOUT` | 该 family |

正常刷新轮换**不**写 family 撤销原因，只把上一代 session 标记为 `LOGOUT` 并吊销上一代
access 令牌——所以轮换后旧 access 立即失效（`session_revoked_logout`），而新一代令牌
健康可用。重新启用账户**不会**恢复已撤销的链（撤销终态），但允许重新登录建立新链。

---

## 3. 授权规则

### 3.1 角色 → 权限

| 角色 | 权限 |
|---|---|
| `USER` | `PROFILE_READ`、`ORDER_READ`、`ORDER_WRITE` |
| `ADMIN` | 全部权限（含 `ADMIN_AUDIT_READ`、`ADMIN_ACCOUNT_MANAGE`） |

判定时取账户所有角色权限的并集。

### 3.2 受保护入口与所需权限

| 入口 | 所需权限 |
|---|---|
| `POST /api/auth/login`、`POST /api/auth/refresh` | 公开 |
| `POST /api/auth/logout` | 仅需有效会话 |
| `POST /api/account/password` | 仅需有效会话 |
| `GET  /api/profile` | `PROFILE_READ` |
| `GET  /api/orders` | `ORDER_READ` |
| `GET  /api/admin/audit` | `ADMIN_AUDIT_READ` |
| `POST /api/admin/accounts/status` | `ADMIN_AUDIT_READ` |

### 3.3 判定顺序（短路，每一步一个稳定错误码）

1. 无 `Authorization` 头 → `missing_token`
2. 不是 `Bearer <token>` / token 为空 → `malformed_authorization`
3. 令牌哈希在存储中不存在 → `invalid_token`
4. 令牌或其 session/family 已撤销 → 按**撤销原因**细分（见第 4 节，撤销优先于过期）
5. 已过 `expiresAt` → `token_expired`
6. 账户缺失或非 ACTIVE → `account_inactive`
7. 缺少所需权限 → `insufficient_permission`
8. 以上均通过 → 放行，并把 `username / familyId / sessionId` 注入请求属性

> **不泄露账户是否存在**：登录对“账户不存在 / 密码错误 / 账户停用”统一返回
> `invalid_credentials`（对不存在账户也执行一次 PBKDF2 比较以拉平耗时）；真实原因只
> 写入审计。刷新未识别令牌统一返回 `invalid_grant`，不带任何账户信息。

---

## 4. 错误分类（对外稳定）

错误体结构固定为：

```json
{ "error": "session_revoked_password_changed",
  "error_description": "会话因账户密码变更已失效",
  "request_id": "…" }
```

| HTTP | error code | 含义 |
|---|---|---|
| 401 | `missing_token` | 缺少访问令牌 |
| 401 | `malformed_authorization` | Authorization 头格式错误 |
| 401 | `invalid_token` | 访问令牌无法识别 |
| 401 | `token_expired` | 访问令牌自然过期（与撤销可区分） |
| 401 | `token_revoked` | 通用撤销兜底 |
| 401 | `session_revoked_logout` | 因主动登出/正常轮换结束 |
| 401 | `session_revoked_password_changed` | 因密码变更失效 |
| 401 | `session_revoked_account_disabled` | 因账户停用失效 |
| 401 | `session_revoked_refresh_reuse` | 因刷新令牌重放被整链撤销 |
| 401 | `account_inactive` | 账户状态非 ACTIVE |
| 403 | `insufficient_permission` | 权限不足 |
| 401 | `invalid_credentials` | 登录凭据无效（不区分用户是否存在） |
| 401 | `invalid_grant` | 刷新令牌无法识别 |
| 401 | `refresh_token_expired` | 刷新令牌自然过期 |
| 401 | `refresh_token_reused` | 一次性刷新令牌被重放，链已撤销 |
| 401 | `old_password_incorrect` | 改密时原密码不正确 |
| 404 | `account_not_found` | 管理操作目标账户不存在 |
| 400 | `bad_request` | 请求参数不合法 |
| 500 | `internal_error` | 兜底，不泄露内部细节 |

---

## 5. 审计

登录失败、刷新失败、撤销（`SESSION_REVOKED`）、登出、密码变更、账户启停、每次授权
拒绝都会**只追加**写入 `AuditStore`，可通过 `GET /api/admin/audit` 查询，支持
`?type=` 与 `?username=` 过滤。每条记录含 `id / at / type / username / familyId /
detail`，`detail` 中给出内部判定依据（如 `reason=bad_password`、
`code=insufficient_permission, basis=…`、重放令牌哈希缩写与首次消费时间等）。

同时服务层以 INFO 级别打印关键输入与判定依据，便于单测/本地运行时在日志中追溯
（令牌仅打印前缀或哈希前 12 位，不打印原文）。每个响应带 `X-Request-Id` 头，错误体
内回显同一 `request_id`。

---

## 6. 可配置项

`src/main/resources/application.properties`：

| 配置键 | 默认值 | 说明 |
|---|---|---|
| `app.security.access-token-ttl-seconds` | `300` | 访问令牌有效期（秒） |
| `app.security.refresh-token-ttl-seconds` | `1209600` | 刷新令牌有效期（秒，14 天） |
| `app.security.issuer` | `local-identity` | 签发者标识 |
| `app.security.bootstrap-accounts[i].username` | — | 启动演示账户名 |
| `app.security.bootstrap-accounts[i].password` | — | 启动演示账户明文口令（仅本地） |
| `app.security.bootstrap-accounts[i].roles[j]` | — | 角色：`USER` / `ADMIN` |

口令使用 PBKDF2WithHmacSHA256（120000 轮、每口令独立 16 字节盐、256 位密钥），
格式为 `pbkdf2$<iterations>$<salt>$<hash>`。

---

## 7. 本地验证方法

### 7.1 构建与测试

```bash
mvn clean test          # 运行全部 15 个测试
mvn spring-boot:run     # 启动服务（默认 8080）
```

测试覆盖：并发刷新同一令牌（20 线程，恰好一个成功）、刷新令牌重放整链撤销、撤销后
访问（登出/改密/停用三类原因）、账户启停状态变更、权限不足、登录失败不泄露账户、
过期与撤销可区分、HTTP 全链路错误码与审计查询。可在
`target/surefire-reports/` 及控制台查看“[输入]/[判定依据]”日志。

### 7.2 手动 curl 走查

```bash
# 1) 登录
curl -s -X POST localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-pwd"}'
# => access_token(vat_..) + refresh_token(vrt_..)

ACCESS='vat_..'; REFRESH='vrt_..'

# 2) 访问受保护资源
curl -s localhost:8080/api/profile -H "Authorization: Bearer $ACCESS"

# 3) 刷新轮换（旧 refresh 立即作废）
curl -s -X POST localhost:8080/api/auth/refresh \
  -H 'Content-Type: application/json' -d "{\"refreshToken\":\"$REFRESH\"}"

# 4) 重放旧 refresh => 401 refresh_token_reused，随后整条链失效
curl -s -X POST localhost:8080/api/auth/refresh \
  -H 'Content-Type: application/json' -d "{\"refreshToken\":\"$REFRESH\"}"

# 5) 权限不足（USER 访问管理端）=> 403 insufficient_permission
curl -s localhost:8080/api/admin/audit -H "Authorization: Bearer $ACCESS"

# 6) 改密后旧令牌 => 401 session_revoked_password_changed
# 7) 登出后旧令牌 => 401 session_revoked_logout

# 8) 审计查询（ADMIN）
curl -s localhost:8080/api/admin/audit?type=ACCESS_DENIED \
  -H "Authorization: Bearer $(登录 admin 后的 vat_..)"
```

### 7.3 并发刷新复现

服务层测试 `concurrentRefreshOfSameTokenAllowsExactlyOneSuccess` 用 20 个线程同时用
同一刷新令牌发起刷新，断言：成功数恰为 1、失败仅归类为重放相关错误码、且不存在多个
并行有效后继。
