# 本地身份会话与访问控制（令牌轮换 / 撤销 / 授权判定 / 多设备会话）

在 Spring Boot Web 服务上实现的一套**本地账户**身份能力：登录签发、访问令牌绑定会话、
刷新令牌**单次轮换**与**复用检测**、按角色/权限的授权判定、**多设备会话管理**
（查看活跃登录、单设备撤销、退出其他设备、每账户活跃登录上限与 LRU 淘汰），
以及在并发刷新、并发登录与账户状态变化下保持一致且可解释的失效分类。
令牌只在内存中以**哈希**存储，原文仅在签发响应中返回给客户端一次。

> 适用于本地演示与集成验证；存储为内存实现，重启数据消失（可改用持久化存储而不改变
> 状态机与判定语义）。

---

## 1. 整体结构

```
domain/    账户/会话/令牌记录、权限角色枚举、撤销原因、审计事件
security/  PBKDF2 口令哈希、SecureRandom 令牌生成、SHA-256 令牌哈希
store/     线程安全内存存储 + 按 family 互斥锁 + 按账户互斥锁 + 只追加审计存储
service/   AuthService（登录/轮换/登出）、AccessTokenService（授权判定）、
           AccountService（改密/启停）、SessionRevocationService（级联撤销）、
           DeviceSessionService（多设备会话：查看/单撤销/退出其他/上限淘汰）
web/       控制器、授权拦截器、路由权限表、requestId 过滤器、全局错误处理
bootstrap/ 按配置初始化演示账户
```

涉及的关键标识符：

- **device session（设备会话）**：一次“设备登录”，以 `familyId` 为对外标识。
  记录客户端/来源（`clientId`、User-Agent、IP）、**登录时间** `loginAt` 与
  **最近活跃时间** `lastActiveAt`。同一设备后续刷新轮换仍属于同一个设备会话。
- **session**：一次登录或一次轮换后的“代”。`id` 唯一，`familyId` 标识整条会话链。
- **family（会话链）**：登录时创建，之后每次刷新在**同一条 family 内**建立新一代 session。
  整链撤销（登出/改密/停用/重放/设备撤销/退出其他/超限清理）对链上所有 session、
  所有 access/refresh 令牌生效。
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
授权判定按固定顺序解析（见第 4 节）。family 的撤销原因是**终态、取首次值**，权威地
解释“为什么这条链失效”：

| 触发动作 | family 撤销原因 | 影响范围 |
|---|---|---|
| 主动登出 `POST /api/auth/logout` | `LOGOUT` | 整链：当前及历史 access/refresh |
| 修改密码 `POST /api/account/password` | `PASSWORD_CHANGED` | 该账户**全部** family |
| 管理员停用账户 | `ACCOUNT_DISABLED` | 该账户**全部** family |
| 刷新令牌重放 | `REFRESH_REUSE` | 该 family（含全部后继） |
| 刷新令牌自然过期清理 | `LOGOUT` | 该 family |
| 单独撤销设备 `POST /api/sessions/{id}/revoke` | `DEVICE_REVOKED` | 仅被点名的 family |
| 退出其他设备 `POST /api/sessions/revoke-others` | `OTHER_DEVICES_LOGOUT` | 除当前 family 外该账户的全部 family |
| 登录数超上限被 LRU 清理 | `MAX_SESSIONS_EVICTED` | 仅被淘汰的 family |

正常刷新轮换**不**写 family 撤销原因，只把上一代 session 标记为 `LOGOUT` 并吊销上一代
access 令牌——所以轮换后旧 access 立即失效（`session_revoked_logout`），而新一代令牌
健康可用。重新启用账户**不会**恢复已撤销的链（撤销终态），但允许重新登录建立新链。

---

## 3. 多设备会话管理（设备 / 上限 / 淘汰）

### 3.1 模型

一次成功登录建立一个**设备会话**（= 一条 family 会话链）。设备会话保存：

| 字段 | 含义 |
|---|---|
| `session_id` | 即 familyId，查看/撤销接口使用的对外标识 |
| `client_id` | 客户端自报来源，登录请求体可选字段 `clientId`（如 `mobile`/`browser`/`cli`） |
| `client_name` | 展示名：优先 `clientId`，否则取 User-Agent 缩写，再否则 `unknown` |
| `user_agent` / `ip` | 登录请求的 User-Agent 与来源 IP（含 `X-Forwarded-For` 首段） |
| `login_at` | 登录时间 |
| `last_active_at` | 最近活跃时间：登录时初始化，**访问受保护资源成功**或**刷新成功**时推进 |
| `current` | 列表中标记是不是“当前这张访问令牌”所在的设备 |

设备会话只在 family **仍活跃**（未被整链撤销）时出现在列表里；撤销后从列表移除。

### 3.2 接口（仅需有效会话，不要求额外权限）

| 接口 | 行为 |
|---|---|
| `GET  /api/sessions` | 当前账户全部活跃设备登录，按最近活跃倒序 |
| `POST /api/sessions/{sessionId}/revoke` | 单独撤销指定设备；目标不存在或不属于自己 → 404 `session_not_found`（不泄露目标是否存在） |
| `POST /api/sessions/revoke-others` | 退出其他所有设备，保留当前会话；返回 `{"revoked_count":N}` |

隔离性：撤销只作用于被点名的 family，当前会话与其他设备的 access/refresh 不受牵连，
仍可正常访问与刷新；操作**立即生效**。

### 3.3 每账户活跃登录上限与 LRU 淘汰

- 上限由 `app.security.max-concurrent-sessions` 配置（默认 `5`，`<=0` 表示不限制）。
- 新登录成功后，在**该账户的互斥锁**内完成「建立新链 → 登记设备 → 清理超限」，
  因此多个客户端几乎同时登录也**不会冲破上限**：最终活跃数恰好等于上限（未到上限前
  新登录永不失败）。
- 超出时按 **LRU** 清理：`lastActiveAt` 最早（最久没有活动）的先清；
  时间相同按 `loginAt`，再相同按 `session_id` 字典序兜底——结果**确定、可预期**。
  本次新登录所在链保证保留。
- 被清理的 family 立即整链撤销，之后其任何 access/refresh 令牌都失败，错误码
  `session_revoked_max_sessions`，与自然过期（`token_expired` /
  `refresh_token_expired`）**明显不同**。

### 3.4 撤销与并发刷新如何对得上

- family 级撤销（单撤销 / 退出其他 / 超限清理 / 改密 / 停用 / 登出）统一在
  **该 family 的锁**内执行；刷新流程的「校验 → 消费 → 签发后继」也在同一把锁内
  （`synchronized` 可重入）。两者线性化，因此不存在“撤销已经完成、刷新却又刷出
  一张能用的新令牌”的窗口：若刷新先赢，它刚签发的后继也会被随后（或同时）的撤销
  一并吊销。
- 未被点名的 family 用的是各自独立的锁，完全不受影响。
- “退出其他设备”与“新登录 + 超限淘汰”都在**账户锁**内运行，两者之间也线性化。

### 3.5 对外错误分类的兼容范围

本次新增但**不改变**任何既有错误码与刷新行为，只新增 3 个撤销细分码与 1 个 404：
`session_revoked_device_revoked`、`session_revoked_other_devices_logout`、
`session_revoked_max_sessions`、`session_not_found`。既有判定顺序、刷新令牌单次轮换、
重放整链撤销等语义保持不变（详见第 4、5 节）。

---

## 4. 授权规则

### 4.1 角色 → 权限

| 角色 | 权限 |
|---|---|
| `USER` | `PROFILE_READ`、`ORDER_READ`、`ORDER_WRITE` |
| `ADMIN` | 全部权限（含 `ADMIN_AUDIT_READ`、`ADMIN_ACCOUNT_MANAGE`） |

判定时取账户所有角色权限的并集。

### 4.2 受保护入口与所需权限

| 入口 | 所需权限 |
|---|---|
| `POST /api/auth/login`、`POST /api/auth/refresh` | 公开 |
| `POST /api/auth/logout` | 仅需有效会话 |
| `POST /api/account/password` | 仅需有效会话 |
| `GET  /api/sessions`、`POST /api/sessions/revoke-others`、`POST /api/sessions/{id}/revoke` | 仅需有效会话 |
| `GET  /api/profile` | `PROFILE_READ` |
| `GET  /api/orders` | `ORDER_READ` |
| `GET  /api/admin/audit` | `ADMIN_AUDIT_READ` |
| `POST /api/admin/accounts/status` | `ADMIN_AUDIT_READ` |

### 4.3 判定顺序（短路，每一步一个稳定错误码）

1. 无 `Authorization` 头 → `missing_token`
2. 不是 `Bearer <token>` / token 为空 → `malformed_authorization`
3. 令牌哈希在存储中不存在 → `invalid_token`
4. 令牌或其 session/family 已撤销 → 按**撤销原因**细分（见第 5 节，撤销优先于过期）
5. 已过 `expiresAt` → `token_expired`
6. 账户缺失或非 ACTIVE → `account_inactive`
7. 缺少所需权限 → `insufficient_permission`
8. 以上均通过 → 放行，并把 `username / familyId / sessionId` 注入请求属性

> **不泄露账户是否存在**：登录对“账户不存在 / 密码错误 / 账户停用”统一返回
> `invalid_credentials`（对不存在账户也执行一次 PBKDF2 比较以拉平耗时）；真实原因只
> 写入审计。刷新未识别令牌统一返回 `invalid_grant`，不带任何账户信息。

---

## 5. 错误分类（对外稳定）

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
| 401 | `session_revoked_device_revoked` | 设备会话被单独撤销（与自然过期可区分） |
| 401 | `session_revoked_other_devices_logout` | 因“退出其他所有设备”被结束 |
| 401 | `session_revoked_max_sessions` | 因超过活跃登录上限，作为最久未活跃会话被清理 |
| 401 | `account_inactive` | 账户状态非 ACTIVE |
| 403 | `insufficient_permission` | 权限不足 |
| 401 | `invalid_credentials` | 登录凭据无效（不区分用户是否存在） |
| 401 | `invalid_grant` | 刷新令牌无法识别 |
| 401 | `refresh_token_expired` | 刷新令牌自然过期 |
| 401 | `refresh_token_reused` | 一次性刷新令牌被重放，链已撤销 |
| 401 | `old_password_incorrect` | 改密时原密码不正确 |
| 404 | `account_not_found` | 管理操作目标账户不存在 |
| 404 | `session_not_found` | 会话不存在或不属于当前账户（单设备撤销） |
| 400 | `bad_request` | 请求参数不合法 |
| 500 | `internal_error` | 兜底，不泄露内部细节 |

---

## 6. 审计

登录失败、刷新失败、撤销（`SESSION_REVOKED`）、登出、密码变更、账户启停、每次授权
拒绝都会**只追加**写入 `AuditStore`，可通过 `GET /api/admin/audit` 查询，支持
`?type=` 与 `?username=` 过滤。每条记录含 `id / at / type / username / familyId /
detail`，`detail` 中给出内部判定依据（如 `reason=bad_password`、
`code=insufficient_permission, basis=…`、重放令牌哈希缩写与首次消费时间等）。

多设备相关动作同样全部可审计：

| 审计类型 | 触发 | detail 要点 |
|---|---|---|
| `SESSION_LISTED` | 查看会话列表 | 活跃会话数 |
| `SESSION_REVOKE_ONE` | 单独撤销设备 | `result=revoked` / `already_revoked` / `not_found_or_not_owner`，clientId |
| `SESSION_REVOKE_OTHERS` | 退出其他设备 | 撤销会话数、保留的 familyId |
| `SESSION_EVICTED` | 超限 LRU 淘汰 | `basis=max_concurrent_sessions`、`limit`、被淘汰者 lastActiveAt、clientId |
| `SESSION_REVOKED` | 上述撤销的链级记录（改密/停用/登出同表） | `reason=DEVICE_REVOKED / OTHER_DEVICES_LOGOUT / MAX_SESSIONS_EVICTED …` |

同时服务层以 INFO 级别打印关键输入与判定依据，便于单测/本地运行时在日志中追溯
（令牌仅打印前缀或哈希前 12 位，不打印原文）。每个响应带 `X-Request-Id` 头，错误体
内回显同一 `request_id`。

---

## 7. 可配置项

`src/main/resources/application.properties`：

| 配置键 | 默认值 | 说明 |
|---|---|---|
| `app.security.access-token-ttl-seconds` | `300` | 访问令牌有效期（秒） |
| `app.security.refresh-token-ttl-seconds` | `1209600` | 刷新令牌有效期（秒，14 天） |
| `app.security.max-concurrent-sessions` | `5` | 每账户同时保持的活跃登录（设备会话）数上限；`<=0` 表示不限制 |
| `app.security.issuer` | `local-identity` | 签发者标识 |
| `app.security.bootstrap-accounts[i].username` | — | 启动演示账户名 |
| `app.security.bootstrap-accounts[i].password` | — | 启动演示账户明文口令（仅本地） |
| `app.security.bootstrap-accounts[i].roles[j]` | — | 角色：`USER` / `ADMIN` |

口令使用 PBKDF2WithHmacSHA256（120000 轮、每口令独立 16 字节盐、256 位密钥），
格式为 `pbkdf2$<iterations>$<salt>$<hash>`。

---

## 8. 本地验证方法

### 8.1 构建与测试

```bash
mvn clean test          # 运行全部 23 个测试
mvn spring-boot:run     # 启动服务（默认 8080）
```

测试覆盖：并发刷新同一令牌（20 线程，恰好一个成功）、刷新令牌重放整链撤销、撤销后
访问（登出/改密/停用三类原因）、账户启停状态变更、权限不足、登录失败不泄露账户、
过期与撤销可区分、HTTP 全链路错误码与审计查询；以及多设备会话专项
（`MultiDeviceSessionTests`，独立装配上限=3，日志以 `[业务:…]`/`[通过] …` 标注）：

- 会话查看：登录/最近活跃时间、客户端来源、`current` 标记；
- 单会话撤销的隔离效果（被点名者立即失效、他人访问与刷新不受牵连、越权 404）；
- 退出其他所有设备（只保留当前会话）；
- 超限 LRU 淘汰顺序与错误码（`session_revoked_max_sessions` ≠ 自然过期）；
- 撤销与 8 线程并发刷新叠加（被撤销链无可用后继令牌，其他链不受影响）；
- 20 个客户端并发登录下上限严格保持为 3、最终存活与淘汰结果可预期、审计齐全。

可在 `target/surefire-reports/` 及控制台查看“[业务]/[输入]/[判定依据]/[通过]”日志。

### 8.2 手动 curl 走查

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

多设备会话走查（用 `clientId` 区分客户端；也可看返回的 `user_agent`）：

```bash
# 三个客户端分别登录同一账户
curl -s -X POST localhost:8080/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-pwd","clientId":"mobile"}'
curl -s -X POST localhost:8080/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-pwd","clientId":"browser"}'
CLI=$(curl -s -X POST localhost:8080/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-pwd","clientId":"cli"}')
CLI_ACCESS=$(echo "$CLI" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')

# 9) 查看当前有哪些活跃登录（登录时间/最近活跃时间/来源，cli 标记 current=true）
curl -s localhost:8080/api/sessions -H "Authorization: Bearer $CLI_ACCESS"

# 10) 单独把某台设备踢下线（SESSION_ID 用上一步返回的 session_id）
curl -s -X POST localhost:8080/api/sessions/$SESSION_ID/revoke \
  -H "Authorization: Bearer $CLI_ACCESS"
# 被踢设备的 access/refresh => 401 session_revoked_device_revoked；cli 照常可用

# 11) 退出其他所有设备（保留当前 cli）
curl -s -X POST localhost:8080/api/sessions/revoke-others \
  -H "Authorization: Bearer $CLI_ACCESS"
# => {"revoked_count":N}；其他设备 => 401 session_revoked_other_devices_logout

# 12) 触发上限淘汰：把上限调小后连续登录
#     在 application.properties 设置 app.security.max-concurrent-sessions=2，
#     第三次登录会挤掉最久未活跃的设备：
curl -s localhost:8080/api/profile -H "Authorization: Bearer $被挤掉设备的vat"
# => 401 session_revoked_max_sessions（区别于 401 token_expired）

# 13) 多设备动作审计
curl -s 'localhost:8080/api/admin/audit?username=alice' \
  -H "Authorization: Bearer $(登录 admin 后的 vat_..)"
```

### 8.3 并发刷新复现

服务层测试 `concurrentRefreshOfSameTokenAllowsExactlyOneSuccess` 用 20 个线程同时用
同一刷新令牌发起刷新，断言：成功数恰为 1、失败仅归类为重放相关错误码、且不存在多个
并行有效后继。

### 8.4 多设备并发与上限复现

- `MultiDeviceSessionTests#concurrentLoginsNeverExceedLimitAndStayDeterministic`：
  上限=3 时 20 个客户端同时登录，断言最终活跃数恰为 3、17 个被淘汰者的 access/refresh
  全部归因为 `session_revoked_max_sessions`（非自然过期）、审计 17 条且 family 不重复。
- `MultiDeviceSessionTests#revocationConcurrentWithRefreshLeavesNoUsableTokenAndSparesOthers`：
  撤销与 8 线程并发刷新同一链，断言被撤销链不留任何可用后继令牌、其他设备访问与刷新正常。

