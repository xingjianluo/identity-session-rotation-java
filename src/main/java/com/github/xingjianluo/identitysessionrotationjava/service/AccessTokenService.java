package com.github.xingjianluo.identitysessionrotationjava.service;

import com.github.xingjianluo.identitysessionrotationjava.domain.AccessTokenInfo;
import com.github.xingjianluo.identitysessionrotationjava.domain.Account;
import com.github.xingjianluo.identitysessionrotationjava.domain.AccountStatus;
import com.github.xingjianluo.identitysessionrotationjava.domain.AuditEventType;
import com.github.xingjianluo.identitysessionrotationjava.domain.Permission;
import com.github.xingjianluo.identitysessionrotationjava.domain.RevocationReason;
import com.github.xingjianluo.identitysessionrotationjava.domain.Role;
import com.github.xingjianluo.identitysessionrotationjava.domain.Session;
import com.github.xingjianluo.identitysessionrotationjava.error.ErrorCode;
import com.github.xingjianluo.identitysessionrotationjava.security.TokenHasher;
import com.github.xingjianluo.identitysessionrotationjava.store.AccessTokenStore;
import com.github.xingjianluo.identitysessionrotationjava.store.AccountStore;
import com.github.xingjianluo.identitysessionrotationjava.store.AuditStore;
import com.github.xingjianluo.identitysessionrotationjava.store.SessionStore;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 访问令牌校验与授权判定。
 *
 * <p>判定顺序（每一步对应彼此可区分、对外稳定的错误码）：
 * <ol>
 *   <li>缺失 / 格式错误 → missing_token / malformed_authorization</li>
 *   <li>令牌无法识别 → invalid_token</li>
 *   <li>会话链已撤销（按撤销原因细分）→ session_revoked_*</li>
 *   <li>令牌过期 → token_expired</li>
 *   <li>账户状态失效 → account_inactive</li>
 *   <li>权限不足 → insufficient_permission</li>
 * </ol>
 * 所有拒绝都会写审计并打印判定依据日志。
 */
@Service
public class AccessTokenService {

    private static final Logger log = LoggerFactory.getLogger(AccessTokenService.class);

    private final AccessTokenStore accessTokenStore;
    private final SessionStore sessionStore;
    private final AccountStore accountStore;
    private final AuditStore auditStore;
    private final TokenHasher tokenHasher;
    private final DeviceSessionService deviceSessionService;

    public AccessTokenService(AccessTokenStore accessTokenStore,
                              SessionStore sessionStore,
                              AccountStore accountStore,
                              AuditStore auditStore,
                              TokenHasher tokenHasher,
                              DeviceSessionService deviceSessionService) {
        this.accessTokenStore = accessTokenStore;
        this.sessionStore = sessionStore;
        this.accountStore = accountStore;
        this.auditStore = auditStore;
        this.tokenHasher = tokenHasher;
        this.deviceSessionService = deviceSessionService;
    }

    /** 纯判定（不抛异常），便于过滤器与单测复用。 */
    public AccessDecision authorize(String authorizationHeader, Permission required) {
        if (authorizationHeader == null || authorizationHeader.isBlank()) {
            return deny(ErrorCode.MISSING_TOKEN, null, null, null, "无 Authorization 头", required);
        }

        String prefix = "Bearer ";
        if (!authorizationHeader.startsWith(prefix)) {
            return deny(ErrorCode.MALFORMED_AUTHORIZATION, null, null, null,
                    "Authorization 头缺少 Bearer 方案", required);
        }
        String token = authorizationHeader.substring(prefix.length()).trim();
        if (token.isEmpty()) {
            return deny(ErrorCode.MALFORMED_AUTHORIZATION, null, null, null,
                    "Bearer 令牌为空", required);
        }

        AccessTokenInfo info = accessTokenStore.findByHash(tokenHasher.hash(token)).orElse(null);
        if (info == null) {
            return deny(ErrorCode.INVALID_TOKEN, null, null, null,
                    "令牌哈希在存储中不存在", required);
        }

        // 会话撤销优先于过期判定：显式撤销原因必须可被解释
        Session session = sessionStore.findById(info.getSessionId()).orElse(null);
        if (info.isRevoked() || (session != null && session.isRevoked())) {
            // family 级原因优先（登出/改密/停用/重放）；其次是单会话原因（正常轮换）
            RevocationReason basis = sessionStore
                    .findFamilyRevocationReason(info.getFamilyId())
                    .orElseGet(() -> session != null ? session.getRevocationReason() : null);
            ErrorCode mapped = mapRevocationReason(basis);
            return deny(mapped, info.getUsername(), info.getFamilyId(), info.getSessionId(),
                    "family撤销原因=" + sessionStore
                            .findFamilyRevocationReason(info.getFamilyId()).orElse(null)
                            + ", 会话撤销原因=" + (session == null ? "missing" : session.getRevocationReason()),
                    required);
        }

        if (info.getExpiresAt().isBefore(Instant.now())) {
            return deny(ErrorCode.TOKEN_EXPIRED, info.getUsername(), info.getFamilyId(),
                    info.getSessionId(), "访问令牌过期时间=" + info.getExpiresAt(), required);
        }

        Account account = accountStore.findByUsername(info.getUsername()).orElse(null);
        if (account == null || account.getStatus() != AccountStatus.ACTIVE) {
            return deny(ErrorCode.ACCOUNT_INACTIVE, info.getUsername(), info.getFamilyId(),
                    info.getSessionId(),
                    "账户状态=" + (account == null ? "缺失" : account.getStatus()), required);
        }

        if (required != null && !hasPermission(account, required)) {
            return deny(ErrorCode.INSUFFICIENT_PERMISSION, account.getUsername(),
                    info.getFamilyId(), info.getSessionId(),
                    "需要权限=" + required + ", 角色=" + account.getRoles()
                            + ", 授予权限=" + effectivePermissions(account), required);
        }

        log.info("授权通过 username={} familyId={} sessionId={} required={}",
                info.getUsername(), info.getFamilyId(), info.getSessionId(), required);
        // 成功访问 = 该设备最近活跃（用于超限淘汰的 LRU 判定）
        deviceSessionService.touch(info.getFamilyId());
        return new AccessDecision(true, null, "allowed", info.getUsername(),
                info.getFamilyId(), info.getSessionId());
    }

    private AccessDecision deny(ErrorCode code, String username, String familyId,
                                String sessionId, String basis, Permission required) {
        log.info("授权拒绝 code={} username={} familyId={} required={} 判定依据: {}",
                code.code(), username, familyId, required, basis);
        auditStore.record(AuditEventType.ACCESS_DENIED, username, familyId,
                "code=" + code.code() + ", required=" + required + ", basis=" + basis);
        return new AccessDecision(false, code.code(), code.defaultMessage(),
                username, familyId, sessionId);
    }

    private boolean hasPermission(Account account, Permission required) {
        return account.getRoles().stream()
                .map(Role::permissions)
                .anyMatch(perms -> perms.contains(required));
    }

    private String effectivePermissions(Account account) {
        java.util.EnumSet<Permission> all = java.util.EnumSet.noneOf(Permission.class);
        account.getRoles().forEach(r -> all.addAll(r.permissions()));
        return all.toString();
    }

    private ErrorCode mapRevocationReason(RevocationReason reason) {
        if (reason == null) {
            return ErrorCode.TOKEN_REVOKED;
        }
        return switch (reason) {
            case LOGOUT -> ErrorCode.SESSION_REVOKED_LOGOUT;
            case PASSWORD_CHANGED -> ErrorCode.SESSION_REVOKED_PASSWORD_CHANGED;
            case ACCOUNT_DISABLED -> ErrorCode.SESSION_REVOKED_ACCOUNT_DISABLED;
            case REFRESH_REUSE -> ErrorCode.SESSION_REVOKED_REFRESH_REUSE;
            case DEVICE_REVOKED -> ErrorCode.SESSION_REVOKED_DEVICE_REVOKED;
            case OTHER_DEVICES_LOGOUT -> ErrorCode.SESSION_REVOKED_OTHER_DEVICES_LOGOUT;
            case MAX_SESSIONS_EVICTED -> ErrorCode.SESSION_REVOKED_MAX_SESSIONS;
        };
    }

    /** 授权判定结果。 */
    public record AccessDecision(boolean allowed, String errorCode, String reason,
                                 String username, String familyId, String sessionId) {
    }
}
