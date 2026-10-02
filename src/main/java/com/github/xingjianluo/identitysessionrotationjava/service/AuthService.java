package com.github.xingjianluo.identitysessionrotationjava.service;

import com.github.xingjianluo.identitysessionrotationjava.config.SecurityProperties;
import com.github.xingjianluo.identitysessionrotationjava.domain.AccessTokenInfo;
import com.github.xingjianluo.identitysessionrotationjava.domain.Account;
import com.github.xingjianluo.identitysessionrotationjava.domain.AccountStatus;
import com.github.xingjianluo.identitysessionrotationjava.domain.AuditEventType;
import com.github.xingjianluo.identitysessionrotationjava.domain.RefreshTokenInfo;
import com.github.xingjianluo.identitysessionrotationjava.domain.RevocationReason;
import com.github.xingjianluo.identitysessionrotationjava.domain.Session;
import com.github.xingjianluo.identitysessionrotationjava.error.AuthException;
import com.github.xingjianluo.identitysessionrotationjava.error.ErrorCode;
import com.github.xingjianluo.identitysessionrotationjava.security.PasswordEncoder;
import com.github.xingjianluo.identitysessionrotationjava.security.TokenGenerator;
import com.github.xingjianluo.identitysessionrotationjava.security.TokenHasher;
import com.github.xingjianluo.identitysessionrotationjava.store.AccessTokenStore;
import com.github.xingjianluo.identitysessionrotationjava.store.AccountLockStore;
import com.github.xingjianluo.identitysessionrotationjava.store.AuditStore;
import com.github.xingjianluo.identitysessionrotationjava.store.FamilyLockStore;
import com.github.xingjianluo.identitysessionrotationjava.store.RefreshTokenStore;
import com.github.xingjianluo.identitysessionrotationjava.store.SessionStore;
import com.github.xingjianluo.identitysessionrotationjava.store.AccountStore;
import com.github.xingjianluo.identitysessionrotationjava.web.dto.LoginRequest;
import com.github.xingjianluo.identitysessionrotationjava.web.dto.RefreshRequest;
import com.github.xingjianluo.identitysessionrotationjava.web.dto.TokenPairResponse;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 认证服务：登录签发、刷新令牌单次轮换（含复用检测与 family 互斥）、登出。
 */
@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private final AccountStore accountStore;
    private final SessionStore sessionStore;
    private final AccessTokenStore accessTokenStore;
    private final RefreshTokenStore refreshTokenStore;
    private final AuditStore auditStore;
    private final FamilyLockStore familyLockStore;
    private final AccountLockStore accountLockStore;
    private final SessionRevocationService revocationService;
    private final DeviceSessionService deviceSessionService;
    private final PasswordEncoder passwordEncoder;
    private final TokenGenerator tokenGenerator;
    private final TokenHasher tokenHasher;
    private final SecurityProperties properties;

    public AuthService(AccountStore accountStore,
                       SessionStore sessionStore,
                       AccessTokenStore accessTokenStore,
                       RefreshTokenStore refreshTokenStore,
                       AuditStore auditStore,
                       FamilyLockStore familyLockStore,
                       AccountLockStore accountLockStore,
                       SessionRevocationService revocationService,
                       DeviceSessionService deviceSessionService,
                       PasswordEncoder passwordEncoder,
                       TokenGenerator tokenGenerator,
                       TokenHasher tokenHasher,
                       SecurityProperties properties) {
        this.accountStore = accountStore;
        this.sessionStore = sessionStore;
        this.accessTokenStore = accessTokenStore;
        this.refreshTokenStore = refreshTokenStore;
        this.auditStore = auditStore;
        this.familyLockStore = familyLockStore;
        this.accountLockStore = accountLockStore;
        this.revocationService = revocationService;
        this.deviceSessionService = deviceSessionService;
        this.passwordEncoder = passwordEncoder;
        this.tokenGenerator = tokenGenerator;
        this.tokenHasher = tokenHasher;
        this.properties = properties;
    }

    /**
     * 登录。无论账户是否存在、密码是否错误、账户是否停用，对外统一返回
     * {@link ErrorCode#INVALID_CREDENTIALS}（不泄露账户是否存在）；
     * 真实原因只写入审计日志。
     */
    public TokenPairResponse login(LoginRequest request) {
        String username = request == null ? null : request.username();
        String password = request == null ? null : request.password();

        if (username == null || username.isBlank() || password == null || password.isEmpty()) {
            auditStore.record(AuditEventType.LOGIN_FAILURE, username, null,
                    "reason=blank_credentials");
            log.info("登录判定输入 username={} passwordPresent={} => 拒绝: 凭据为空",
                    username, password != null);
            throw new AuthException(ErrorCode.INVALID_CREDENTIALS);
        }

        Account account = accountStore.findByUsername(username).orElse(null);
        // 对不存在的账户也执行一次哈希比较，尽量拉平响应耗时
        if (account == null) {
            passwordEncoder.matches(password,
                    "pbkdf2$120000$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
            auditStore.record(AuditEventType.LOGIN_FAILURE, username, null,
                    "reason=account_not_found");
            log.info("登录判定输入 username={} => 拒绝: 账户不存在（对外=invalid_credentials）", username);
            throw new AuthException(ErrorCode.INVALID_CREDENTIALS);
        }

        if (!passwordEncoder.matches(password, account.getPasswordHash())) {
            auditStore.record(AuditEventType.LOGIN_FAILURE, username, null,
                    "reason=bad_password");
            log.info("登录判定输入 username={} => 拒绝: 密码错误（对外=invalid_credentials）", username);
            throw new AuthException(ErrorCode.INVALID_CREDENTIALS);
        }

        if (account.getStatus() != AccountStatus.ACTIVE) {
            auditStore.record(AuditEventType.LOGIN_FAILURE, username, null,
                    "reason=account_status=" + account.getStatus());
            log.info("登录判定输入 username={} => 拒绝: 账户状态 {}（对外=invalid_credentials）",
                    username, account.getStatus());
            throw new AuthException(ErrorCode.INVALID_CREDENTIALS);
        }

        // 同账号串行化：登记新登录 + 超限淘汰作为一个整体，并发登录不会冲破上限
        synchronized (accountLockStore.lockFor(account.getUsername())) {
            String familyId = tokenGenerator.newId();
            TokenPairResponse pair = issueTokenPair(account.getUsername(), familyId);
            deviceSessionService.registerLogin(account.getUsername(), familyId,
                    request.client());
            deviceSessionService.enforceLimit(account.getUsername());
            auditStore.record(AuditEventType.LOGIN_SUCCESS, username, familyId,
                    "session 建立, client=" + (request.client() == null ? "unknown"
                            : request.client()));
            log.info("登录成功 username={} familyId={} client={} accessExpiresIn={}s",
                    username, familyId, request.client(),
                    properties.getAccessTokenTtlSeconds());
            return pair;
        }
    }

    /**
     * 刷新：旧刷新令牌只能被成功使用一次。
     *
     * <p>并发安全：同一 family 的刷新在 {@link FamilyLockStore} 锁内完成
     * 「校验 → 标记消费 → 签发后继」，因此并发刷新同一令牌恰好一个成功。
     * 已消费令牌再次出现即判定为重放，整条会话链被撤销。
     */
    public TokenPairResponse refresh(RefreshRequest request) {
        String rawRefreshToken = request == null ? null : request.refreshToken();
        if (rawRefreshToken == null || rawRefreshToken.isBlank()) {
            auditStore.record(AuditEventType.REFRESH_FAILURE, null, null,
                    "reason=blank_refresh_token");
            log.info("刷新判定输入 refreshTokenPresent=false => 拒绝: 刷新令牌为空");
            throw new AuthException(ErrorCode.REFRESH_TOKEN_INVALID);
        }

        String tokenHash = tokenHasher.hash(rawRefreshToken);
        RefreshTokenInfo oldToken = refreshTokenStore.findByHash(tokenHash).orElse(null);

        if (oldToken == null) {
            auditStore.record(AuditEventType.REFRESH_FAILURE, null, null,
                    "reason=refresh_token_unknown");
            log.info("刷新判定输入 tokenHash={} => 拒绝: 刷新令牌无法识别", abbreviate(tokenHash));
            throw new AuthException(ErrorCode.REFRESH_TOKEN_INVALID);
        }

        // 同链串行化：保证并发刷新线性化
        synchronized (familyLockStore.lockFor(oldToken.getFamilyId())) {
            RefreshTokenInfo current = refreshTokenStore.findByHash(tokenHash).orElseThrow();

            // 1) 已撤销（链路此前已被登出/改密/停用/重放撤销），以 family 原因为准
            if (current.isRevoked()) {
                RevocationReason familyReason = sessionStore
                        .findFamilyRevocationReason(current.getFamilyId())
                        .orElse(null);
                ErrorCode mapped = mapRevocationReason(familyReason,
                        ErrorCode.REFRESH_TOKEN_INVALID);
                auditStore.record(AuditEventType.REFRESH_FAILURE, current.getUsername(),
                        current.getFamilyId(),
                        "reason=revoked, familyReason=" + familyReason + ", mapped=" + mapped.code());
                log.info("刷新判定 tokenHash={} familyId={} => 拒绝: 链路已撤销 familyReason={} mapped={}",
                        abbreviate(tokenHash), current.getFamilyId(), familyReason, mapped.code());
                throw new AuthException(mapped);
            }

            // 2) 重放检测：已被消费的令牌再次出现 -> 撤销整条链
            if (current.isConsumed()) {
                revocationService.revokeFamily(current.getFamilyId(),
                        RevocationReason.REFRESH_REUSE, current.getUsername(),
                        "重放的刷新令牌 tokenHash=" + abbreviate(tokenHash)
                                + ", 首次消费于 " + current.getConsumedAt());
                auditStore.record(AuditEventType.REFRESH_FAILURE, current.getUsername(),
                        current.getFamilyId(),
                        "reason=refresh_token_reuse, 链路已撤销");
                log.warn("刷新令牌重放 username={} familyId={} consumedAt={} => 撤销整条会话链",
                        current.getUsername(), current.getFamilyId(), current.getConsumedAt());
                throw new AuthException(ErrorCode.REFRESH_TOKEN_REUSED);
            }

            // 3) 过期（尚未消费，过期原因与撤销可区分）
            if (current.getExpiresAt().isBefore(Instant.now())) {
                revocationService.revokeFamily(current.getFamilyId(),
                        RevocationReason.LOGOUT, current.getUsername(),
                        "刷新令牌过期，清理会话");
                auditStore.record(AuditEventType.REFRESH_FAILURE, current.getUsername(),
                        current.getFamilyId(), "reason=refresh_token_expired");
                log.info("刷新判定 tokenHash={} => 拒绝: 刷新令牌过期 expiresAt={}",
                        abbreviate(tokenHash), current.getExpiresAt());
                throw new AuthException(ErrorCode.REFRESH_TOKEN_EXPIRED);
            }

            // 4) 账户状态：停用账户不得续期
            Account account = accountStore.findByUsername(current.getUsername()).orElse(null);
            if (account == null || account.getStatus() != AccountStatus.ACTIVE) {
                revocationService.revokeFamily(current.getFamilyId(),
                        RevocationReason.ACCOUNT_DISABLED, current.getUsername(),
                        "刷新时账户状态非 ACTIVE");
                auditStore.record(AuditEventType.REFRESH_FAILURE, current.getUsername(),
                        current.getFamilyId(), "reason=account_inactive");
                log.info("刷新判定 username={} familyId={} => 拒绝: 账户已停用",
                        current.getUsername(), current.getFamilyId());
                throw new AuthException(ErrorCode.ACCOUNT_INACTIVE);
            }

            // 5) 正常轮换：原子地消费旧令牌、建立后继会话与新令牌对
            current.markConsumed(Instant.now());

            Session childSession = new Session(
                    tokenGenerator.newId(), current.getFamilyId(),
                    current.getUsername(), Instant.now());
            sessionStore.save(childSession);

            TokenPairResponse pair = issueTokenPair(current.getUsername(),
                    current.getFamilyId(), childSession.getId());

            // 撤销旧会话本身（链保留，新会话接管），旧访问令牌随之失效
            sessionStore.findById(current.getSessionId())
                    .ifPresent(s -> s.markRevoked(RevocationReason.LOGOUT));
            accessTokenStore.findByFamily(current.getFamilyId()).stream()
                    .filter(t -> t.getSessionId().equals(current.getSessionId()))
                    .forEach(AccessTokenInfo::markRevoked);

            auditStore.record(AuditEventType.REFRESH_SUCCESS, current.getUsername(),
                    current.getFamilyId(),
                    "轮换 session " + current.getSessionId() + " -> " + childSession.getId());
            deviceSessionService.touch(current.getFamilyId());
            log.info("刷新轮换成功 username={} familyId={} oldSession={} newSession={}",
                    current.getUsername(), current.getFamilyId(),
                    current.getSessionId(), childSession.getId());
            return pair;
        }
    }

    /** 登出：撤销当前访问令牌所在的整条会话链，刷新令牌同时失效。 */
    public void logout(String rawAccessToken) {
        if (rawAccessToken == null || rawAccessToken.isBlank()) {
            throw new AuthException(ErrorCode.MISSING_TOKEN);
        }
        AccessTokenInfo token = accessTokenStore.findByHash(tokenHasher.hash(rawAccessToken))
                .orElseThrow(() -> new AuthException(ErrorCode.INVALID_TOKEN));
        boolean changed = revocationService.revokeFamily(token.getFamilyId(),
                RevocationReason.LOGOUT, token.getUsername(), "用户主动登出");
        auditStore.record(AuditEventType.LOGOUT, token.getUsername(), token.getFamilyId(),
                changed ? "登出并撤销会话链" : "会话链此前已撤销");
        log.info("登出 username={} familyId={} changed={}",
                token.getUsername(), token.getFamilyId(), changed);
    }

    /**
     * 签发令牌对：登录（新会话）与刷新（后继会话）共用。
     * 访问令牌通过 familyId/sessionId 绑定到会话。
     */
    private TokenPairResponse issueTokenPair(String username, String familyId) {
        Session session = new Session(tokenGenerator.newId(), familyId, username, Instant.now());
        sessionStore.save(session);
        return issueTokenPair(username, familyId, session.getId());
    }

    private TokenPairResponse issueTokenPair(String username, String familyId, String sessionId) {
        Instant now = Instant.now();

        String rawAccess = tokenGenerator.newAccessToken();
        AccessTokenInfo accessInfo = new AccessTokenInfo(
                tokenHasher.hash(rawAccess), tokenGenerator.newId(),
                familyId, sessionId, username, now,
                now.plusSeconds(properties.getAccessTokenTtlSeconds()));
        accessTokenStore.save(accessInfo);

        String rawRefresh = tokenGenerator.newRefreshToken();
        RefreshTokenInfo refreshInfo = new RefreshTokenInfo(
                tokenHasher.hash(rawRefresh), familyId, sessionId, username,
                now, now.plusSeconds(properties.getRefreshTokenTtlSeconds()));
        refreshTokenStore.save(refreshInfo);

        return new TokenPairResponse(rawAccess, rawRefresh, "Bearer",
                properties.getAccessTokenTtlSeconds());
    }

    /** 将撤销原因映射为对外稳定错误码，使各失效原因彼此可区分。 */
    private ErrorCode mapRevocationReason(RevocationReason reason, ErrorCode fallback) {
        if (reason == null) {
            return fallback;
        }
        return switch (reason) {
            case LOGOUT -> ErrorCode.SESSION_REVOKED_LOGOUT;
            case PASSWORD_CHANGED -> ErrorCode.SESSION_REVOKED_PASSWORD_CHANGED;
            case ACCOUNT_DISABLED -> ErrorCode.SESSION_REVOKED_ACCOUNT_DISABLED;
            case REFRESH_REUSE -> ErrorCode.SESSION_REVOKED_REFRESH_REUSE;
            case DEVICE_REVOKED -> ErrorCode.SESSION_REVOKED_BY_USER;
            case SESSION_LIMIT_EVICTED -> ErrorCode.SESSION_REVOKED_EVICTED;
        };
    }

    private static String abbreviate(String hash) {
        if (hash == null || hash.length() <= 12) {
            return hash;
        }
        return hash.substring(0, 12) + "...";
    }
}
