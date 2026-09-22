package com.github.xingjianluo.identitysessionrotationjava.tests;

import com.github.xingjianluo.identitysessionrotationjava.domain.AccessTokenInfo;
import com.github.xingjianluo.identitysessionrotationjava.domain.Account;
import com.github.xingjianluo.identitysessionrotationjava.domain.AccountStatus;
import com.github.xingjianluo.identitysessionrotationjava.domain.Permission;
import com.github.xingjianluo.identitysessionrotationjava.domain.RefreshTokenInfo;
import com.github.xingjianluo.identitysessionrotationjava.domain.Role;
import com.github.xingjianluo.identitysessionrotationjava.error.AuthException;
import com.github.xingjianluo.identitysessionrotationjava.error.ErrorCode;
import com.github.xingjianluo.identitysessionrotationjava.security.PasswordEncoder;
import com.github.xingjianluo.identitysessionrotationjava.security.TokenGenerator;
import com.github.xingjianluo.identitysessionrotationjava.security.TokenHasher;
import com.github.xingjianluo.identitysessionrotationjava.service.AccessTokenService;
import com.github.xingjianluo.identitysessionrotationjava.service.AccountService;
import com.github.xingjianluo.identitysessionrotationjava.service.AuthService;
import com.github.xingjianluo.identitysessionrotationjava.store.AccessTokenStore;
import com.github.xingjianluo.identitysessionrotationjava.store.AccountStore;
import com.github.xingjianluo.identitysessionrotationjava.store.AuditStore;
import com.github.xingjianluo.identitysessionrotationjava.store.RefreshTokenStore;
import com.github.xingjianluo.identitysessionrotationjava.web.dto.LoginRequest;
import com.github.xingjianluo.identitysessionrotationjava.web.dto.RefreshRequest;
import com.github.xingjianluo.identitysessionrotationjava.web.dto.TokenPairResponse;
import java.time.Instant;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * 服务层场景测试。
 *
 * <p>日志中会打印关键输入（令牌前缀/哈希缩写、familyId）与判定依据（错误码）。
 */
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SessionRotationServiceTests {

    private static final Logger log = LoggerFactory.getLogger(SessionRotationServiceTests.class);

    @Autowired private AuthService authService;
    @Autowired private AccessTokenService accessTokenService;
    @Autowired private AccountService accountService;
    @Autowired private AccountStore accountStore;
    @Autowired private AccessTokenStore accessTokenStore;
    @Autowired private RefreshTokenStore refreshTokenStore;
    @Autowired private AuditStore auditStore;
    @Autowired private PasswordEncoder passwordEncoder;
    @Autowired private TokenHasher tokenHasher;
    @Autowired private TokenGenerator tokenGenerator;

    /** 令牌对 + 服务端记录的便捷视图。 */
    record Issued(TokenPairResponse pair, AccessTokenInfo access, RefreshTokenInfo refresh) {
    }

    @BeforeAll
    void setUp() {
        // 专用测试账户，避免与演示账户互相干扰
        createAccount("svc_user", "password123", Role.USER);
        createAccount("svc_admin", "password123", Role.ADMIN);
        createAccount("svc_dormant", "password123", Role.USER);
        accountStore.findByUsername("svc_dormant")
                .ifPresent(a -> a.setStatus(AccountStatus.DISABLED));
    }

    private void createAccount(String username, String rawPassword, Role... roles) {
        accountStore.save(new Account(username, passwordEncoder.encode(rawPassword),
                AccountStatus.ACTIVE, EnumSet.copyOf(List.of(roles))));
    }

    private Issued login(String username, String password) {
        TokenPairResponse pair = authService.login(new LoginRequest(username, password));
        AccessTokenInfo access = accessTokenStore
                .findByHash(tokenHasher.hash(pair.accessToken())).orElseThrow();
        RefreshTokenInfo refresh = refreshTokenStore
                .findByHash(tokenHasher.hash(pair.refreshToken())).orElseThrow();
        log.info("[输入] login username={} -> familyId={} access={} refresh={}",
                username, access.getFamilyId(),
                pair.accessToken().substring(0, 10) + "...",
                pair.refreshToken().substring(0, 10) + "...");
        return new Issued(pair, access, refresh);
    }

    private Issued refresh(Issued current) {
        TokenPairResponse pair = authService.refresh(
                new RefreshRequest(current.pair().refreshToken()));
        AccessTokenInfo access = accessTokenStore
                .findByHash(tokenHasher.hash(pair.accessToken())).orElseThrow();
        RefreshTokenInfo refresh = refreshTokenStore
                .findByHash(tokenHasher.hash(pair.refreshToken())).orElseThrow();
        return new Issued(pair, access, refresh);
    }

    private AuthException expectAuthError(Runnable action, ErrorCode expected) {
        var thrown = (AuthException) catchError(action, AuthException.class);
        assertThat(thrown).as("应抛出 AuthException").isNotNull();
        assertThat(thrown.getErrorCode()).as("错误分类").isEqualTo(expected);
        log.info("[判定依据] 期望错误码={} 实际={}", expected.code(),
                thrown.getErrorCode().code());
        return thrown;
    }

    private Throwable catchError(Runnable action, Class<? extends Throwable> type) {
        try {
            action.run();
            return null;
        } catch (Throwable t) {
            if (type.isInstance(t)) {
                return t;
            }
            throw t;
        }
    }

    // ------------------------------------------------------------------
    // 1. 登录
    // ------------------------------------------------------------------

    @Test
    void loginSucceedsAndBindsAccessTokenToSession() {
        Issued issued = login("svc_user", "password123");
        assertThat(issued.pair().accessToken()).startsWith("vat_");
        assertThat(issued.pair().refreshToken()).startsWith("vrt_");
        assertThat(issued.pair().expiresIn()).isPositive();
        assertThat(issued.access().getFamilyId()).isEqualTo(issued.refresh().getFamilyId());
        assertThat(issued.access().getSessionId()).isEqualTo(issued.refresh().getSessionId());
        assertThat(issued.access().getUsername()).isEqualTo("svc_user");

        var decision = accessTokenService.authorize(
                "Bearer " + issued.pair().accessToken(), Permission.PROFILE_READ);
        assertThat(decision.allowed()).isTrue();
        assertThat(decision.familyId()).isEqualTo(issued.access().getFamilyId());
    }

    // ------------------------------------------------------------------
    // 2. 登录失败：错误分类一致，且不泄露账户是否存在
    // ------------------------------------------------------------------

    @Test
    void loginFailuresReturnSameStableErrorAndWriteAudit() {
        // 不存在的账户
        expectAuthError(
                () -> authService.login(new LoginRequest("svc_ghost", "whatever")),
                ErrorCode.INVALID_CREDENTIALS);
        // 密码错误
        expectAuthError(
                () -> authService.login(new LoginRequest("svc_user", "wrong-password")),
                ErrorCode.INVALID_CREDENTIALS);
        // 账户被停用（对外仍为 invalid_credentials，真实原因仅在审计中）
        expectAuthError(
                () -> authService.login(new LoginRequest("svc_dormant", "password123")),
                ErrorCode.INVALID_CREDENTIALS);

        long failures = auditStore.findByType("LOGIN_FAILURE").stream()
                .filter(e -> e.username() != null
                        && e.username().startsWith("svc_"))
                .count();
        assertThat(failures).as("三次失败登录均应写审计").isGreaterThanOrEqualTo(3);
        // 审计内部保留真实原因：停用账户
        assertThat(auditStore.findByType("LOGIN_FAILURE"))
                .anyMatch(e -> "svc_dormant".equals(e.username())
                        && e.detail().contains("account_status=DISABLED"));
        log.info("[判定依据] 三类登录失败对外错误码统一为 invalid_credentials，审计可见真实原因");
    }

    // ------------------------------------------------------------------
    // 3. 刷新轮换：每次换发新刷新令牌，旧令牌不得再次成功
    // ------------------------------------------------------------------

    @Test
    void refreshRotatesTokensAndOldTokenCannotBeReused() {
        Issued first = login("svc_user", "password123");

        Issued second = refresh(first);
        assertThat(second.pair().refreshToken())
                .as("刷新令牌必须换发").isNotEqualTo(first.pair().refreshToken());
        assertThat(second.pair().accessToken())
                .as("访问令牌必须换发").isNotEqualTo(first.pair().accessToken());
        assertThat(second.access().getFamilyId())
                .as("轮换在同一会话链内").isEqualTo(first.access().getFamilyId());
        assertThat(second.access().getSessionId())
                .as("每次轮换产生新会话").isNotEqualTo(first.access().getSessionId());

        // 新访问令牌有效（此时尚未发生重放，链路健康）
        var decision = accessTokenService.authorize(
                "Bearer " + second.pair().accessToken(), Permission.PROFILE_READ);
        assertThat(decision.allowed()).isTrue();

        // 旧访问令牌因其会话被轮换结束而立即失效，原因为登出（正常轮换）
        var oldDecision = accessTokenService.authorize(
                "Bearer " + first.pair().accessToken(), Permission.PROFILE_READ);
        assertThat(oldDecision.allowed()).isFalse();
        assertThat(oldDecision.errorCode())
                .isEqualTo(ErrorCode.SESSION_REVOKED_LOGOUT.code());

        // 旧刷新令牌已消费：再次使用即重放，撤销整条链
        expectAuthError(() -> authService.refresh(
                new RefreshRequest(first.pair().refreshToken())),
                ErrorCode.REFRESH_TOKEN_REUSED);

        // 重放后：后继访问令牌也必须失效，且原因可区分为刷新重放
        var decisionAfterReuse = accessTokenService.authorize(
                "Bearer " + second.pair().accessToken(), Permission.PROFILE_READ);
        assertThat(decisionAfterReuse.allowed()).isFalse();
        assertThat(decisionAfterReuse.errorCode())
                .isEqualTo(ErrorCode.SESSION_REVOKED_REFRESH_REUSE.code());
        // 后继刷新令牌同样被拒绝
        expectAuthError(() -> authService.refresh(
                new RefreshRequest(second.pair().refreshToken())),
                ErrorCode.SESSION_REVOKED_REFRESH_REUSE);

        log.info("[判定依据] familyId={} 轮换会话={} -> {}，重放后整链撤销",
                first.access().getFamilyId(), first.access().getSessionId(),
                second.access().getSessionId());
    }

    // ------------------------------------------------------------------
    // 4. 并发刷新同一令牌：只有一个请求成功，其余分类为“重放”，
    //    且不得产生两个并行的有效后继令牌
    // ------------------------------------------------------------------

    @Test
    void concurrentRefreshOfSameTokenAllowsExactlyOneSuccess() throws Exception {
        Issued issued = login("svc_user", "password123");
        int threads = 20;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch start = new CountDownLatch(1);
        ConcurrentLinkedQueue<TokenPairResponse> successes = new ConcurrentLinkedQueue<>();
        ConcurrentLinkedQueue<String> failureCodes = new ConcurrentLinkedQueue<>();

        List<Callable<Void>> tasks = java.util.stream.IntStream.range(0, threads)
                .<Callable<Void>>mapToObj(i -> () -> {
                    ready.countDown();
                    start.await();
                    try {
                        TokenPairResponse pair = authService.refresh(
                                new RefreshRequest(issued.pair().refreshToken()));
                        successes.add(pair);
                        log.info("[并发输入] 线程 {} 刷新成功", i);
                    } catch (AuthException e) {
                        failureCodes.add(e.getErrorCode().code());
                        log.info("[并发输入] 线程 {} 刷新被拒 code={}", i,
                                e.getErrorCode().code());
                    }
                    return null;
                }).toList();

        List<Future<Void>> futures = tasks.stream().map(pool::submit).toList();
        assertThat(ready.await(10, TimeUnit.SECONDS)).isTrue();
        start.countDown();
        for (Future<Void> f : futures) {
            f.get(10, TimeUnit.SECONDS);
        }
        pool.shutdown();

        log.info("[判定依据] 并发 {} 次: 成功={} 失败分类={}", threads,
                successes.size(), failureCodes);
        assertThat(successes).hasSize(1);
        assertThat(failureCodes).hasSize(threads - 1);
        // 第一个落败者直接观测到“已消费”-> refresh_token_reused 并撤销整链；
        // 其后到达的线程观测到链路已因重放撤销 -> session_revoked_refresh_reuse。
        // 两种分类都明确指向“重放”，彼此可区分且稳定。
        assertThat(failureCodes).isSubsetOf(
                ErrorCode.REFRESH_TOKEN_REUSED.code(),
                ErrorCode.SESSION_REVOKED_REFRESH_REUSE.code());
        assertThat(failureCodes).contains(ErrorCode.REFRESH_TOKEN_REUSED.code());

        // 整链在重放后被撤销：唯一“成功”的后继令牌也不能保持有效，
        // 即系统中不存在多个并行有效后继
        TokenPairResponse winner = successes.iterator().next();
        var winnerDecision = accessTokenService.authorize(
                "Bearer " + winner.accessToken(), Permission.PROFILE_READ);
        assertThat(winnerDecision.allowed()).isFalse();
        assertThat(winnerDecision.errorCode())
                .isEqualTo(ErrorCode.SESSION_REVOKED_REFRESH_REUSE.code());
    }

    // ------------------------------------------------------------------
    // 5. 登出：访问令牌与刷新令牌立即失效，原因=主动登出（可与过期区分）
    // ------------------------------------------------------------------

    @Test
    void logoutImmediatelyInvalidatesBothTokensWithLogoutReason() {
        Issued issued = login("svc_user", "password123");

        authService.logout(issued.pair().accessToken());

        var decision = accessTokenService.authorize(
                "Bearer " + issued.pair().accessToken(), Permission.PROFILE_READ);
        assertThat(decision.allowed()).isFalse();
        assertThat(decision.errorCode())
                .as("访问令牌因登出失效")
                .isEqualTo(ErrorCode.SESSION_REVOKED_LOGOUT.code());

        expectAuthError(
                () -> authService.refresh(new RefreshRequest(issued.pair().refreshToken())),
                ErrorCode.SESSION_REVOKED_LOGOUT);
        log.info("[判定依据] 登出后 access/refresh 均失败，错误码=session_revoked_logout");
    }

    // ------------------------------------------------------------------
    // 6. 密码变更：旧令牌立即失效，原因=密码变更，与登出/过期可区分
    // ------------------------------------------------------------------

    @Test
    void passwordChangeRevokesTokensWithDistinctReasonAndOldPasswordChecked() {
        Issued issued = login("svc_user", "password123");

        // 原密码错误必须被拒绝，且不产生任何撤销
        expectAuthError(
                () -> accountService.changePassword("svc_user", "wrong-old", "new-password1"),
                ErrorCode.OLD_PASSWORD_INCORRECT);

        accountService.changePassword("svc_user", "password123", "new-password1");

        var decision = accessTokenService.authorize(
                "Bearer " + issued.pair().accessToken(), Permission.PROFILE_READ);
        assertThat(decision.allowed()).isFalse();
        assertThat(decision.errorCode())
                .isEqualTo(ErrorCode.SESSION_REVOKED_PASSWORD_CHANGED.code());

        expectAuthError(
                () -> authService.refresh(new RefreshRequest(issued.pair().refreshToken())),
                ErrorCode.SESSION_REVOKED_PASSWORD_CHANGED);

        // 新密码可登录，旧密码不可
        expectAuthError(
                () -> authService.login(new LoginRequest("svc_user", "password123")),
                ErrorCode.INVALID_CREDENTIALS);
        Issued reLogin = login("svc_user", "new-password1");
        assertThat(accessTokenService.authorize(
                "Bearer " + reLogin.pair().accessToken(), Permission.PROFILE_READ).allowed())
                .isTrue();

        // 还原密码，避免影响其他测试
        accountService.changePassword("svc_user", "new-password1", "password123");
        log.info("[判定依据] 改密后旧令牌错误码=session_revoked_password_changed");
    }

    // ------------------------------------------------------------------
    // 7. 账户停用：在途令牌立即失效且原因可区分；重新启用后不恢复旧链
    // ------------------------------------------------------------------

    @Test
    void accountDisableRevokesActiveTokensWithDistinctReason() {
        createAccount("svc_toggle", "password123", Role.USER);
        Issued issued = login("svc_toggle", "password123");

        accountService.setStatus("svc_admin", "svc_toggle", false);

        var decision = accessTokenService.authorize(
                "Bearer " + issued.pair().accessToken(), Permission.PROFILE_READ);
        assertThat(decision.allowed()).isFalse();
        assertThat(decision.errorCode())
                .isEqualTo(ErrorCode.SESSION_REVOKED_ACCOUNT_DISABLED.code());

        expectAuthError(
                () -> authService.refresh(new RefreshRequest(issued.pair().refreshToken())),
                ErrorCode.SESSION_REVOKED_ACCOUNT_DISABLED);

        // 停用期间无法登录（对外仍统一 invalid_credentials）
        expectAuthError(
                () -> authService.login(new LoginRequest("svc_toggle", "password123")),
                ErrorCode.INVALID_CREDENTIALS);

        // 重新启用后：可登录，但旧链令牌仍然失效（撤销是终态）
        accountService.setStatus("svc_admin", "svc_toggle", true);
        Issued reLogin = login("svc_toggle", "password123");
        assertThat(accessTokenService.authorize(
                "Bearer " + reLogin.pair().accessToken(), Permission.PROFILE_READ).allowed())
                .isTrue();
        var oldDecision = accessTokenService.authorize(
                "Bearer " + issued.pair().accessToken(), Permission.PROFILE_READ);
        assertThat(oldDecision.allowed()).isFalse();
        assertThat(oldDecision.errorCode())
                .isEqualTo(ErrorCode.SESSION_REVOKED_ACCOUNT_DISABLED.code());
        log.info("[判定依据] 停用撤销错误码=session_revoked_account_disabled，启用不恢复旧链");
    }

    // ------------------------------------------------------------------
    // 8. 授权判定：缺失 / 格式错误 / 无效 / 过期 / 权限不足，彼此可区分
    // ------------------------------------------------------------------

    @Test
    void authorizationClassifiesEachDenialReasonDistinctly() {
        Issued issued = login("svc_user", "password123");
        String bearer = "Bearer " + issued.pair().accessToken();

        assertThat(accessTokenService.authorize(null, Permission.PROFILE_READ).errorCode())
                .isEqualTo(ErrorCode.MISSING_TOKEN.code());
        assertThat(accessTokenService.authorize("", Permission.PROFILE_READ).errorCode())
                .isEqualTo(ErrorCode.MISSING_TOKEN.code());
        assertThat(accessTokenService.authorize("Basic abc", Permission.PROFILE_READ).errorCode())
                .isEqualTo(ErrorCode.MALFORMED_AUTHORIZATION.code());
        assertThat(accessTokenService.authorize("Bearer ", Permission.PROFILE_READ).errorCode())
                .isEqualTo(ErrorCode.MALFORMED_AUTHORIZATION.code());
        assertThat(accessTokenService.authorize("Bearer not-a-real-token",
                        Permission.PROFILE_READ).errorCode())
                .isEqualTo(ErrorCode.INVALID_TOKEN.code());

        // 权限不足：USER 访问 ADMIN 专属权限
        var denied = accessTokenService.authorize(bearer, Permission.ADMIN_AUDIT_READ);
        assertThat(denied.allowed()).isFalse();
        assertThat(denied.errorCode())
                .isEqualTo(ErrorCode.INSUFFICIENT_PERMISSION.code());
        log.info("[输入] USER 令牌请求 ADMIN_AUDIT_READ => [判定依据] {}", denied.errorCode());

        // 过期：构造一张绑定同会话、已过期的访问令牌（过期与撤销可区分）
        String rawExpired = tokenGenerator.newAccessToken();
        AccessTokenInfo expiredInfo = new AccessTokenInfo(
                tokenHasher.hash(rawExpired), tokenGenerator.newId(),
                issued.access().getFamilyId(), issued.access().getSessionId(),
                "svc_user", Instant.now().minusSeconds(60), Instant.now().minusSeconds(1));
        accessTokenStore.save(expiredInfo);
        var expiredDecision = accessTokenService.authorize(
                "Bearer " + rawExpired, Permission.PROFILE_READ);
        assertThat(expiredDecision.allowed()).isFalse();
        assertThat(expiredDecision.errorCode())
                .as("普通过期必须区别于撤销")
                .isEqualTo(ErrorCode.TOKEN_EXPIRED.code());

        // 同会话的健康令牌仍可用
        assertThat(accessTokenService.authorize(bearer, Permission.PROFILE_READ).allowed())
                .isTrue();

        // 每次拒绝都写审计
        assertThat(auditStore.findByType("ACCESS_DENIED")).isNotEmpty();
        log.info("[判定依据] missing/malformed/invalid/expired/insufficient_permission 分类均独立稳定");
    }
}
