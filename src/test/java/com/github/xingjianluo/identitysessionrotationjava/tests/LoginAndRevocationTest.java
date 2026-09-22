package com.github.xingjianluo.identitysessionrotationjava.tests;

import com.github.xingjianluo.identitysessionrotationjava.account.Account;
import com.github.xingjianluo.identitysessionrotationjava.error.ApiException;
import com.github.xingjianluo.identitysessionrotationjava.error.ErrorCode;
import com.github.xingjianluo.identitysessionrotationjava.tests.support.MutableClock;
import com.github.xingjianluo.identitysessionrotationjava.tests.support.TestAccounts;
import com.github.xingjianluo.identitysessionrotationjava.tests.support.TestComponents;
import com.github.xingjianluo.identitysessionrotationjava.token.TokenPair;
import com.github.xingjianluo.identitysessionrotationjava.token.TokenService;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Login verification, token-session binding, and the distinction between
 * ordinary expiry and explicit revocation (with reasons).
 */
class LoginAndRevocationTest {

    private static final Logger log = LoggerFactory.getLogger(LoginAndRevocationTest.class);

    private final MutableClock clock = MutableClock.startAt(Instant.parse("2026-09-23T00:00:00Z"));
    private final TestComponents c = TestComponents.fresh(clock);

    private Account reader() {
        return TestAccounts.create(c.accounts(), "acc-reader", "reader", "reader-password",
                Set.of("reader"), Set.of("read"));
    }

    private ErrorCode loginError(String username, String password) {
        log.info("[输入] 登录 username={} password={}", username, password);
        ApiException ex = assertThrows(ApiException.class,
                () -> c.accountService().verifyLogin(username, password));
        log.info("[判定依据] 登录失败错误码={} 信息={} (对未知用户/错密码必须一致)",
                ex.code(), ex.detail());
        return ex.code();
    }

    @Test
    void loginFailuresNeverRevealAccountExistence() {
        reader();
        assertEquals(ErrorCode.INVALID_CREDENTIALS, loginError("nobody", "whatever"));
        assertEquals(ErrorCode.INVALID_CREDENTIALS, loginError("reader", "wrong-password"));
        c.accountService().disable("acc-reader");
        assertEquals(ErrorCode.INVALID_CREDENTIALS, loginError("reader", "reader-password"));
        log.info("[结论] 未知用户、密码错误、账户停用全部映射为 INVALID_CREDENTIALS");
    }

    @Test
    void accessTokenIsBoundToSessionAndExpiresIndependentlyOfRefresh() {
        reader();
        Account account = c.accountService().verifyLogin("reader", "reader-password");
        TokenPair pair = c.tokenService().issueSession(account);
        TokenService.AuthContext ctx = c.tokenService().authenticate(pair.accessToken());
        log.info("[输入] 登录后访问令牌={}, 判定会话={}", mask(pair.accessToken()), ctx.sessionId());

        clock.advanceSeconds(c.properties().getAccessTokenTtlSeconds() + 1);
        ApiException expired = assertThrows(ApiException.class,
                () -> c.tokenService().authenticate(pair.accessToken()));
        log.info("[判定依据] 超过访问令牌TTL({}s): code={} message={}",
                c.properties().getAccessTokenTtlSeconds(), expired.code(), expired.detail());
        assertEquals(ErrorCode.TOKEN_EXPIRED, expired.code());

        // The session is still active: refresh must succeed and stay on the same chain.
        TokenPair rotated = c.tokenService().rotate(pair.refreshToken());
        TokenService.AuthContext afterRotate = c.tokenService().authenticate(rotated.accessToken());
        assertEquals(ctx.sessionId(), afterRotate.sessionId());
        log.info("[结论] 访问令牌过期≠会话失效；轮换后仍绑定同一会话 {}", ctx.sessionId());
    }

    @Test
    void passwordChangeImmediatelyRevokesTokensWithDistinctReason() {
        reader();
        Account account = c.accountService().verifyLogin("reader", "reader-password");
        TokenPair pair = c.tokenService().issueSession(account);

        c.accountService().changePassword("acc-reader", "brand-new-password");
        log.info("[输入] 账户已改密，重放旧访问令牌与旧刷新令牌");

        ApiException access = assertThrows(ApiException.class,
                () -> c.tokenService().authenticate(pair.accessToken()));
        ApiException refresh = assertThrows(ApiException.class,
                () -> c.tokenService().rotate(pair.refreshToken()));
        log.info("[判定依据] 旧访问令牌 code={} message={}; 旧刷新令牌 code={} message={}",
                access.code(), access.detail(), refresh.code(), refresh.detail());
        assertEquals(ErrorCode.SESSION_REVOKED, access.code());
        assertEquals(ErrorCode.SESSION_REVOKED, refresh.code());
        assertNotEquals(ErrorCode.TOKEN_EXPIRED, access.code());
    }

    @Test
    void logoutImmediatelyRevokesWithLogoutReason() {
        reader();
        Account account = c.accountService().verifyLogin("reader", "reader-password");
        TokenPair pair = c.tokenService().issueSession(account);

        c.tokenService().logout(pair.accessToken());
        ApiException access = assertThrows(ApiException.class,
                () -> c.tokenService().authenticate(pair.accessToken()));
        ApiException refresh = assertThrows(ApiException.class,
                () -> c.tokenService().rotate(pair.refreshToken()));
        log.info("[判定依据] 登出后访问 code={} message={}; 刷新 code={} message={}",
                access.code(), access.detail(), refresh.code(), refresh.detail());
        assertEquals(ErrorCode.SESSION_REVOKED, access.code());
        assertEquals(ErrorCode.SESSION_REVOKED, refresh.code());
    }

    @Test
    void disablingAccountInvalidatesOutstandingTokens() {
        reader();
        Account account = c.accountService().verifyLogin("reader", "reader-password");
        TokenPair pair = c.tokenService().issueSession(account);

        c.accountService().disable("acc-reader");
        ApiException access = assertThrows(ApiException.class,
                () -> c.tokenService().authenticate(pair.accessToken()));
        log.info("[判定依据] 停用后旧令牌 code={} message={}", access.code(), access.detail());
        assertEquals(ErrorCode.SESSION_REVOKED, access.code());
    }

    private static String mask(String token) {
        return token == null ? null : token.substring(0, 6) + "***";
    }
}
