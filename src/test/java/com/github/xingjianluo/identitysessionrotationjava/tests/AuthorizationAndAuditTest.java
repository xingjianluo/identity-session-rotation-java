package com.github.xingjianluo.identitysessionrotationjava.tests;

import com.github.xingjianluo.identitysessionrotationjava.account.Account;
import com.github.xingjianluo.identitysessionrotationjava.audit.AuditEvent;
import com.github.xingjianluo.identitysessionrotationjava.audit.AuditEventType;
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
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Role/permission decisions, the stable error categories for protected
 * entry points, and audit-record queryability for every rejection class.
 */
class AuthorizationAndAuditTest {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationAndAuditTest.class);

    private final MutableClock clock = MutableClock.startAt(Instant.parse("2026-09-23T00:00:00Z"));
    private final TestComponents c = TestComponents.fresh(clock);

    private TokenPair loginReader() {
        TestAccounts.create(c.accounts(), "acc-reader", "reader", "reader-password",
                Set.of("reader"), Set.of("read"));
        Account account = c.accountService().verifyLogin("reader", "reader-password");
        return c.tokenService().issueSession(account);
    }

    @Test
    void missingPermissionIsDeniedAndDistinguishedFromAuthFailures() {
        TokenPair pair = loginReader();
        TokenService.AuthContext ctx = c.tokenService().authenticate(pair.accessToken());

        c.authorization().requirePermission(ctx, "read"); // allowed
        ApiException denied = assertThrows(ApiException.class,
                () -> c.authorization().requirePermission(ctx, "admin:audit"));
        log.info("[判定依据] 权限不足 code={} httpStatus={} message={}",
                denied.code(), denied.code().httpStatus(), denied.detail());
        assertEquals(ErrorCode.PERMISSION_DENIED, denied.code());
        assertEquals(403, denied.code().httpStatus());
        assertThrows(ApiException.class,
                () -> c.authorization().requireRole(ctx, "admin"));

        List<AuditEvent> deniedEvents =
                c.audit().query(AuditEventType.ACCESS_DENIED, "acc-reader");
        assertFalse(deniedEvents.isEmpty());
        log.info("[结论] ACCESS_DENIED 审计记录数={} 最近一条={}",
                deniedEvents.size(), deniedEvents.get(deniedEvents.size() - 1).detail());
    }

    @Test
    void protectedDecisionCategoriesAreAllDistinguishable() {
        TokenPair pair = loginReader();

        // 1) unknown token
        ApiException invalid = assertThrows(ApiException.class,
                () -> c.tokenService().authenticate("at_does_not_exist"));
        // 2) expired token
        clock.advanceSeconds(c.properties().getAccessTokenTtlSeconds() + 1);
        ApiException expired = assertThrows(ApiException.class,
                () -> c.tokenService().authenticate(pair.accessToken()));
        // 3) revoked session (via replay after grace window)
        clock.advanceSeconds(1); // past TTL; rotate with refresh is still within refresh TTL
        TokenPair second = c.tokenService().rotate(pair.refreshToken());
        clock.advanceSeconds(c.properties().getRefreshReuseGraceSeconds() + 1);
        ApiException replay = assertThrows(ApiException.class,
                () -> c.tokenService().rotate(pair.refreshToken()));
        ApiException revoked = assertThrows(ApiException.class,
                () -> c.tokenService().authenticate(second.accessToken()));
        // 4) insufficient permission on a valid session happens before expiry tests:
        log.info("[判定依据] 四类受保护入口错误: TOKEN_INVALID={}, TOKEN_EXPIRED={}, "
                        + "REFRESH_TOKEN_REUSED={}, SESSION_REVOKED({})",
                invalid.code(), expired.code(), replay.code(), revoked.detail());

        assertEquals(ErrorCode.TOKEN_INVALID, invalid.code());
        assertEquals(ErrorCode.TOKEN_EXPIRED, expired.code());
        assertEquals(ErrorCode.REFRESH_TOKEN_REUSED, replay.code());
        assertEquals(ErrorCode.SESSION_REVOKED, revoked.code());
        assertTrue(revoked.detail().contains("REFRESH_TOKEN_REUSE_DETECTED"));
        assertEquals(401, invalid.code().httpStatus());
    }

    @Test
    void loginRefreshRevocationAndDenialEventsAreAllAudited() {
        // failed login (unknown user)
        assertThrows(ApiException.class,
                () -> c.accountService().verifyLogin("ghost", "x"));

        TokenPair pair = loginReader();
        // successful rotation
        TokenPair second = c.tokenService().rotate(pair.refreshToken());
        // password change revokes chain
        c.accountService().changePassword("acc-reader", "new-password");
        assertThrows(ApiException.class,
                () -> c.tokenService().authenticate(second.accessToken()));

        List<AuditEvent> all = c.audit().all();
        log.info("[输入/判定] 全部审计事件:");
        all.forEach(e -> log.info("  {} account={} session={} detail={}",
                e.type(), e.accountId(),
                e.sessionId() == null ? "-" : e.sessionId().substring(0, 10) + "***",
                e.detail()));

        assertTrue(c.audit().query(AuditEventType.LOGIN_FAILURE, null).stream()
                .anyMatch(e -> "username=ghost reason=unknown_username".equals(e.detail())));
        assertTrue(c.audit().query(AuditEventType.TOKEN_REFRESHED, "acc-reader").size() >= 1);
        assertTrue(c.audit().query(AuditEventType.PASSWORD_CHANGED, "acc-reader").size() == 1);
        assertTrue(c.audit().query(AuditEventType.SESSION_REVOKED, "acc-reader").stream()
                .anyMatch(e -> e.detail().contains("PASSWORD_CHANGED")));
    }

    @Test
    void missingTokenAndMalformedHeaderAreStableInvalidToken() {
        ApiException none = assertThrows(ApiException.class,
                () -> c.tokenService().authenticate(null));
        ApiException blank = assertThrows(ApiException.class,
                () -> c.tokenService().authenticate("  "));
        assertEquals(ErrorCode.TOKEN_INVALID, none.code());
        assertEquals(ErrorCode.TOKEN_INVALID, blank.code());
    }
}
