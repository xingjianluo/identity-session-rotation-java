package com.github.xingjianluo.identitysessionrotationjava.tests;

import com.github.xingjianluo.identitysessionrotationjava.account.Account;
import com.github.xingjianluo.identitysessionrotationjava.error.ApiException;
import com.github.xingjianluo.identitysessionrotationjava.error.ErrorCode;
import com.github.xingjianluo.identitysessionrotationjava.tests.support.MutableClock;
import com.github.xingjianluo.identitysessionrotationjava.tests.support.TestAccounts;
import com.github.xingjianluo.identitysessionrotationjava.tests.support.TestComponents;
import com.github.xingjianluo.identitysessionrotationjava.token.TokenPair;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Single-use refresh rotation, replay detection (chain revocation) and
 * concurrent refresh of one token.
 */
class RefreshRotationTest {

    private static final Logger log = LoggerFactory.getLogger(RefreshRotationTest.class);

    private final MutableClock clock = MutableClock.startAt(Instant.parse("2026-09-23T00:00:00Z"));
    private final TestComponents c = TestComponents.fresh(clock);

    private TokenPair login() {
        TestAccounts.create(c.accounts(), "acc-reader", "reader", "reader-password",
                Set.of("reader"), Set.of("read"));
        Account account = c.accountService().verifyLogin("reader", "reader-password");
        return c.tokenService().issueSession(account);
    }

    @Test
    void eachRotationIssuesNewOneTimeTokenAndOldTokenFails() {
        TokenPair first = login();
        TokenPair second = c.tokenService().rotate(first.refreshToken());
        log.info("[输入] 第一次轮换: old={} -> new={}",
                mask(first.refreshToken()), mask(second.refreshToken()));
        assertNotEquals(first.refreshToken(), second.refreshToken());

        // Leave the concurrency grace window before replaying the consumed link.
        clock.advanceSeconds(c.properties().getRefreshReuseGraceSeconds() + 1);
        ApiException replay = assertThrows(ApiException.class,
                () -> c.tokenService().rotate(first.refreshToken()));
        log.info("[判定依据] 越过宽限窗口后旧刷新令牌再次使用 code={} message={}",
                replay.code(), replay.detail());
        assertEquals(ErrorCode.REFRESH_TOKEN_REUSED, replay.code());

        // Replay burned the chain: even the newest token is now rejected.
        ApiException newest = assertThrows(ApiException.class,
                () -> c.tokenService().rotate(second.refreshToken()));
        log.info("[判定依据] 复用检测后新令牌也被拒 code={} message={}", newest.code(), newest.detail());
        assertEquals(ErrorCode.SESSION_REVOKED, newest.code());
    }

    @Test
    void concurrentRefreshOfSameTokenYieldsExactlyOneSuccessor() throws Exception {
        TokenPair pair = login();
        int threads = 20;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CyclicBarrier barrier = new CyclicBarrier(threads);
        AtomicInteger success = new AtomicInteger();
        AtomicInteger raceRejects = new AtomicInteger();
        List<Future<String>> futures = new ArrayList<>();

        for (int i = 0; i < threads; i++) {
            Callable<String> task = () -> {
                barrier.await(); // maximize contention: all threads hit rotate() together
                try {
                    TokenPair next = c.tokenService().rotate(pair.refreshToken());
                    success.incrementAndGet();
                    return "OK:" + next.refreshToken();
                } catch (ApiException ex) {
                    raceRejects.incrementAndGet();
                    return "REJECT:" + ex.code();
                }
            };
            futures.add(pool.submit(task));
        }

        List<String> winnerTokens = new ArrayList<>();
        for (Future<String> f : futures) {
            String result = f.get();
            log.info("[判定依据] 并发刷新结果 {}", result.replaceAll("rt_[a-f0-9]+", "rt_***"));
            if (result.startsWith("OK:")) {
                winnerTokens.add(result.substring(3));
            } else {
                assertTrue(result.endsWith(ErrorCode.REFRESH_TOKEN_RACE.name()),
                        "竞态失败方必须是 REFRESH_TOKEN_RACE，实际: " + result);
            }
        }
        pool.shutdown();

        log.info("[结论] 成功={} 竞态拒绝={} (要求成功恰为1，且胜者链路未被连带撤销)",
                success.get(), raceRejects.get());
        assertEquals(1, success.get());
        assertEquals(threads - 1, raceRejects.get());
        assertEquals(1, winnerTokens.size());

        // The winner's new token is a live, usable successor (no parallel successors exist).
        TokenPair winnerPair = new TokenPair(null, winnerTokens.get(0), 0);
        TokenPair next = c.tokenService().rotate(winnerPair.refreshToken());
        assertFalse(next.refreshToken().equals(pair.refreshToken()));
        clock.advanceSeconds(c.properties().getRefreshReuseGraceSeconds() + 1);
        ApiException laterReplay = assertThrows(ApiException.class,
                () -> c.tokenService().rotate(winnerPair.refreshToken()));
        assertEquals(ErrorCode.REFRESH_TOKEN_REUSED, laterReplay.code());
    }

    @Test
    void replayRevokesTheWholeChainAndIsAudited() {
        TokenPair first = login();
        TokenPair second = c.tokenService().rotate(first.refreshToken());
        TokenPair third = c.tokenService().rotate(second.refreshToken());

        // Attacker replays an old consumed link after the grace window.
        clock.advanceSeconds(c.properties().getRefreshReuseGraceSeconds() + 1);
        ApiException replay = assertThrows(ApiException.class,
                () -> c.tokenService().rotate(first.refreshToken()));
        assertEquals(ErrorCode.REFRESH_TOKEN_REUSED, replay.code());

        // Current access token stops working immediately.
        ApiException access = assertThrows(ApiException.class,
                () -> c.tokenService().authenticate(third.accessToken()));
        log.info("[判定依据] 复用检测后当前访问令牌 code={} message={}", access.code(), access.detail());
        assertEquals(ErrorCode.SESSION_REVOKED, access.code());
        assertTrue(access.detail().contains("REFRESH_TOKEN_REUSE_DETECTED"));

        // The newest refresh link is rejected as revoked-chain, not as another replay.
        ApiException currentRefresh = assertThrows(ApiException.class,
                () -> c.tokenService().rotate(third.refreshToken()));
        assertEquals(ErrorCode.SESSION_REVOKED, currentRefresh.code());

        long reuseEvents = c.audit().query(
                com.github.xingjianluo.identitysessionrotationjava.audit.AuditEventType
                        .REFRESH_TOKEN_REUSE_DETECTED, "acc-reader").size();
        assertTrue(reuseEvents >= 1, "复用检测必须写入审计");
        log.info("[结论] 审计中复用事件数={}", reuseEvents);
    }

    @Test
    void expiredRefreshTokenHasItsOwnCategory() {
        TokenPair pair = login();
        clock.advanceSeconds(c.properties().getRefreshTokenTtlSeconds() + 1);
        ApiException ex = assertThrows(ApiException.class,
                () -> c.tokenService().rotate(pair.refreshToken()));
        log.info("[判定依据] 刷新令牌过期 code={} message={}", ex.code(), ex.detail());
        assertEquals(ErrorCode.REFRESH_TOKEN_EXPIRED, ex.code());
    }

    private static String mask(String token) {
        return token == null ? null : token.substring(0, 6) + "***";
    }
}
