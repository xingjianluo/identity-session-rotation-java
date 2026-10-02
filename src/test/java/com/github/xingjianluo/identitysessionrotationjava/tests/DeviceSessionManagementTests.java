package com.github.xingjianluo.identitysessionrotationjava.tests;

import com.github.xingjianluo.identitysessionrotationjava.domain.AccessTokenInfo;
import com.github.xingjianluo.identitysessionrotationjava.domain.Account;
import com.github.xingjianluo.identitysessionrotationjava.domain.AccountStatus;
import com.github.xingjianluo.identitysessionrotationjava.domain.AuditEventType;
import com.github.xingjianluo.identitysessionrotationjava.domain.DeviceSession;
import com.github.xingjianluo.identitysessionrotationjava.domain.Permission;
import com.github.xingjianluo.identitysessionrotationjava.domain.RefreshTokenInfo;
import com.github.xingjianluo.identitysessionrotationjava.domain.Role;
import com.github.xingjianluo.identitysessionrotationjava.error.AuthException;
import com.github.xingjianluo.identitysessionrotationjava.error.ErrorCode;
import com.github.xingjianluo.identitysessionrotationjava.security.PasswordEncoder;
import com.github.xingjianluo.identitysessionrotationjava.security.TokenHasher;
import com.github.xingjianluo.identitysessionrotationjava.service.AccessTokenService;
import com.github.xingjianluo.identitysessionrotationjava.service.AuthService;
import com.github.xingjianluo.identitysessionrotationjava.service.DeviceSessionService;
import com.github.xingjianluo.identitysessionrotationjava.store.AccessTokenStore;
import com.github.xingjianluo.identitysessionrotationjava.store.AccountStore;
import com.github.xingjianluo.identitysessionrotationjava.store.AuditStore;
import com.github.xingjianluo.identitysessionrotationjava.store.RefreshTokenStore;
import com.github.xingjianluo.identitysessionrotationjava.web.dto.LoginRequest;
import com.github.xingjianluo.identitysessionrotationjava.web.dto.RefreshRequest;
import com.github.xingjianluo.identitysessionrotationjava.web.dto.TokenPairResponse;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 多设备会话管理场景测试（上限配置为 3，便于验证淘汰顺序）。
 *
 * <p>日志打印每个场景的输入（客户端标识、familyId）与判定依据（错误码），
 * 覆盖：会话查看、单会话撤销隔离、退出其他设备、超限淘汰顺序、
 * 撤销与并发刷新叠加、并发登录下的上限保持。
 */
@SpringBootTest(properties = "app.security.max-active-sessions-per-account=3")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DeviceSessionManagementTests {

    private static final Logger log =
            LoggerFactory.getLogger(DeviceSessionManagementTests.class);

    @Autowired private AuthService authService;
    @Autowired private AccessTokenService accessTokenService;
    @Autowired private DeviceSessionService deviceSessionService;
    @Autowired private AccountStore accountStore;
    @Autowired private AccessTokenStore accessTokenStore;
    @Autowired private RefreshTokenStore refreshTokenStore;
    @Autowired private AuditStore auditStore;
    @Autowired private PasswordEncoder passwordEncoder;
    @Autowired private TokenHasher tokenHasher;

    /** 一次设备登录的便捷视图。 */
    record Device(String client, TokenPairResponse pair, String familyId) {
    }

    @BeforeAll
    void setUp() {
        createAccount("dev_list", Role.USER);
        createAccount("dev_revoke_one", Role.USER);
        createAccount("dev_revoke_others", Role.USER);
        createAccount("dev_evict", Role.USER);
        createAccount("dev_race", Role.USER);
        createAccount("dev_concurrent", Role.USER);
    }

    private void createAccount(String username, Role... roles) {
        accountStore.save(new Account(username, passwordEncoder.encode("password123"),
                AccountStatus.ACTIVE, EnumSet.copyOf(List.of(roles))));
    }

    private Device login(String username, String client) {
        TokenPairResponse pair = authService.login(
                new LoginRequest(username, "password123", client));
        AccessTokenInfo access = accessTokenStore
                .findByHash(tokenHasher.hash(pair.accessToken())).orElseThrow();
        log.info("[输入] login username={} client={} -> familyId={}",
                username, client, access.getFamilyId());
        return new Device(client, pair, access.getFamilyId());
    }

    private String accessError(Device device) {
        return accessTokenService.authorize(
                "Bearer " + device.pair().accessToken(), Permission.PROFILE_READ).errorCode();
    }

    private ErrorCode refreshError(String refreshToken) {
        try {
            authService.refresh(new RefreshRequest(refreshToken));
            return null;
        } catch (AuthException e) {
            return e.getErrorCode();
        }
    }

    private long auditCount(String type, String username) {
        return auditStore.findByType(type).stream()
                .filter(e -> username.equals(e.username()))
                .count();
    }

    // ------------------------------------------------------------------
    // 1. 会话查看
    // ------------------------------------------------------------------

    @Test
    void listShowsActiveLoginsWithClientAndTimestamps() {
        Device mobile = login("dev_list", "mobile");
        Device web = login("dev_list", "web");

        List<DeviceSession> sessions = deviceSessionService.listActive("dev_list");
        log.info("[覆盖] 会话查看: 活跃登录数={}", sessions.size());

        assertThat(sessions).hasSize(2);
        assertThat(sessions).extracting(DeviceSession::getClient)
                .containsExactlyInAnyOrder("mobile", "web");
        for (DeviceSession s : sessions) {
            assertThat(s.getCreatedAt()).as("登录时间").isNotNull();
            assertThat(s.getLastActiveAt()).as("最近活跃时间").isNotNull();
            assertThat(s.getLastActiveAt()).isAfterOrEqualTo(s.getCreatedAt());
        }
        assertThat(auditCount(AuditEventType.DEVICE_SESSIONS_LISTED, "dev_list"))
                .as("查看动作应记入审计").isGreaterThanOrEqualTo(1);
        log.info("[判定依据] 列表含 client/createdAt/lastActiveAt, 审计 DEVICE_SESSIONS_LISTED 已记录");
    }

    // ------------------------------------------------------------------
    // 2. 单会话撤销的隔离效果
    // ------------------------------------------------------------------

    @Test
    void revokeOneSessionLeavesOthersUntouched() {
        Device mobile = login("dev_revoke_one", "mobile");
        Device web = login("dev_revoke_one", "web");

        deviceSessionService.revokeOne("dev_revoke_one", mobile.familyId());
        log.info("[覆盖] 单会话撤销: 撤销 familyId={}", mobile.familyId());

        // 被撤销的登录：访问与刷新都立即失败，且原因可与自然过期区分
        assertThat(accessError(mobile)).isEqualTo(ErrorCode.SESSION_REVOKED_BY_USER.code());
        assertThat(refreshError(mobile.pair().refreshToken()))
                .isEqualTo(ErrorCode.SESSION_REVOKED_BY_USER);
        // 未被点名的登录不受牵连
        assertThat(accessError(web)).isNull();
        assertThat(refreshError(web.pair().refreshToken())).isNull();
        // 列表只剩未被撤销的登录
        List<DeviceSession> remaining = deviceSessionService.listActive("dev_revoke_one");
        assertThat(remaining).extracting(DeviceSession::getFamilyId)
                .containsExactly(web.familyId());
        assertThat(auditCount(AuditEventType.DEVICE_SESSION_REVOKED, "dev_revoke_one"))
                .isEqualTo(1);
        log.info("[判定依据] 被撤销方={} 未撤销方=可正常访问与刷新",
                ErrorCode.SESSION_REVOKED_BY_USER.code());
    }

    @Test
    void revokeOneRejectsForeignOrUnknownSession() {
        Device own = login("dev_revoke_one", "tablet");
        Device foreign = login("dev_revoke_others", "laptop");

        ErrorCode foreignError = null;
        try {
            deviceSessionService.revokeOne("dev_revoke_one", foreign.familyId());
        } catch (AuthException e) {
            foreignError = e.getErrorCode();
        }
        assertThat(foreignError).isEqualTo(ErrorCode.SESSION_NOT_FOUND);

        ErrorCode unknownError = null;
        try {
            deviceSessionService.revokeOne("dev_revoke_one", "vid_not_exists");
        } catch (AuthException e) {
            unknownError = e.getErrorCode();
        }
        assertThat(unknownError).isEqualTo(ErrorCode.SESSION_NOT_FOUND);
        // 双方登录均不受影响
        assertThat(accessError(own)).isNull();
        assertThat(accessError(foreign)).isNull();
        log.info("[判定依据] 撤销他人/不存在会话 => {}", ErrorCode.SESSION_NOT_FOUND.code());
    }

    // ------------------------------------------------------------------
    // 3. 退出其他所有设备
    // ------------------------------------------------------------------

    @Test
    void revokeOthersKeepsOnlyCurrentSession() {
        Device first = login("dev_revoke_others", "mobile");
        Device second = login("dev_revoke_others", "web");
        Device current = login("dev_revoke_others", "cli");

        int revoked = deviceSessionService.revokeOthers("dev_revoke_others",
                current.familyId());
        log.info("[覆盖] 退出其他设备: 保留 familyId={} 撤销数={}", current.familyId(), revoked);

        assertThat(revoked).isEqualTo(2);
        assertThat(accessError(first)).isEqualTo(ErrorCode.SESSION_REVOKED_BY_USER.code());
        assertThat(accessError(second)).isEqualTo(ErrorCode.SESSION_REVOKED_BY_USER.code());
        assertThat(refreshError(first.pair().refreshToken()))
                .isEqualTo(ErrorCode.SESSION_REVOKED_BY_USER);
        // 当前会话完全不受影响：可访问、可刷新
        assertThat(accessError(current)).isNull();
        assertThat(refreshError(current.pair().refreshToken())).isNull();

        List<DeviceSession> remaining = deviceSessionService.listActive("dev_revoke_others");
        assertThat(remaining).extracting(DeviceSession::getFamilyId)
                .containsExactly(current.familyId());
        assertThat(auditCount(AuditEventType.OTHER_SESSIONS_REVOKED, "dev_revoke_others"))
                .isGreaterThanOrEqualTo(1);
        log.info("[判定依据] 其他设备={}, 当前会话不受影响",
                ErrorCode.SESSION_REVOKED_BY_USER.code());
    }

    // ------------------------------------------------------------------
    // 4. 超限淘汰：最久未活动最先被清掉
    // ------------------------------------------------------------------

    @Test
    void evictionFollowsLeastRecentlyActiveOrder() {
        Device oldest = login("dev_evict", "old-tablet");
        Device middle = login("dev_evict", "middle-web");
        Device newest = login("dev_evict", "new-mobile");

        // oldest 设备重新活跃一次，使 middle 变成“最久未活动”
        accessTokenService.authorize("Bearer " + oldest.pair().accessToken(),
                Permission.PROFILE_READ);

        Device extra = login("dev_evict", "extra-cli");
        log.info("[覆盖] 超限淘汰: max=3, 第 4 个登录 familyId={}", extra.familyId());

        // middle 最久未活动 -> 被淘汰，且失效原因可解释、区别于自然过期
        assertThat(accessError(middle)).isEqualTo(ErrorCode.SESSION_REVOKED_EVICTED.code());
        assertThat(refreshError(middle.pair().refreshToken()))
                .isEqualTo(ErrorCode.SESSION_REVOKED_EVICTED);
        // 其余登录不受影响
        assertThat(accessError(oldest)).isNull();
        assertThat(accessError(newest)).isNull();
        assertThat(accessError(extra)).isNull();

        List<DeviceSession> active = deviceSessionService.listActive("dev_evict");
        assertThat(active).extracting(DeviceSession::getFamilyId)
                .containsExactlyInAnyOrder(oldest.familyId(), newest.familyId(),
                        extra.familyId());
        assertThat(auditCount(AuditEventType.SESSION_EVICTED_LIMIT, "dev_evict"))
                .isEqualTo(1);
        log.info("[判定依据] 被淘汰方={} (区别于 token_expired), 保留方均可访问",
                ErrorCode.SESSION_REVOKED_EVICTED.code());
    }

    // ------------------------------------------------------------------
    // 5. 撤销与并发刷新叠加
    // ------------------------------------------------------------------

    @Test
    void revokeRacingWithRefreshLeavesNoUsableTokens() throws Exception {
        for (int round = 0; round < 10; round++) {
            Device device = login("dev_race", "round-" + round);
            AtomicReference<TokenPairResponse> refreshed = new AtomicReference<>();
            AtomicReference<ErrorCode> refreshFailure = new AtomicReference<>();
            CountDownLatch ready = new CountDownLatch(2);
            CountDownLatch go = new CountDownLatch(1);

            Runnable refresher = () -> {
                ready.countDown();
                await(go);
                try {
                    refreshed.set(authService.refresh(
                            new RefreshRequest(device.pair().refreshToken())));
                } catch (AuthException e) {
                    refreshFailure.set(e.getErrorCode());
                }
            };
            Runnable revoker = () -> {
                ready.countDown();
                await(go);
                deviceSessionService.revokeOne("dev_race", device.familyId());
            };

            ExecutorService pool = Executors.newFixedThreadPool(2);
            Future<?> f1 = pool.submit(refresher);
            Future<?> f2 = pool.submit(revoker);
            await(ready);
            go.countDown();
            f1.get(10, TimeUnit.SECONDS);
            f2.get(10, TimeUnit.SECONDS);
            pool.shutdown();

            // 无论谁先拿到 family 锁，撤销完成后该登录不能再换到可用的新令牌
            if (refreshed.get() != null) {
                // 刷新先完成：新令牌对必须随后被撤销一并覆盖
                assertThat(accessTokenService.authorize(
                        "Bearer " + refreshed.get().accessToken(),
                        Permission.PROFILE_READ).errorCode())
                        .isEqualTo(ErrorCode.SESSION_REVOKED_BY_USER.code());
                assertThat(refreshError(refreshed.get().refreshToken()))
                        .isEqualTo(ErrorCode.SESSION_REVOKED_BY_USER);
            } else {
                // 撤销先完成：刷新必须失败，且原因是撤销而非过期
                assertThat(refreshFailure.get())
                        .isEqualTo(ErrorCode.SESSION_REVOKED_BY_USER);
            }
            assertThat(accessError(device))
                    .isEqualTo(ErrorCode.SESSION_REVOKED_BY_USER.code());
            assertThat(refreshError(device.pair().refreshToken()))
                    .isEqualTo(ErrorCode.SESSION_REVOKED_BY_USER);
        }
        log.info("[覆盖] 撤销与并发刷新叠加 x10: 撤销完成后无任何可用令牌, "
                + "判定={} (与自然过期 token_expired 明确区分)",
                ErrorCode.SESSION_REVOKED_BY_USER.code());
    }

    // ------------------------------------------------------------------
    // 6. 并发登录下的上限保持
    // ------------------------------------------------------------------

    @Test
    void concurrentLoginsNeverExceedLimit() throws Exception {
        int logins = 8;
        CountDownLatch ready = new CountDownLatch(logins);
        CountDownLatch go = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(logins);
        List<Future<Device>> futures = new ArrayList<>();
        for (int i = 0; i < logins; i++) {
            String client = "client-" + i;
            futures.add(pool.submit(() -> {
                ready.countDown();
                await(go);
                return login("dev_concurrent", client);
            }));
        }
        await(ready);
        go.countDown();

        List<Device> devices = new ArrayList<>();
        for (Future<Device> f : futures) {
            devices.add(f.get(15, TimeUnit.SECONDS));
        }
        pool.shutdown();
        log.info("[覆盖] 并发登录: {} 个客户端同时登录, max=3", logins);

        // 上限不被冲破：恰好 3 个活跃登录
        List<DeviceSession> active = deviceSessionService.listActive("dev_concurrent");
        assertThat(active).hasSize(3);
        // 淘汰数量可预期：8 - 3 = 5
        assertThat(auditCount(AuditEventType.SESSION_EVICTED_LIMIT, "dev_concurrent"))
                .isEqualTo(logins - 3);

        // 留下的登录都能正常访问，被清掉的都以可解释原因失效
        List<String> activeIds = active.stream().map(DeviceSession::getFamilyId).toList();
        int evicted = 0;
        for (Device d : devices) {
            if (activeIds.contains(d.familyId())) {
                assertThat(accessError(d)).as("留下的登录应可访问").isNull();
            } else {
                assertThat(accessError(d)).as("被清掉的登录应失效")
                        .isEqualTo(ErrorCode.SESSION_REVOKED_EVICTED.code());
                assertThat(refreshError(d.pair().refreshToken()))
                        .isEqualTo(ErrorCode.SESSION_REVOKED_EVICTED);
                evicted++;
            }
        }
        assertThat(evicted).isEqualTo(logins - 3);
        log.info("[判定依据] 活跃=3, 淘汰=5, 被淘汰方={}",
                ErrorCode.SESSION_REVOKED_EVICTED.code());
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await(10, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }
}
