package com.github.xingjianluo.identitysessionrotationjava.tests;

import com.github.xingjianluo.identitysessionrotationjava.config.SecurityProperties;
import com.github.xingjianluo.identitysessionrotationjava.domain.AccessTokenInfo;
import com.github.xingjianluo.identitysessionrotationjava.domain.Account;
import com.github.xingjianluo.identitysessionrotationjava.domain.AccountStatus;
import com.github.xingjianluo.identitysessionrotationjava.domain.AuditEvent;
import com.github.xingjianluo.identitysessionrotationjava.domain.AuditEventType;
import com.github.xingjianluo.identitysessionrotationjava.domain.DeviceSession;
import com.github.xingjianluo.identitysessionrotationjava.domain.Permission;
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
import com.github.xingjianluo.identitysessionrotationjava.store.DeviceSessionStore;
import com.github.xingjianluo.identitysessionrotationjava.web.dto.LoginRequest;
import com.github.xingjianluo.identitysessionrotationjava.web.dto.RefreshRequest;
import com.github.xingjianluo.identitysessionrotationjava.web.dto.TokenPairResponse;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 登录上限淘汰的“新登录保护”回归测试（上限配置为 2）。
 *
 * <p>复现并守住的核心语义：触发淘汰的那次新登录必须永远保留，
 * 能被清掉的只是这次登录之前就已存在的登录；并发登录叠加并发
 * 访问/刷新时，活跃数不冲破上限、淘汰结果稳定可预期；上限取
 * 边界值（0 或小于当前活跃数）时，刚登录成功的那一个始终可用。
 *
 * <p>日志打印每个场景的输入（客户端标识、familyId、上限取值）与
 * 判定依据（错误码、活跃集合），便于从单测日志核对覆盖情况。
 */
@SpringBootTest(properties = "app.security.max-active-sessions-per-account=2")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SessionLimitProtectionTests {

    private static final Logger log =
            LoggerFactory.getLogger(SessionLimitProtectionTests.class);

    private static final int MAX = 2;

    @Autowired private AuthService authService;
    @Autowired private AccessTokenService accessTokenService;
    @Autowired private DeviceSessionService deviceSessionService;
    @Autowired private AccountStore accountStore;
    @Autowired private AccessTokenStore accessTokenStore;
    @Autowired private DeviceSessionStore deviceSessionStore;
    @Autowired private AuditStore auditStore;
    @Autowired private PasswordEncoder passwordEncoder;
    @Autowired private TokenHasher tokenHasher;
    @Autowired private SecurityProperties properties;

    /** 一次设备登录的便捷视图。 */
    record Device(String client, TokenPairResponse pair, String familyId) {
    }

    @BeforeAll
    void setUp() {
        createAccount("lp_replay");
        createAccount("lp_race");
        createAccount("lp_zero");
        createAccount("lp_shrink");
    }

    @AfterEach
    void restoreLimit() {
        properties.setMaxActiveSessionsPerAccount(MAX);
    }

    private void createAccount(String username) {
        accountStore.save(new Account(username, passwordEncoder.encode("password123"),
                AccountStatus.ACTIVE, EnumSet.of(Role.USER)));
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

    private List<String> activeFamilyIds(String username) {
        return deviceSessionService.listActive(username).stream()
                .map(DeviceSession::getFamilyId).toList();
    }

    private boolean isActive(String familyId) {
        return deviceSessionStore.findByFamilyId(familyId)
                .map(DeviceSession::isActive).orElse(false);
    }

    // ------------------------------------------------------------------
    // 1. 确定性复现：登录锁内窗口被并发 touch 插入时，新登录不得被清
    // ------------------------------------------------------------------

    @Test
    void freshLoginIsNeverEvictedWhenOthersAreTouchedDuringLogin() {
        String username = "lp_replay";
        properties.setMaxActiveSessionsPerAccount(1);

        // 两个本次登录之前就已存在的登录
        DeviceSession old1 = deviceSessionService.registerLogin(username,
                "fam-replay-old-1", "old-1");
        DeviceSession old2 = deviceSessionService.registerLogin(username,
                "fam-replay-old-2", "old-2");
        // 新登录登记（lastActiveAt = 登记时刻）
        DeviceSession fresh = deviceSessionService.registerLogin(username,
                "fam-replay-new", "new");
        // 重放登录锁内的交错窗口：其他设备的并发访问/刷新（touch 不持有
        // 账号锁）把已有登录的最近活跃时间刷到新登录登记时间之后
        old1.touch(Instant.now());
        old2.touch(Instant.now());
        log.info("[覆盖] 锁内交错复现: max=1, 新登录 familyId={} 的 lastActiveAt "
                + "早于两个旧登录的 touch 时间", fresh.getFamilyId());

        deviceSessionService.enforceLimit(username, fresh.getFamilyId());

        // 新登录必须保留；被清掉的只能是此前已存在的登录（按最久未活动次序）
        assertThat(isActive(fresh.getFamilyId())).as("触发淘汰的新登录必须保留").isTrue();
        assertThat(isActive(old1.getFamilyId())).as("旧登录 old1 应被清掉").isFalse();
        assertThat(isActive(old2.getFamilyId())).as("旧登录 old2 应被清掉").isFalse();
        assertThat(activeFamilyIds(username)).containsExactly(fresh.getFamilyId());

        // 淘汰次序可预期：最久未活动的 old1 先被清
        List<String> evictedOrder = auditStore
                .findByType(AuditEventType.SESSION_EVICTED_LIMIT).stream()
                .filter(e -> username.equals(e.username()))
                .map(AuditEvent::familyId).toList();
        assertThat(evictedOrder)
                .containsExactly(old1.getFamilyId(), old2.getFamilyId());
        log.info("[判定依据] 新登录保留, 淘汰次序={} (最久未活动优先)", evictedOrder);
    }

    // ------------------------------------------------------------------
    // 2. 并发压测：多客户端同时登录 + 期间已有设备不停访问/刷新
    // ------------------------------------------------------------------

    @Test
    void concurrentLoginsWithConcurrentTouchKeepInvariants() throws Exception {
        String username = "lp_race";
        // 两个老设备：一个不停访问（touch），一个不停刷新（touch + 轮换）
        Device accessor = login(username, "old-accessor");
        Device refresher = login(username, "old-refresher");
        AtomicReference<TokenPairResponse> refresherLatest =
                new AtomicReference<>(refresher.pair());
        AtomicBoolean stop = new AtomicBoolean(false);

        ExecutorService touchPool = Executors.newFixedThreadPool(2);
        touchPool.submit(() -> {
            while (!stop.get()) {
                accessTokenService.authorize("Bearer " + accessor.pair().accessToken(),
                        Permission.PROFILE_READ);
            }
        });
        touchPool.submit(() -> {
            while (!stop.get()) {
                try {
                    refresherLatest.set(authService.refresh(new RefreshRequest(
                            refresherLatest.get().refreshToken())));
                } catch (AuthException e) {
                    return; // 老设备被合法淘汰后退出
                }
            }
        });

        int rounds = 15;
        int loginsPerRound = 3;
        List<Device> all = new CopyOnWriteArrayList<>();
        all.add(accessor);
        try {
            for (int r = 0; r < rounds; r++) {
                CountDownLatch ready = new CountDownLatch(loginsPerRound);
                CountDownLatch go = new CountDownLatch(1);
                ExecutorService pool = Executors.newFixedThreadPool(loginsPerRound);
                List<Future<Device>> futures = new ArrayList<>();
                for (int i = 0; i < loginsPerRound; i++) {
                    String client = "round-" + r + "-client-" + i;
                    futures.add(pool.submit(() -> {
                        ready.countDown();
                        await(go);
                        return login(username, client);
                    }));
                }
                await(ready);
                go.countDown();
                List<Device> roundDevices = new ArrayList<>();
                for (Future<Device> f : futures) {
                    roundDevices.add(f.get(15, TimeUnit.SECONDS));
                }
                pool.shutdown();
                all.addAll(roundDevices);

                List<String> active = activeFamilyIds(username);
                // 不变量 1：活跃数不冲破上限，且至少保留一个
                assertThat(active.size())
                        .as("第 %d 轮后活跃登录数应在 [1, %d] 内", r, MAX)
                        .isBetween(1, MAX);
                // 不变量 2：本轮最后完成登录关键段的那个登录必须存活且立即可用。
                // 完成次序以 LOGIN_SUCCESS 审计事件为准（它在账号锁内记录，
                // 其 id 顺序即锁内串行顺序；客户端侧计时无法可靠反映该顺序）。
                // 最后完成者之后没有任何淘汰能清掉它。
                java.util.Set<String> roundIds = new java.util.HashSet<>();
                roundDevices.forEach(d -> roundIds.add(d.familyId()));
                String lastLoginFamily = auditStore
                        .findByType(AuditEventType.LOGIN_SUCCESS).stream()
                        .filter(e -> username.equals(e.username()))
                        .filter(e -> roundIds.contains(e.familyId()))
                        .max(Comparator.comparingLong(AuditEvent::id))
                        .map(AuditEvent::familyId).orElseThrow();
                Device lastCompleted = roundDevices.stream()
                        .filter(d -> d.familyId().equals(lastLoginFamily))
                        .findFirst().orElseThrow();
                assertThat(active).as("最后完成登录关键段的登录必须保留")
                        .contains(lastCompleted.familyId());
                assertThat(accessError(lastCompleted)).as("该登录立即可用").isNull();
                // 不变量 3：活跃的都可访问；被清掉的都以可解释原因失效
                for (Device d : all) {
                    if (active.contains(d.familyId())) {
                        assertThat(accessError(d)).as("留下的登录应可访问").isNull();
                    } else {
                        assertThat(accessError(d)).as("被清掉的登录应以 evicted 失效")
                                .isEqualTo(ErrorCode.SESSION_REVOKED_EVICTED.code());
                    }
                }
                if (r % 5 == 4) {
                    log.info("[覆盖] 并发压测进度: 第 {} 轮后活跃数={} (上限={})",
                            r + 1, active.size(), MAX);
                }
            }
        } finally {
            stop.set(true);
            touchPool.shutdown();
            touchPool.awaitTermination(10, TimeUnit.SECONDS);
        }

        // 收尾：刷新设备若仍活跃，其最新令牌对可用；若被清，则是最久未活动淘汰
        List<String> active = activeFamilyIds(username);
        if (active.contains(refresher.familyId())) {
            assertThat(accessTokenService.authorize(
                    "Bearer " + refresherLatest.get().accessToken(),
                    Permission.PROFILE_READ).errorCode()).isNull();
        } else {
            assertThat(accessTokenService.authorize(
                    "Bearer " + refresherLatest.get().accessToken(),
                    Permission.PROFILE_READ).errorCode())
                    .isEqualTo(ErrorCode.SESSION_REVOKED_EVICTED.code());
        }
        log.info("[判定依据] {} 轮 x {} 并发登录 + 持续访问/刷新: 活跃数恒在 [1,{}], "
                + "每轮最晚完成的登录均保留且可用, 被清者={}",
                rounds, loginsPerRound, MAX, ErrorCode.SESSION_REVOKED_EVICTED.code());
    }

    // ------------------------------------------------------------------
    // 3. 上限边界：上限为 0
    // ------------------------------------------------------------------

    @Test
    void zeroLimitKeepsOnlyTheFreshLogin() {
        String username = "lp_zero";
        properties.setMaxActiveSessionsPerAccount(0);
        log.info("[覆盖] 上限边界: max=0");

        Device first = login(username, "first");
        // 上限 0：刚登录成功的这一个仍然可用（实际保留数下限为 1）
        assertThat(accessError(first)).as("max=0 时刚登录的会话必须可用").isNull();
        assertThat(activeFamilyIds(username)).containsExactly(first.familyId());

        Device second = login(username, "second");
        // 第二次登录：清掉之前的 first，保留自己——不会“全部登录成功却全部失效”
        assertThat(accessError(second)).as("新登录必须保留").isNull();
        assertThat(accessError(first)).as("之前的登录被新登录挤掉")
                .isEqualTo(ErrorCode.SESSION_REVOKED_EVICTED.code());
        assertThat(activeFamilyIds(username)).containsExactly(second.familyId());
        log.info("[判定依据] max=0: 任一时刻仅保留最近一次登录, 其令牌可用, "
                + "被挤掉者={}", ErrorCode.SESSION_REVOKED_EVICTED.code());
    }

    // ------------------------------------------------------------------
    // 4. 上限边界：上限收紧到比当前活跃数还小
    // ------------------------------------------------------------------

    @Test
    void limitBelowCurrentActiveCountEvictsOnlyPreExistingLogins() {
        String username = "lp_shrink";
        Device a = login(username, "a");
        Device b = login(username, "b");
        // a 重新活跃一次，使 b 成为“最久未活动”
        accessTokenService.authorize("Bearer " + a.pair().accessToken(),
                Permission.PROFILE_READ);

        // 收紧到 1（比当前活跃数 2 小），再登录 c
        properties.setMaxActiveSessionsPerAccount(1);
        Device c = login(username, "c");
        log.info("[覆盖] 上限边界: 活跃 2 个时上限收紧为 1, 再登录 c familyId={}",
                c.familyId());

        // 超出 2 个，但候选只有 a、b -> 全部清掉，新登录 c 保留（下限为 1）
        assertThat(accessError(c)).as("新登录必须保留且可用").isNull();
        assertThat(accessError(a)).isEqualTo(ErrorCode.SESSION_REVOKED_EVICTED.code());
        assertThat(accessError(b)).isEqualTo(ErrorCode.SESSION_REVOKED_EVICTED.code());
        assertThat(activeFamilyIds(username)).containsExactly(c.familyId());

        // 收紧到 2：当前仅 c 活跃，再登录 d、e，淘汰只按最久未活动清旧登录
        properties.setMaxActiveSessionsPerAccount(2);
        Device d = login(username, "d");
        // c 重新活跃，使 d 成为最久未活动
        accessTokenService.authorize("Bearer " + c.pair().accessToken(),
                Permission.PROFILE_READ);
        Device e = login(username, "e");

        assertThat(accessError(d)).as("最久未活动的 d 被清掉")
                .isEqualTo(ErrorCode.SESSION_REVOKED_EVICTED.code());
        assertThat(accessError(c)).as("此前已存在且较活跃的 c 保留").isNull();
        assertThat(accessError(e)).as("新登录 e 保留").isNull();
        assertThat(activeFamilyIds(username))
                .containsExactlyInAnyOrder(c.familyId(), e.familyId());
        log.info("[判定依据] 上限收紧后: 新登录始终保留, 淘汰只落在之前的登录上, "
                + "次序=最久未活动优先, 被清者={}",
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
