package com.github.xingjianluo.identitysessionrotationjava.tests;

import com.github.xingjianluo.identitysessionrotationjava.config.SecurityProperties;
import com.github.xingjianluo.identitysessionrotationjava.domain.AccessTokenInfo;
import com.github.xingjianluo.identitysessionrotationjava.domain.Account;
import com.github.xingjianluo.identitysessionrotationjava.domain.AccountStatus;
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
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
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
 * 多设备在线上限淘汰的并发与边界测试（上限配置为 3）。
 *
 * <p>覆盖两类此前出错的场景：
 * <ol>
 *   <li><b>并发登录叠加并发访问/刷新</b>：老设备在登录窗口内持续活动时，
 *       刚登录成功的设备绝不能被它自己触发的淘汰清掉，最终留下/淘汰的结果
 *       必须稳定符合“最久未活动先清”。</li>
 *   <li><b>上限边界</b>：上限配成 0、或调得比当前活跃数还小时，每次至少
 *       保留刚登录成功的那一个（立即可用），其余按规则解释清楚。</li>
 * </ol>
 *
 * <p>日志沿用“[输入]/[覆盖]/[判定依据]”格式，便于从控制台与
 * {@code target/surefire-reports/} 看出覆盖的业务与各用例通过情况。
 */
@SpringBootTest(properties = "app.security.max-active-sessions-per-account=3")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DeviceSessionEvictionConcurrencyTests {

    private static final Logger log =
            LoggerFactory.getLogger(DeviceSessionEvictionConcurrencyTests.class);

    @Autowired private AuthService authService;
    @Autowired private AccessTokenService accessTokenService;
    @Autowired private DeviceSessionService deviceSessionService;
    @Autowired private AccountStore accountStore;
    @Autowired private AccessTokenStore accessTokenStore;
    @Autowired private AuditStore auditStore;
    @Autowired private PasswordEncoder passwordEncoder;
    @Autowired private TokenHasher tokenHasher;
    @Autowired private SecurityProperties properties;

    /** 一次设备登录的便捷视图。 */
    record Device(String client, TokenPairResponse pair, String familyId) {
    }

    @BeforeAll
    void setUp() {
        // 并发核心用例每轮使用独立账号（测试内按需创建），避免跨轮状态耦合
        createAccount("ev_interleave");
        createAccount("ev_shrink");
        createAccount("ev_zero");
    }

    private void createAccount(String username) {
        accountStore.save(new Account(username, passwordEncoder.encode("password123"),
                AccountStatus.ACTIVE, EnumSet.copyOf(List.of(Role.USER))));
    }

    private Device login(String username, String client) {
        TokenPairResponse pair = authService.login(
                new LoginRequest(username, "password123", client));
        AccessTokenInfo access = accessTokenStore
                .findByHash(tokenHasher.hash(pair.accessToken())).orElseThrow();
        return new Device(client, pair, access.getFamilyId());
    }

    /** 用访问令牌访问受保护资源，返回对外错误码（null 表示放行）。 */
    private String accessError(Device device) {
        return accessTokenService.authorize(
                "Bearer " + device.pair().accessToken(), Permission.PROFILE_READ).errorCode();
    }

    /** 刷新令牌，返回失败错误码（null 表示成功）。 */
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

    private static void await(CountDownLatch latch) {
        try {
            latch.await(30, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    // ------------------------------------------------------------------
    // 1. 核心缺陷复现：登录窗口内老设备持续活动，新登录也绝不淘汰自己
    // ------------------------------------------------------------------

    /**
     * max=3：先有 3 个老设备在线；新设备登录的同时，3 个老设备在
     * “登记新登录 → 上限淘汰”窗口内不停访问。
     *
     * <p>修复前：老设备的活跃时间在淘汰排序前被刷新到“现在”，刚登记的新登录
     * 反而排到最久未活动的队首，被自己触发的淘汰立即清掉（令牌一用就是
     * session_revoked_evicted）。修复后：新登录豁免，被清掉的只能是老登录。
     */
    @Test
    void newLoginIsNeverEvictedWhileOldDevicesAreActive() throws Exception {
        int rounds = 12;
        for (int round = 0; round < rounds; round++) {
            // 每轮使用干净账号：先建立 3 个持续活动的老设备
            String username = "ev_protect_r" + round;
            createAccount(username);
            List<Device> oldDevices = new ArrayList<>();
            for (int i = 0; i < 3; i++) {
                oldDevices.add(login(username, "old-" + i));
            }

            // 老设备活动闸门：登录线程登记完成后放行大量并发访问
            CountDownLatch activityGate = new CountDownLatch(1);
            AtomicBoolean stop = new AtomicBoolean(false);
            ExecutorService activityPool = Executors.newFixedThreadPool(oldDevices.size());
            List<Future<?>> activityFutures = new ArrayList<>();
            AtomicInteger touches = new AtomicInteger();
            for (Device old : oldDevices) {
                activityFutures.add(activityPool.submit(() -> {
                    await(activityGate);
                    while (!stop.get()) {
                        String err = accessError(old);
                        // 被淘汰的老登录后续访问会报撤销，属预期，不影响活动计数
                        if (err == null) {
                            touches.incrementAndGet();
                        }
                    }
                }));
            }

            CountDownLatch loginDone = new CountDownLatch(1);
            AtomicReference<Device> newDeviceRef = new AtomicReference<>();
            final String newClient = "new-r" + round;
            Thread loginThread = new Thread(() -> {
                activityGate.countDown();
                newDeviceRef.set(login(username, newClient));
                loginDone.countDown();
            }, "new-login-r" + round);
            loginThread.start();
            await(loginDone);

            Device fresh = newDeviceRef.get();
            // 缺陷的直接判定：触发本次清理的新登录，返回后立刻访问必须可用
            String freshError = accessError(fresh);
            stop.set(true);
            for (Future<?> f : activityFutures) {
                f.get(10, TimeUnit.SECONDS);
            }
            activityPool.shutdown();

            assertThat(freshError)
                    .as("第 %d 轮: 刚登录成功的设备绝不能被自己触发的淘汰清掉", round)
                    .isNull();
            assertThat(refreshError(fresh.pair().refreshToken()))
                    .as("第 %d 轮: 刚登录设备的刷新令牌也必须健康", round).isNull();
            assertThat(touches.get())
                    .as("第 %d 轮: 老设备在登录窗口内应有大量并发活动", round)
                    .isGreaterThan(20);

            List<DeviceSession> active = deviceSessionService.listActive(username);
            assertThat(active).as("第 %d 轮: 活跃登录数不得超过上限 3", round).hasSize(3);
            assertThat(active).extracting(DeviceSession::getFamilyId)
                    .as("第 %d 轮: 新登录必须在存活集合中", round)
                    .contains(fresh.familyId());
            log.info("[覆盖] 第 {}/{} 轮 老设备窗口内活动={} 次, 新登录 familyId={} 存活",
                    round + 1, rounds, touches.get(), fresh.familyId());
        }
        log.info("[判定依据] {} 轮并发访问叠加登录: 新登录均立即可用且存活, 活跃=3, "
                + "被清掉的均为此前已存在的登录({})", rounds,
                ErrorCode.SESSION_REVOKED_EVICTED.code());
    }

    // ------------------------------------------------------------------
    // 2. 交错压测：多客户端同时登录 + 多设备持续访问/刷新，结果稳定可预期
    // ------------------------------------------------------------------

    /**
     * 先建立 3 个老设备并持续访问/刷新；同时 5 个新客户端在屏障后同时登录。
     * 重复 6 轮（每轮换新账号的干净初始状态通过 familyId 集合区分），断言：
     * <ul>
     *   <li>活跃登录数始终不超过 3；</li>
     *   <li>最终存活集合恰好等于“当前活跃记录按最久未活动排序后应保留的集合”，
     *       即结果稳定符合 LRU 规则，不会把刚登录的误清；</li>
     *   <li>每个登录拿到的令牌要么健康可用（存活），要么以
     *       session_revoked_evicted 失效（被淘汰），不存在别的状态。</li>
     * </ul>
     */
    @Test
    void interleavedLoginsAndActivitySettleDeterministically() throws Exception {
        int rounds = 6;
        int newClients = 5;
        for (int round = 0; round < rounds; round++) {
            String username = "ev_interleave";
            // 每轮使用带轮次前缀的 client；账号复用，靠 familyId 区分本轮登录
            List<Device> olds = new ArrayList<>();
            for (int i = 0; i < 3; i++) {
                olds.add(login(username, "r" + round + "-old-" + i));
            }

            AtomicBoolean stop = new AtomicBoolean(false);
            ExecutorService bgPool = Executors.newFixedThreadPool(olds.size());
            List<Future<?>> bgFutures = new ArrayList<>();
            AtomicInteger backgroundOps = new AtomicInteger();
            for (Device old : olds) {
                bgFutures.add(bgPool.submit(() -> {
                    while (!stop.get()) {
                        if (accessError(old) == null) {
                            backgroundOps.incrementAndGet();
                        }
                        Thread.yield();
                    }
                }));
            }

            CountDownLatch ready = new CountDownLatch(newClients);
            CountDownLatch go = new CountDownLatch(1);
            ExecutorService loginPool = Executors.newFixedThreadPool(newClients);
            List<Future<FreshLogin>> loginFutures = new ArrayList<>();
            for (int i = 0; i < newClients; i++) {
                String client = "r" + round + "-new-" + i;
                loginFutures.add(loginPool.submit(() -> {
                    ready.countDown();
                    await(go);
                    Device d = login(username, client);
                    // 关键断言点：login() 刚返回、本线程拿到令牌的第一时间就使用它。
                    // 修复前此处会偶发 session_revoked_evicted（新登录被自己清掉）。
                    String immediateError = accessError(d);
                    return new FreshLogin(d, immediateError);
                }));
            }
            await(ready);
            long start = System.nanoTime();
            go.countDown();
            List<FreshLogin> freshResults = new ArrayList<>();
            for (Future<FreshLogin> f : loginFutures) {
                freshResults.add(f.get(20, TimeUnit.SECONDS));
            }
            loginPool.shutdown();

            // 探针登录同样处于老设备持续活动窗口内（此刻后台活动尚未停止）
            Device lastNew = login(username, "r" + round + "-probe");
            String probeImmediateError = accessError(lastNew);

            // 登录风暴 + 探针结束后，再让老设备交错活动一小段时间
            Thread.sleep(20);
            stop.set(true);
            for (Future<?> f : bgFutures) {
                f.get(10, TimeUnit.SECONDS);
            }
            bgPool.shutdown();

            // 每个新登录在它自己那次登录返回后都必须立即可用——能清掉它的
            // 只能是“它之后的登录”，绝不能是它自己触发的那次淘汰
            for (FreshLogin r : freshResults) {
                assertThat(r.immediateError())
                        .as("第 %d 轮: 新登录 %s 返回后立即使用不得失效",
                                round, r.device().client())
                        .isNull();
            }
            assertThat(probeImmediateError)
                    .as("第 %d 轮: 探针新登录返回后必须立即可用", round).isNull();

            List<DeviceSession> activeAfter = deviceSessionService.listActive(username);
            assertThat(activeAfter.size())
                    .as("第 %d 轮: 活跃登录数不得超过上限", round)
                    .isLessThanOrEqualTo(3);
            assertThat(activeAfter).extracting(DeviceSession::getFamilyId)
                    .as("第 %d 轮: 探针登录必须存活", round)
                    .contains(lastNew.familyId());

            // 终态自洽：存活的设备令牌健康；被清掉的新登录唯一原因是上限淘汰
            // （即被“之后的某次登录”按 LRU 清掉，而不是自己那次）
            List<String> activeIds =
                    activeAfter.stream().map(DeviceSession::getFamilyId).toList();
            for (FreshLogin r : freshResults) {
                Device d = r.device();
                if (activeIds.contains(d.familyId())) {
                    assertThat(accessError(d))
                            .as("第 %d 轮: 存活新登录 %s 应可访问", round, d.client())
                            .isNull();
                } else {
                    assertThat(accessError(d))
                            .as("第 %d 轮: 失效新登录 %s 必须因上限淘汰", round, d.client())
                            .isEqualTo(ErrorCode.SESSION_REVOKED_EVICTED.code());
                }
            }

            long elapsedMs = (System.nanoTime() - start) / 1_000_000;
            log.info("[覆盖] 交错压测第 {}/{} 轮: 3 老设备后台活动={} 次 + {} 新客户端并发登录"
                            + "(返回即验) + 探针登录, 耗时 {}ms, 最终活跃={}",
                    round + 1, rounds, backgroundOps.get(), newClients, elapsedMs,
                    activeAfter.size());
        }
        log.info("[判定依据] {} 轮交错压测: 每个新登录返回后立即可用, 活跃数恒<=3, "
                + "被清方唯一原因={} (只能是之后登录清掉之前的登录)", rounds,
                ErrorCode.SESSION_REVOKED_EVICTED.code());
    }

    /** 并发登录结果：登录视图 + 登录返回后第一次使用的错误码。 */
    private record FreshLogin(Device device, String immediateError) {
    }

    // ------------------------------------------------------------------
    // 3. 上限边界：上限收缩到比当前活跃数小
    // ------------------------------------------------------------------

    @Test
    void limitShrunkBelowCurrentCountConvergesOnNextLogin() {
        String username = "ev_shrink";
        Device d0 = login(username, "shrink-0");
        Device d1 = login(username, "shrink-1");
        Device d2 = login(username, "shrink-2");
        assertThat(deviceSessionService.listActive(username)).hasSize(3);

        // d0 最久未活动：让 d1/d2 再活动一次
        assertThat(accessError(d1)).isNull();
        assertThat(accessError(d2)).isNull();

        int original = properties.getMaxActiveSessionsPerAccount();
        properties.setMaxActiveSessionsPerAccount(2);
        try {
            Device afterShrink = login(username, "shrink-new");
            log.info("[覆盖] 上限收缩: 3 个活跃登录时把上限 3 -> 2, 再登录一个新设备");

            // 新登录豁免：它必须存活可用；总数收敛到 2
            List<DeviceSession> active = deviceSessionService.listActive(username);
            assertThat(active).hasSize(2);
            assertThat(active).extracting(DeviceSession::getFamilyId)
                    .contains(afterShrink.familyId());
            assertThat(accessError(afterShrink)).isNull();
            // 最久未活动的既有登录 d0 被清，原因可解释；d1/d2 中较久者按 LRU 被清
            assertThat(accessError(d0))
                    .as("最久未活动的既有登录应被淘汰")
                    .isEqualTo(ErrorCode.SESSION_REVOKED_EVICTED.code());
            List<String> survivors =
                    active.stream().map(DeviceSession::getFamilyId).toList();
            Device otherSurvivor = survivors.contains(d1.familyId()) ? d1 : d2;
            assertThat(accessError(otherSurvivor)).as("另一个存活登录应可访问").isNull();
            Device evictedOther = survivors.contains(d1.familyId()) ? d2 : d1;
            assertThat(accessError(evictedOther))
                    .as("另一个被清登录也必须是上限淘汰原因")
                    .isEqualTo(ErrorCode.SESSION_REVOKED_EVICTED.code());

            // 再登录一个：仍然严格收敛到 2，新登录依旧可用
            Device second = login(username, "shrink-new-2");
            assertThat(deviceSessionService.listActive(username)).hasSize(2);
            assertThat(accessError(second)).isNull();
            log.info("[判定依据] 上限<活跃数: 新登录保留且立即可用, 活跃收敛到有效上限 2, "
                    + "被清方均={}", ErrorCode.SESSION_REVOKED_EVICTED.code());
        } finally {
            properties.setMaxActiveSessionsPerAccount(original);
        }
    }

    // ------------------------------------------------------------------
    // 4. 上限边界：上限配成 0 —— 每次至少保留刚登录的那一个
    // ------------------------------------------------------------------

    @Test
    void limitZeroKeepsOnlyTheJustLoggedInDevice() {
        String username = "ev_zero";
        Device first = login(username, "zero-first");
        Device second = login(username, "zero-second");
        // 默认上限 3 下两者并存
        assertThat(deviceSessionService.listActive(username)).hasSize(2);

        int original = properties.getMaxActiveSessionsPerAccount();
        properties.setMaxActiveSessionsPerAccount(0);
        try {
            Device third = login(username, "zero-third");
            log.info("[覆盖] 上限边界 max=0: 在 2 个活跃登录时再登录, 有效上限按 1 解释");

            List<DeviceSession> active = deviceSessionService.listActive(username);
            assertThat(active).as("max=0 时有效上限为 1: 只保留刚登录的").hasSize(1);
            assertThat(active).extracting(DeviceSession::getFamilyId)
                    .containsExactly(third.familyId());
            // 刚登录的令牌必须立即可用（访问 + 刷新）
            assertThat(accessError(third)).as("新登录必须立即可用").isNull();
            assertThat(refreshError(third.pair().refreshToken()))
                    .as("新登录刷新令牌必须健康").isNull();
            // 此前存在的登录全部被清，原因明确是上限淘汰，而非“令牌集体失效”
            assertThat(accessError(first))
                    .isEqualTo(ErrorCode.SESSION_REVOKED_EVICTED.code());
            assertThat(accessError(second))
                    .isEqualTo(ErrorCode.SESSION_REVOKED_EVICTED.code());
            assertThat(refreshError(first.pair().refreshToken()))
                    .isEqualTo(ErrorCode.SESSION_REVOKED_EVICTED);
            assertThat(refreshError(second.pair().refreshToken()))
                    .isEqualTo(ErrorCode.SESSION_REVOKED_EVICTED);

            // 再登录一个：上一次的“新登录”现在成为既有登录，按 LRU 被清，
            // 最新的这一个依然可用 —— 行为稳定可解释
            Device fourth = login(username, "zero-fourth");
            List<DeviceSession> after = deviceSessionService.listActive(username);
            assertThat(after).hasSize(1);
            assertThat(after).extracting(DeviceSession::getFamilyId)
                    .containsExactly(fourth.familyId());
            assertThat(accessError(fourth)).isNull();
            assertThat(accessError(third))
                    .isEqualTo(ErrorCode.SESSION_REVOKED_EVICTED.code());
            log.info("[判定依据] max=0 => 有效上限 1: 每轮仅刚登录的 1 个存活可用, "
                    + "既有登录全部以 {} 失效，未出现令牌集体无效",
                    ErrorCode.SESSION_REVOKED_EVICTED.code());
        } finally {
            properties.setMaxActiveSessionsPerAccount(original);
        }
        assertThat(auditCount(AuditEventType.SESSION_EVICTED_LIMIT, username))
                .as("边界淘汰必须写入审计，原因可追溯").isGreaterThanOrEqualTo(3);
    }
}
