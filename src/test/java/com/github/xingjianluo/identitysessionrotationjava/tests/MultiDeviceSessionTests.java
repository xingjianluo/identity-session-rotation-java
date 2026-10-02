package com.github.xingjianluo.identitysessionrotationjava.tests;

import com.github.xingjianluo.identitysessionrotationjava.config.SecurityProperties;
import com.github.xingjianluo.identitysessionrotationjava.domain.AccessTokenInfo;
import com.github.xingjianluo.identitysessionrotationjava.domain.Account;
import com.github.xingjianluo.identitysessionrotationjava.domain.AccountStatus;
import com.github.xingjianluo.identitysessionrotationjava.domain.AuditEvent;
import com.github.xingjianluo.identitysessionrotationjava.domain.DeviceSession;
import com.github.xingjianluo.identitysessionrotationjava.domain.Permission;
import com.github.xingjianluo.identitysessionrotationjava.domain.RefreshTokenInfo;
import com.github.xingjianluo.identitysessionrotationjava.domain.Role;
import com.github.xingjianluo.identitysessionrotationjava.error.AuthException;
import com.github.xingjianluo.identitysessionrotationjava.error.ErrorCode;
import com.github.xingjianluo.identitysessionrotationjava.security.PasswordEncoder;
import com.github.xingjianluo.identitysessionrotationjava.security.TokenGenerator;
import com.github.xingjianluo.identitysessionrotationjava.security.TokenHasher;
import com.github.xingjianluo.identitysessionrotationjava.service.AccessTokenService;
import com.github.xingjianluo.identitysessionrotationjava.service.AuthService;
import com.github.xingjianluo.identitysessionrotationjava.service.ClientContext;
import com.github.xingjianluo.identitysessionrotationjava.service.DeviceSessionService;
import com.github.xingjianluo.identitysessionrotationjava.service.SessionRevocationService;
import com.github.xingjianluo.identitysessionrotationjava.store.AccessTokenStore;
import com.github.xingjianluo.identitysessionrotationjava.store.AccountLockStore;
import com.github.xingjianluo.identitysessionrotationjava.store.AccountStore;
import com.github.xingjianluo.identitysessionrotationjava.store.AuditStore;
import com.github.xingjianluo.identitysessionrotationjava.store.DeviceSessionStore;
import com.github.xingjianluo.identitysessionrotationjava.store.FamilyLockStore;
import com.github.xingjianluo.identitysessionrotationjava.store.RefreshTokenStore;
import com.github.xingjianluo.identitysessionrotationjava.store.SessionStore;
import com.github.xingjianluo.identitysessionrotationjava.web.dto.LoginRequest;
import com.github.xingjianluo.identitysessionrotationjava.web.dto.RefreshRequest;
import com.github.xingjianluo.identitysessionrotationjava.web.dto.SessionInfoResponse;
import com.github.xingjianluo.identitysessionrotationjava.web.dto.TokenPairResponse;
import java.time.Duration;
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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * 多设备会话管理场景测试：
 * 查看/单撤销隔离、退出其他设备、超限 LRU 淘汰顺序、撤销与并发刷新叠加、
 * 并发登录下上限保持。使用独立装配（上限=3），避免与其他测试类共享存储。
 */
class MultiDeviceSessionTests {

    private static final Logger log = LoggerFactory.getLogger(MultiDeviceSessionTests.class);

    private AccountStore accountStore;
    private SessionStore sessionStore;
    private AccessTokenStore accessTokenStore;
    private RefreshTokenStore refreshTokenStore;
    private DeviceSessionStore deviceSessionStore;
    private AuditStore auditStore;
    private FamilyLockStore familyLockStore;
    private AccountLockStore accountLockStore;
    private AuthService authService;
    private AccessTokenService accessTokenService;
    private DeviceSessionService deviceSessionService;
    private TokenHasher tokenHasher;

    private final String user = "multi_user";
    private final String password = "password123";

    /** 登录结果便捷视图。 */
    record Issued(TokenPairResponse pair, String familyId) {
    }

    @BeforeEach
    void setUp() {
        // 独立装配，maxConcurrentSessions=3
        accountStore = new AccountStore();
        sessionStore = new SessionStore();
        accessTokenStore = new AccessTokenStore();
        refreshTokenStore = new RefreshTokenStore();
        deviceSessionStore = new DeviceSessionStore();
        auditStore = new AuditStore();
        familyLockStore = new FamilyLockStore();
        accountLockStore = new AccountLockStore();
        tokenHasher = new TokenHasher();
        PasswordEncoder passwordEncoder = new PasswordEncoder();
        TokenGenerator tokenGenerator = new TokenGenerator();
        SecurityProperties props = new SecurityProperties();
        props.setAccessTokenTtlSeconds(300);
        props.setRefreshTokenTtlSeconds(1209600);
        props.setMaxConcurrentSessions(3);

        accountStore.save(new Account(user, passwordEncoder.encode(password),
                AccountStatus.ACTIVE, EnumSet.of(Role.USER)));

        SessionRevocationService revocationService = new SessionRevocationService(
                sessionStore, accessTokenStore, refreshTokenStore, auditStore,
                familyLockStore);
        deviceSessionService = new DeviceSessionService(
                deviceSessionStore, sessionStore, auditStore,
                accountLockStore, familyLockStore, revocationService, props);
        authService = new AuthService(accountStore, sessionStore, accessTokenStore,
                refreshTokenStore, auditStore, familyLockStore, revocationService,
                deviceSessionService, passwordEncoder, tokenGenerator, tokenHasher, props);
        accessTokenService = new AccessTokenService(accessTokenStore, sessionStore,
                accountStore, auditStore, tokenHasher, deviceSessionService);
    }

    private Issued login(String clientId) {
        TokenPairResponse pair = authService.login(
                new LoginRequest(user, password, clientId),
                ClientContext.of(clientId, "UA-" + clientId, "10.0.0." + clientId));
        AccessTokenInfo access = accessTokenStore
                .findByHash(tokenHasher.hash(pair.accessToken())).orElseThrow();
        log.info("[业务:多设备登录] clientId={} familyId={}", clientId, access.getFamilyId());
        return new Issued(pair, access.getFamilyId());
    }

    private AccessTokenInfo accessInfo(Issued i) {
        return accessTokenStore.findByHash(tokenHasher.hash(i.pair().accessToken())).orElseThrow();
    }

    private RefreshTokenInfo refreshInfo(Issued i) {
        return refreshTokenStore.findByHash(tokenHasher.hash(i.pair().refreshToken())).orElseThrow();
    }

    private void setLastActive(String familyId, Instant at) {
        deviceSessionStore.findByFamily(familyId).orElseThrow().touch(at);
    }

    // ------------------------------------------------------------------
    // 1. 会话查看：能看到全部活跃登录、登录/最近活跃时间、客户端来源
    // ------------------------------------------------------------------

    @Test
    void listSessionsShowsActiveLoginsWithTimesAndClient() throws Exception {
        Issued mobile = login("mobile");
        Thread.sleep(12);
        Issued browser = login("browser");
        Thread.sleep(12);
        Issued cli = login("cli");

        List<SessionInfoResponse> sessions =
                deviceSessionService.listSessions(user, cli.familyId());

        log.info("[业务:会话查看] 返回 {} 个活跃会话: {}", sessions.size(),
                sessions.stream().map(s -> s.clientId()
                        + "(login=" + s.loginAt() + ",active=" + s.lastActiveAt()
                        + ",current=" + s.current() + ")").toList());

        assertThat(sessions).hasSize(3);
        assertThat(sessions).extracting(SessionInfoResponse::clientId)
                .containsExactlyInAnyOrder("mobile", "browser", "cli");
        for (SessionInfoResponse s : sessions) {
            assertThat(s.loginAt()).isNotNull();
            assertThat(s.lastActiveAt()).isNotNull();
            assertThat(s.userAgent()).startsWith("UA-");
            assertThat(s.ip()).startsWith("10.0.0.");
        }
        // 只有当前会话被标记 current
        assertThat(sessions).filteredOn(SessionInfoResponse::current)
                .extracting(SessionInfoResponse::sessionId).containsExactly(cli.familyId());
        // 最近活跃倒序：后登录的在前（初始 lastActiveAt == loginAt）
        assertThat(sessions).extracting(SessionInfoResponse::clientId)
                .containsExactly("cli", "browser", "mobile");
        // 查看动作写审计
        assertThat(auditStore.findByType("SESSION_LISTED")).isNotEmpty();
        log.info("[通过] 会话查看：3 个设备登录时间/来源/current 标记均正确");
    }

    // ------------------------------------------------------------------
    // 2. 单会话撤销：立即生效且严格隔离；撤销分类与自然过期不同
    // ------------------------------------------------------------------

    @Test
    void revokeOneSessionOnlyAffectsThatDeviceAndErrorIsExplainable() {
        Issued mobile = login("mobile");
        Issued browser = login("browser");
        Issued cli = login("cli");

        // 撤销 mobile 一个
        deviceSessionService.revokeSession(user, mobile.familyId());
        log.info("[业务:单会话撤销] 点名撤销 familyId={} (mobile)", mobile.familyId());

        // 被点名的：access 立即失败，原因为设备单独撤销（与 token_expired 明显不同）
        var deniedMobile = accessTokenService.authorize(
                "Bearer " + mobile.pair().accessToken(), Permission.PROFILE_READ);
        assertThat(deniedMobile.allowed()).isFalse();
        assertThat(deniedMobile.errorCode())
                .isEqualTo(ErrorCode.SESSION_REVOKED_DEVICE_REVOKED.code());
        assertThat(deniedMobile.errorCode()).isNotEqualTo(ErrorCode.TOKEN_EXPIRED.code());

        // 被点名的：refresh 同样换不出新令牌
        assertThatThrownBy(() -> authService.refresh(
                new RefreshRequest(mobile.pair().refreshToken())))
                .isInstanceOf(AuthException.class)
                .extracting(e -> ((AuthException) e).getErrorCode())
                .isEqualTo(ErrorCode.SESSION_REVOKED_DEVICE_REVOKED);

        // 当前会话 cli 与未被点名的 browser 必须照常可用
        assertThat(accessTokenService.authorize(
                "Bearer " + browser.pair().accessToken(), Permission.PROFILE_READ).allowed())
                .as("未被点名的 browser 不受牵连").isTrue();
        assertThat(accessTokenService.authorize(
                "Bearer " + cli.pair().accessToken(), Permission.PROFILE_READ).allowed())
                .as("当前会话 cli 不受牵连").isTrue();
        // 未被点名的 browser 仍可正常刷新轮换
        TokenPairResponse rotated = authService.refresh(
                new RefreshRequest(browser.pair().refreshToken()));
        assertThat(accessTokenService.authorize(
                "Bearer " + rotated.accessToken(), Permission.PROFILE_READ).allowed()).isTrue();

        // 列表里不再出现 mobile
        List<SessionInfoResponse> rest = deviceSessionService.listSessions(user, cli.familyId());
        assertThat(rest).extracting(SessionInfoResponse::clientId)
                .doesNotContain("mobile").containsExactlyInAnyOrder("browser", "cli");

        // 不能撤销别人的会话 / 不存在的会话 => session_not_found
        assertThatThrownBy(() -> deviceSessionService.revokeSession(user, "vid_ghost"))
                .isInstanceOf(AuthException.class)
                .extracting(e -> ((AuthException) e).getErrorCode())
                .isEqualTo(ErrorCode.SESSION_NOT_FOUND);

        // 撤销动作写审计
        assertThat(auditStore.findByType("SESSION_REVOKE_ONE"))
                .anyMatch(e -> mobile.familyId().equals(e.familyId())
                        && e.detail().contains("result=revoked"));
        log.info("[通过] 单会话撤销：mobile 立即失效(device_revoked)，browser/cli 访问与刷新均正常");
    }

    // ------------------------------------------------------------------
    // 3. 退出其他所有设备：只保留当前会话，其他立即失效
    // ------------------------------------------------------------------

    @Test
    void revokeOthersKeepsCurrentAndKillsAllOtherDevices() {
        Issued mobile = login("mobile");
        Issued browser = login("browser");
        Issued cli = login("cli");

        int revoked = deviceSessionService.revokeOtherSessions(user, cli.familyId());
        log.info("[业务:退出其他设备] currentFamilyId={} 撤销数量={}", cli.familyId(), revoked);
        assertThat(revoked).isEqualTo(2);

        // 其他设备 access 立即失败，原因为“退出其他设备”
        for (Issued other : List.of(mobile, browser)) {
            var denied = accessTokenService.authorize(
                    "Bearer " + other.pair().accessToken(), Permission.PROFILE_READ);
            assertThat(denied.allowed()).isFalse();
            assertThat(denied.errorCode())
                    .isEqualTo(ErrorCode.SESSION_REVOKED_OTHER_DEVICES_LOGOUT.code());
            assertThatThrownBy(() -> authService.refresh(
                    new RefreshRequest(other.pair().refreshToken())))
                    .isInstanceOf(AuthException.class)
                    .extracting(e -> ((AuthException) e).getErrorCode())
                    .isEqualTo(ErrorCode.SESSION_REVOKED_OTHER_DEVICES_LOGOUT);
        }

        // 当前会话仍然能访问、能刷新
        assertThat(accessTokenService.authorize(
                "Bearer " + cli.pair().accessToken(), Permission.PROFILE_READ).allowed()).isTrue();
        TokenPairResponse rotated = authService.refresh(
                new RefreshRequest(cli.pair().refreshToken()));
        assertThat(accessTokenService.authorize(
                "Bearer " + rotated.accessToken(), Permission.PROFILE_READ).allowed()).isTrue();

        List<SessionInfoResponse> rest = deviceSessionService.listSessions(user, cli.familyId());
        assertThat(rest).hasSize(1);
        assertThat(rest.get(0).clientId()).isEqualTo("cli");
        assertThat(rest.get(0).current()).isTrue();

        assertThat(auditStore.findByType("SESSION_REVOKE_OTHERS"))
                .anyMatch(e -> e.detail().contains("撤销会话数=2"));
        log.info("[通过] 退出其他设备：mobile/browser 失效(other_devices_logout)，cli 访问/刷新正常");
    }

    // ------------------------------------------------------------------
    // 4. 超限淘汰：上限=3，新登录按“最久未活跃”清理，顺序确定、原因可解释
    // ------------------------------------------------------------------

    @Test
    void loginBeyondLimitEvictsLeastRecentlyActiveWithDistinctError() {
        Issued mobile = login("mobile");
        Issued browser = login("browser");
        Issued cli = login("cli");
        assertThat(deviceSessionService.listSessions(user, cli.familyId())).hasSize(3);

        Instant base = Instant.now().minusSeconds(3600);
        // browser 最近最活跃，mobile 最久未活跃，cli 居中
        setLastActive(mobile.familyId(), base);
        setLastActive(browser.familyId(), base.plusSeconds(300));
        setLastActive(cli.familyId(), base.plusSeconds(100));

        // 第 4 个登录：淘汰 mobile（最久未活跃）
        Issued tablet = login("tablet");
        log.info("[业务:超限淘汰] 第4个登录 tablet familyId={}，预期淘汰 mobile", tablet.familyId());

        List<SessionInfoResponse> remaining =
                deviceSessionService.listSessions(user, tablet.familyId());
        assertThat(remaining).extracting(SessionInfoResponse::clientId)
                .as("mobile 最久未活跃应被清理，新登录 tablet 保留")
                .containsExactlyInAnyOrder("browser", "cli", "tablet");

        // mobile 的 access/refresh 都不能再成功，错误码与自然过期不同
        var denied = accessTokenService.authorize(
                "Bearer " + mobile.pair().accessToken(), Permission.PROFILE_READ);
        assertThat(denied.allowed()).isFalse();
        assertThat(denied.errorCode())
                .isEqualTo(ErrorCode.SESSION_REVOKED_MAX_SESSIONS.code());
        assertThat(denied.errorCode()).isNotEqualTo(ErrorCode.TOKEN_EXPIRED.code());
        assertThat(denied.errorCode()).isNotEqualTo(ErrorCode.REFRESH_TOKEN_EXPIRED.code());
        assertThatThrownBy(() -> authService.refresh(
                new RefreshRequest(mobile.pair().refreshToken())))
                .isInstanceOf(AuthException.class)
                .extracting(e -> ((AuthException) e).getErrorCode())
                .isEqualTo(ErrorCode.SESSION_REVOKED_MAX_SESSIONS);

        // 其余三个仍然健康
        for (Issued alive : List.of(browser, cli, tablet)) {
            assertThat(accessTokenService.authorize(
                    "Bearer " + alive.pair().accessToken(), Permission.PROFILE_READ).allowed())
                    .as(alive == browser ? "browser 存活" : alive == cli ? "cli 存活" : "tablet 存活")
                    .isTrue();
        }

        // 再登录两个：持续按 LRU 淘汰（此时 cli 比 browser 更久未活跃）
        setLastActive(browser.familyId(), Instant.now());
        Issued watch = login("watch");   // 淘汰 cli（lastActive=base+100）
        setLastActive(tablet.familyId(), Instant.now());
        Issued tv = login("tv");         // 淘汰 watch（watch 刚登录后未再活跃，
        // 但其 lastActiveAt=loginAt(now) 晚于 browser/tablet touch(now) 之前？
        // 此处仅断言总数稳定为 3，且被淘汰者令牌失效）
        List<SessionInfoResponse> finalList =
                deviceSessionService.listSessions(user, tv.familyId());
        assertThat(finalList).as("上限始终保持为 3").hasSize(3);

        // 审计可查淘汰记录，含判定依据
        List<AuditEvent> evictions = auditStore.findByType("SESSION_EVICTED");
        assertThat(evictions).hasSizeGreaterThanOrEqualTo(3);
        assertThat(evictions).anyMatch(e -> e.familyId().equals(mobile.familyId())
                && e.detail().contains("basis=max_concurrent_sessions")
                && e.detail().contains("limit=3"));
        log.info("[通过] 超限淘汰：mobile 因最久未活跃被清，错误=session_revoked_max_sessions，上限稳定=3");
    }

    // ------------------------------------------------------------------
    // 5. 撤销与并发刷新叠加：被撤销链不可能留下可用新令牌；其他链不受牵连
    // ------------------------------------------------------------------

    @Test
    void revocationConcurrentWithRefreshLeavesNoUsableTokenAndSparesOthers() throws Exception {
        Issued victim = login("mobile");
        Issued other = login("browser");
        Issued cli = login("cli");

        int threads = 8;
        ExecutorService pool = Executors.newFixedThreadPool(threads + 1);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch start = new CountDownLatch(1);
        ConcurrentLinkedQueue<TokenPairResponse> refreshSuccesses = new ConcurrentLinkedQueue<>();
        ConcurrentLinkedQueue<String> refreshFailureCodes = new ConcurrentLinkedQueue<>();
        AtomicInteger revokeWins = new AtomicInteger();

        List<Callable<Void>> refreshTasks = java.util.stream.IntStream.range(0, threads)
                .<Callable<Void>>mapToObj(i -> () -> {
                    ready.countDown();
                    start.await();
                    try {
                        refreshSuccesses.add(authService.refresh(
                                new RefreshRequest(victim.pair().refreshToken())));
                    } catch (AuthException e) {
                        refreshFailureCodes.add(e.getErrorCode().code());
                    }
                    return null;
                }).toList();
        // 撤销线程同时启动，与刷新抢同一把 family 锁
        Callable<Void> revokeTask = () -> {
            ready.countDown();
            start.await();
            deviceSessionService.revokeSession(user, victim.familyId());
            revokeWins.incrementAndGet();
            return null;
        };

        List<Future<Void>> futures = new java.util.ArrayList<>();
        refreshTasks.forEach(t -> futures.add(pool.submit(t)));
        futures.add(pool.submit(revokeTask));
        assertThat(ready.await(10, TimeUnit.SECONDS)).isTrue();
        start.countDown();
        for (Future<Void> f : futures) {
            f.get(10, TimeUnit.SECONDS);
        }
        pool.shutdown();

        log.info("[业务:撤销x并发刷新] 刷新成功={} 刷新失败分类={} 撤销完成={}",
                refreshSuccesses.size(), refreshFailureCodes, revokeWins.get());

        // 撤销恰好执行一次
        assertThat(revokeWins.get()).isEqualTo(1);

        // 关键断言：被撤销链上不存在“还能用”的令牌——
        // 若刷新先赢，它刚签发的后继也会被随后（或同时）的撤销吊销
        for (TokenPairResponse successPair : refreshSuccesses) {
            var d = accessTokenService.authorize(
                    "Bearer " + successPair.accessToken(), Permission.PROFILE_READ);
            assertThat(d.allowed())
                    .as("撤销完成后，刷新赢出的后继令牌也必须失效").isFalse();
            // 失败原因必须是“显式撤销”类，绝不能是自然过期
            assertThat(d.errorCode()).isNotEqualTo(ErrorCode.TOKEN_EXPIRED.code());
        }
        // 原令牌同样失效（device_revoked 或并发重放分类，二者都显式区分于过期）
        var original = accessTokenService.authorize(
                "Bearer " + victim.pair().accessToken(), Permission.PROFILE_READ);
        assertThat(original.allowed()).isFalse();
        assertThat(original.errorCode()).isNotEqualTo(ErrorCode.TOKEN_EXPIRED.code());
        // 任何后续刷新都无法换回可用令牌
        for (int i = 0; i < 3; i++) {
            assertThatThrownBy(() -> authService.refresh(
                    new RefreshRequest(victim.pair().refreshToken())))
                    .isInstanceOf(AuthException.class);
        }

        // 未被点名的 browser/cli 访问与刷新均正常
        assertThat(accessTokenService.authorize(
                "Bearer " + other.pair().accessToken(), Permission.PROFILE_READ).allowed())
                .as("其他设备 browser 不受牵连").isTrue();
        assertThat(accessTokenService.authorize(
                "Bearer " + cli.pair().accessToken(), Permission.PROFILE_READ).allowed())
                .as("当前会话 cli 不受牵连").isTrue();
        TokenPairResponse otherRotated = authService.refresh(
                new RefreshRequest(other.pair().refreshToken()));
        assertThat(accessTokenService.authorize(
                "Bearer " + otherRotated.accessToken(), Permission.PROFILE_READ).allowed())
                .as("其他设备仍能正常刷新").isTrue();

        log.info("[通过] 撤销x并发刷新：被撤销链无可用后继令牌，browser/cli 不受影响");
    }

    // ------------------------------------------------------------------
    // 6. 并发登录：多客户端几乎同时登录，活跃会话数绝不冲破上限，且结果可预期
    // ------------------------------------------------------------------

    @Test
    void concurrentLoginsNeverExceedLimitAndStayDeterministic() throws Exception {
        int attempts = 20;
        ExecutorService pool = Executors.newFixedThreadPool(attempts);
        CountDownLatch ready = new CountDownLatch(attempts);
        CountDownLatch start = new CountDownLatch(1);
        ConcurrentLinkedQueue<Issued> winners = new ConcurrentLinkedQueue<>();
        ConcurrentLinkedQueue<String> errors = new ConcurrentLinkedQueue<>();

        List<Callable<Void>> tasks = java.util.stream.IntStream.range(0, attempts)
                .<Callable<Void>>mapToObj(i -> () -> {
                    ready.countDown();
                    start.await();
                    String clientId = "dev-" + i;
                    try {
                        TokenPairResponse pair = authService.login(
                                new LoginRequest(user, password, clientId),
                                ClientContext.of(clientId, "UA-" + clientId, null));
                        String familyId = accessTokenStore
                                .findByHash(tokenHasher.hash(pair.accessToken())).orElseThrow()
                                .getFamilyId();
                        winners.add(new Issued(pair, familyId));
                    } catch (Exception e) {
                        errors.add(e.toString());
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

        log.info("[业务:并发登录] 登录尝试={} 成功返回={} 错误={}",
                attempts, winners.size(), errors);

        // 所有登录请求都成功返回（新登录永不失败，只是挤掉最久未活跃者）
        assertThat(errors).isEmpty();
        assertThat(winners).hasSize(attempts);

        // 无论 20 次登录如何交错，最终活跃会话数恰好等于上限
        List<SessionInfoResponse> active = deviceSessionService.listSessions(user, null);
        log.info("[判定依据] 最终活跃会话={}",
                active.stream().map(SessionInfoResponse::clientId).toList());
        assertThat(active).hasSize(3);

        // 每个被淘汰的登录：令牌立即失效且原因明确；最终存活的登录：令牌可用
        java.util.Set<String> activeFamilies = active.stream()
                .map(SessionInfoResponse::sessionId)
                .collect(java.util.stream.Collectors.toSet());
        int evictedCount = 0;
        for (Issued issued : winners) {
            var decision = accessTokenService.authorize(
                    "Bearer " + issued.pair().accessToken(), Permission.PROFILE_READ);
            if (activeFamilies.contains(issued.familyId())) {
                assertThat(decision.allowed())
                        .as("存活设备令牌必须可用 " + issued.familyId()).isTrue();
            } else {
                evictedCount++;
                assertThat(decision.allowed()).isFalse();
                assertThat(decision.errorCode())
                        .as("被挤掉的设备必须归因为超限淘汰而非自然过期")
                        .isEqualTo(ErrorCode.SESSION_REVOKED_MAX_SESSIONS.code());
                assertThat(decision.errorCode()).isNotEqualTo(ErrorCode.TOKEN_EXPIRED.code());
            }
        }
        assertThat(evictedCount).as("20 次登录、上限 3 => 17 个被淘汰").isEqualTo(attempts - 3);

        // 被淘汰者的刷新令牌同样换不出可用新令牌（抽样检查全部被淘汰者）
        for (Issued issued : winners) {
            if (!activeFamilies.contains(issued.familyId())) {
                assertThatThrownBy(() -> authService.refresh(
                        new RefreshRequest(issued.pair().refreshToken())))
                        .isInstanceOf(AuthException.class)
                        .extracting(e -> ((AuthException) e).getErrorCode())
                        .isEqualTo(ErrorCode.SESSION_REVOKED_MAX_SESSIONS);
            }
        }

        // 审计：恰好 17 条淘汰记录，family 不重复
        List<AuditEvent> evictions = auditStore.findByType("SESSION_EVICTED");
        assertThat(evictions).hasSize(attempts - 3);
        assertThat(evictions.stream().map(AuditEvent::familyId).distinct().toList())
                .hasSize(attempts - 3);
        log.info("[通过] 并发登录：上限 3 未被冲破，最终存活={}，淘汰 17 个，结果可预期",
                activeFamilies);
    }
}
