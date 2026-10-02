package com.github.xingjianluo.identitysessionrotationjava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** 端到端：HTTP 层的错误分类、令牌轮换与授权链路（骨架）。 */
@SpringBootTest
@AutoConfigureMockMvc
class WebApiIntegrationTests {

    private static final Logger log = LoggerFactory.getLogger(WebApiIntegrationTests.class);

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;

    private MvcResult login(String username, String password) throws Exception {
        return mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                java.util.Map.of("username", username, "password", password))))
                .andReturn();
    }

    private String accessToken(MvcResult loginResult) throws Exception {
        return objectMapper.readTree(loginResult.getResponse().getContentAsString())
                .get("access_token").asText();
    }

    private String refreshToken(MvcResult loginResult) throws Exception {
        return objectMapper.readTree(loginResult.getResponse().getContentAsString())
                .get("refresh_token").asText();
    }

    /** 断言 HTTP 状态与稳定 error code，并返回响应体用于进一步检查。 */
    private JsonNode expectError(MvcResult result, int httpStatus, String errorCode)
            throws Exception {
        assertThat(result.getResponse().getStatus()).isEqualTo(httpStatus);
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertThat(body.get("error").asText())
                .as("对外稳定错误码").isEqualTo(errorCode);
        assertThat(body.get("request_id").asText()).isNotBlank();
        log.info("[HTTP判定] status={} error={} description={}",
                httpStatus, errorCode, body.get("error_description").asText());
        return body;
    }

    @Test
    void loginAndAccessProtectedResourceOverHttp() throws Exception {
        MvcResult login = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"alice-pwd\"}"))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode tokens = objectMapper.readTree(login.getResponse().getContentAsString());
        String accessToken = tokens.get("access_token").asText();
        assertThat(accessToken).startsWith("vat_");

        MvcResult profile = mockMvc.perform(get("/api/profile")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode body = objectMapper.readTree(profile.getResponse().getContentAsString());
        assertThat(body.get("username").asText()).isEqualTo("alice");
        log.info("[HTTP] 登录并访问 /api/profile 成功, body={}", body);
    }

    @Test
    void httpDenialErrorsAreStableAndDistinguishable() throws Exception {
        // 登录失败：不泄露账户是否存在
        expectError(login("alice", "bad-password"), 401, "invalid_credentials");
        expectError(login("ghost-user", "whatever"), 401, "invalid_credentials");

        MvcResult ok = login("alice", "alice-pwd");
        String token = accessToken(ok);

        // 缺失 / 格式错误 / 无效令牌
        expectError(mockMvc.perform(get("/api/profile")).andReturn(),
                401, "missing_token");
        expectError(mockMvc.perform(get("/api/profile")
                        .header("Authorization", "Basic xyz")).andReturn(),
                401, "malformed_authorization");
        expectError(mockMvc.perform(get("/api/profile")
                        .header("Authorization", "Bearer vat_forged")).andReturn(),
                401, "invalid_token");

        // 权限不足：USER 访问管理端审计
        expectError(mockMvc.perform(get("/api/admin/audit")
                        .header("Authorization", "Bearer " + token)).andReturn(),
                403, "insufficient_permission");

        // ADMIN 可以访问管理端审计
        MvcResult adminLogin = login("admin", "admin-pwd");
        mockMvc.perform(get("/api/admin/audit")
                        .header("Authorization", "Bearer " + accessToken(adminLogin)))
                .andExpect(status().isOk());
        log.info("[HTTP] ADMIN 访问 /api/admin/audit 成功，USER 被稳定拒绝");
    }

    @Test
    void httpRefreshRotationReplayAndRevocationLifecycle() throws Exception {
        MvcResult first = login("bob", "bob-pwd");
        String access1 = accessToken(first);
        String refresh1 = refreshToken(first);

        // 首次访问正常
        mockMvc.perform(get("/api/orders")
                        .header("Authorization", "Bearer " + access1))
                .andExpect(status().isOk());

        // 刷新轮换
        MvcResult rotated = mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                java.util.Map.of("refreshToken", refresh1))))
                .andExpect(status().isOk())
                .andReturn();
        String access2 = accessToken(rotated);
        String refresh2 = refreshToken(rotated);
        assertThat(access2).isNotEqualTo(access1);
        assertThat(refresh2).isNotEqualTo(refresh1);

        // 旧访问令牌立即失效（正常轮换 -> 登出原因）
        expectError(mockMvc.perform(get("/api/orders")
                        .header("Authorization", "Bearer " + access1)).andReturn(),
                401, "session_revoked_logout");
        // 新访问令牌有效
        mockMvc.perform(get("/api/orders")
                        .header("Authorization", "Bearer " + access2))
                .andExpect(status().isOk());

        // 旧刷新令牌重放：401 refresh_token_reused
        expectError(mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                java.util.Map.of("refreshToken", refresh1))))
                        .andReturn(),
                401, "refresh_token_reused");

        // 重放后后继访问令牌被整链撤销
        expectError(mockMvc.perform(get("/api/orders")
                        .header("Authorization", "Bearer " + access2)).andReturn(),
                401, "session_revoked_refresh_reuse");
        // 后继刷新令牌同样不可用
        expectError(mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                java.util.Map.of("refreshToken", refresh2))))
                        .andReturn(),
                401, "session_revoked_refresh_reuse");
        log.info("[HTTP] 轮换/重放/整链撤销链路断言完成");
    }

    @Test
    void httpLogoutAndPasswordChangeInvalidateTokens() throws Exception {
        MvcResult first = login("alice", "alice-pwd");
        String token = accessToken(first);
        String refresh = refreshToken(first);

        // 登出
        mockMvc.perform(post("/api/auth/logout")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isNoContent());

        expectError(mockMvc.perform(get("/api/profile")
                        .header("Authorization", "Bearer " + token)).andReturn(),
                401, "session_revoked_logout");
        expectError(mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                java.util.Map.of("refreshToken", refresh))))
                        .andReturn(),
                401, "session_revoked_logout");

        // 改密后旧会话失效，且审计可查
        MvcResult second = login("alice", "alice-pwd");
        String token2 = accessToken(second);
        mockMvc.perform(post("/api/account/password")
                        .header("Authorization", "Bearer " + token2)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(java.util.Map.of(
                                "oldPassword", "alice-pwd",
                                "newPassword", "alice-new-pwd-1"))))
                .andExpect(status().isNoContent());
        expectError(mockMvc.perform(get("/api/profile")
                        .header("Authorization", "Bearer " + token2)).andReturn(),
                401, "session_revoked_password_changed");

        MvcResult audit = mockMvc.perform(get("/api/admin/audit")
                        .header("Authorization",
                                "Bearer " + accessToken(login("admin", "admin-pwd"))))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode events = objectMapper.readTree(audit.getResponse().getContentAsString());
        assertThat(events.toString()).contains("PASSWORD_CHANGED");
        assertThat(events.toString()).contains("LOGOUT");

        // 还原密码
        MvcResult after = login("alice", "alice-new-pwd-1");
        mockMvc.perform(post("/api/account/password")
                        .header("Authorization", "Bearer " + accessToken(after))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(java.util.Map.of(
                                "oldPassword", "alice-new-pwd-1",
                                "newPassword", "alice-pwd"))))
                .andExpect(status().isNoContent());
        log.info("[HTTP] 登出/改密撤销与审计查询断言完成");
    }

    // ------------------------------------------------------------------
    // 多设备会话：查看 / 单撤销隔离 / 退出其他设备（HTTP 全链路）
    // ------------------------------------------------------------------

    @Test
    void httpMultiDeviceListRevokeOneAndRevokeOthers() throws Exception {
        // 三个客户端登录（bob）
        MvcResult mobileLogin = loginWithClient("bob", "bob-pwd", "mobile");
        MvcResult browserLogin = loginWithClient("bob", "bob-pwd", "browser");
        MvcResult cliLogin = loginWithClient("bob", "bob-pwd", "cli");
        String mobileAccess = accessToken(mobileLogin);
        String mobileRefresh = refreshToken(mobileLogin);
        String browserAccess = accessToken(browserLogin);
        String cliAccess = accessToken(cliLogin);

        // 1) 查看会话列表：3 个，含时间与来源，当前 cli 标记 current
        MvcResult listResult = mockMvc.perform(get("/api/sessions")
                        .header("Authorization", "Bearer " + cliAccess))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode sessions = objectMapper.readTree(listResult.getResponse().getContentAsString());
        assertThat(sessions).hasSize(3);
        assertThat(sessions.toString()).contains("mobile", "browser", "cli");
        assertThat(sessions.toString()).contains("login_at", "last_active_at", "session_id");
        int currentFlags = 0;
        for (JsonNode s : sessions) {
            if (s.get("current").asBoolean()) {
                currentFlags++;
                assertThat(s.get("client_id").asText()).isEqualTo("cli");
            }
        }
        assertThat(currentFlags).as("仅当前会话标记 current").isEqualTo(1);
        log.info("[HTTP] GET /api/sessions 返回 3 个设备，字段与 current 标记正确");

        // 2) 撤销不存在/不属于自己的会话 => 404 session_not_found
        expectError(mockMvc.perform(post("/api/sessions/vid_ghost/revoke")
                        .header("Authorization", "Bearer " + cliAccess)).andReturn(),
                404, "session_not_found");

        // 3) 单独撤销 mobile
        String mobileFamily = findFamily(sessions, "mobile");
        mockMvc.perform(post("/api/sessions/" + mobileFamily + "/revoke")
                        .header("Authorization", "Bearer " + cliAccess))
                .andExpect(status().isNoContent());
        expectError(mockMvc.perform(get("/api/orders")
                        .header("Authorization", "Bearer " + mobileAccess)).andReturn(),
                401, "session_revoked_device_revoked");
        expectError(mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                java.util.Map.of("refreshToken", mobileRefresh))))
                        .andReturn(),
                401, "session_revoked_device_revoked");
        // browser、cli 未被牵连
        mockMvc.perform(get("/api/orders").header("Authorization", "Bearer " + browserAccess))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/orders").header("Authorization", "Bearer " + cliAccess))
                .andExpect(status().isOk());
        log.info("[HTTP] 单设备撤销 mobile 立即失效，browser/cli 正常访问");

        // 4) 退出其他所有设备（以 browser 为当前会话，cli 被退出）
        var revokeOthers = mockMvc.perform(post("/api/sessions/revoke-others")
                        .header("Authorization", "Bearer " + browserAccess))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode othersBody =
                objectMapper.readTree(revokeOthers.getResponse().getContentAsString());
        assertThat(othersBody.get("revoked_count").asInt())
                .as("此时仅剩 cli 一个其他设备").isEqualTo(1);
        expectError(mockMvc.perform(get("/api/orders")
                        .header("Authorization", "Bearer " + cliAccess)).andReturn(),
                401, "session_revoked_other_devices_logout");
        // browser 仍正常
        mockMvc.perform(get("/api/orders").header("Authorization", "Bearer " + browserAccess))
                .andExpect(status().isOk());

        // 5) 列表只剩 browser
        MvcResult finalList = mockMvc.perform(get("/api/sessions")
                        .header("Authorization", "Bearer " + browserAccess))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode remaining =
                objectMapper.readTree(finalList.getResponse().getContentAsString());
        assertThat(remaining).hasSize(1);
        assertThat(remaining.get(0).get("client_id").asText()).isEqualTo("browser");
        assertThat(remaining.get(0).get("current").asBoolean()).isTrue();

        // 6) 审计可查
        MvcResult audit = mockMvc.perform(get("/api/admin/audit")
                        .header("Authorization",
                                "Bearer " + accessToken(login("admin", "admin-pwd"))))
                .andExpect(status().isOk())
                .andReturn();
        String auditBody = audit.getResponse().getContentAsString();
        assertThat(auditBody).contains("SESSION_REVOKE_ONE");
        assertThat(auditBody).contains("SESSION_REVOKE_OTHERS");
        assertThat(auditBody).contains("SESSION_LISTED");
        log.info("[HTTP] 多设备查看/单撤销/退出其他 全链路断言完成");
    }

    /** 上限=2 的 HTTP 超限淘汰测试放在独立嵌套上下文（属性覆盖），保证存储与默认上下文隔离。 */
    @org.junit.jupiter.api.Nested
    @SpringBootTest
    @AutoConfigureMockMvc
    @TestPropertySource(properties = "app.security.max-concurrent-sessions=2")
    class MaxSessionsTwoHttpTests {

        @org.springframework.beans.factory.annotation.Autowired private MockMvc nestedMockMvc;
        @Autowired private ObjectMapper nestedObjectMapper;

        @Test
        void httpLoginBeyondLimitEvictsOldestAndExplainsIt() throws Exception {
            // 独立 Spring 上下文（属性不同），存储为空，初始化器创建 bob。
            MvcResult b1 = loginWithClient(nestedMockMvc, nestedObjectMapper,
                    "bob", "bob-pwd", "bob-http-1");
            Thread.sleep(15);
            MvcResult b2 = loginWithClient(nestedMockMvc, nestedObjectMapper,
                    "bob", "bob-pwd", "bob-http-2");
            Thread.sleep(15);
            MvcResult b3 = loginWithClient(nestedMockMvc, nestedObjectMapper,
                    "bob", "bob-pwd", "bob-http-3");
            log.info("[HTTP] 上限=2 下连续三次登录 bob");

            MvcResult list = nestedMockMvc.perform(get("/api/sessions")
                            .header("Authorization", "Bearer " + token(nestedObjectMapper, b3, "access_token")))
                    .andExpect(status().isOk())
                    .andReturn();
            JsonNode active = nestedObjectMapper.readTree(
                    list.getResponse().getContentAsString());
            assertThat(active).hasSize(2);
            assertThat(active.toString()).contains("bob-http-3");

            nestedMockMvc.perform(get("/api/orders")
                            .header("Authorization", "Bearer " + token(nestedObjectMapper, b3, "access_token")))
                    .andExpect(status().isOk());
            nestedMockMvc.perform(get("/api/orders")
                            .header("Authorization", "Bearer " + token(nestedObjectMapper, b2, "access_token")))
                    .andExpect(status().isOk());

            // 第一个被 LRU 淘汰：错误码明确，区别于自然过期
            MvcResult deniedAccess = nestedMockMvc.perform(get("/api/orders")
                            .header("Authorization", "Bearer " + token(nestedObjectMapper, b1, "access_token")))
                    .andReturn();
            expectError(nestedObjectMapper, deniedAccess, 401, "session_revoked_max_sessions");

            MvcResult deniedRefresh = nestedMockMvc.perform(post("/api/auth/refresh")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(nestedObjectMapper.writeValueAsString(java.util.Map.of(
                                    "refreshToken", token(nestedObjectMapper, b1, "refresh_token")))))
                    .andReturn();
            expectError(nestedObjectMapper, deniedRefresh, 401, "session_revoked_max_sessions");

            MvcResult audit = nestedMockMvc.perform(get("/api/admin/audit")
                            .header("Authorization", "Bearer " + token(
                                    nestedObjectMapper,
                                    loginWithClient(nestedMockMvc, nestedObjectMapper,
                                            "admin", "admin-pwd", "admin-cli"),
                                    "access_token")))
                    .andExpect(status().isOk())
                    .andReturn();
            assertThat(audit.getResponse().getContentAsString()).contains("SESSION_EVICTED");
            log.info("[HTTP] 上限=2 未被冲破，被淘汰设备错误码=session_revoked_max_sessions");
        }
    }

    private static String token(ObjectMapper mapper, MvcResult result, String field) throws Exception {
        return mapper.readTree(result.getResponse().getContentAsString()).get(field).asText();
    }

    private static void expectError(ObjectMapper mapper, MvcResult result,
                                    int httpStatus, String errorCode) throws Exception {
        assertThat(result.getResponse().getStatus()).isEqualTo(httpStatus);
        JsonNode body = mapper.readTree(result.getResponse().getContentAsString());
        assertThat(body.get("error").asText()).isEqualTo(errorCode);
        assertThat(body.get("request_id").asText()).isNotBlank();
        log.info("[HTTP判定] status={} error={}", httpStatus, errorCode);
    }

    private static MvcResult loginWithClient(MockMvc mvc, ObjectMapper mapper,
                                             String username, String password, String clientId)
            throws Exception {
        return mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(java.util.Map.of(
                                "username", username,
                                "password", password,
                                "clientId", clientId))))
                .andExpect(status().isOk())
                .andReturn();
    }

    private MvcResult loginWithClient(String username, String password, String clientId)
            throws Exception {
        return mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(java.util.Map.of(
                                "username", username,
                                "password", password,
                                "clientId", clientId))))
                .andExpect(status().isOk())
                .andReturn();
    }

    private String findFamily(JsonNode sessions, String clientId) {
        for (JsonNode s : sessions) {
            if (clientId.equals(s.get("client_id").asText())) {
                return s.get("session_id").asText();
            }
        }
        throw new IllegalStateException("会话列表中缺少 client_id=" + clientId);
    }
}
