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
}
