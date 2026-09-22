package com.github.xingjianluo.identitysessionrotationjava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.xingjianluo.identitysessionrotationjava.account.Account;
import com.github.xingjianluo.identitysessionrotationjava.account.AccountRepository;
import com.github.xingjianluo.identitysessionrotationjava.account.AccountService;
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

import java.util.HexFormat;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end HTTP tests: stable error payloads, seeded accounts, protected
 * endpoints, rotation over HTTP, and the audit query endpoint.
 * The reuse grace window is set to 0 so replays classify immediately.
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = "security.refresh-reuse-grace-seconds=0")
class WebLayerTest {

    private static final Logger log = LoggerFactory.getLogger(WebLayerTest.class);
    private static final ObjectMapper JSON = new ObjectMapper();

    @Autowired
    private MockMvc mvc;

    @Autowired
    private AccountRepository accounts;

    private JsonNode login(String username, String password) throws Exception {
        MvcResult result = mvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().isOk())
                .andReturn();
        return JSON.readTree(result.getResponse().getContentAsString());
    }

    @Test
    void loginFailureIsStableAndNeverRevealsExistence() throws Exception {
        MvcResult unknown = mvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"ghost\",\"password\":\"x\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("INVALID_CREDENTIALS"))
                .andReturn();
        MvcResult badPassword = mvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"reader\",\"password\":\"wrong\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("INVALID_CREDENTIALS"))
                .andReturn();
        log.info("[判定依据] 未知用户响应={} 错密码响应={} (两者对外一致)",
                unknown.getResponse().getContentAsString(),
                badPassword.getResponse().getContentAsString());
    }

    @Test
    void protectedEndpointsEnforcePermissionAndTokenValidity() throws Exception {
        JsonNode tokens = login("reader", "reader-password");
        String access = tokens.get("accessToken").asText();
        log.info("[输入] reader 登录成功，访问受保护端点");

        mvc.perform(get("/api/read").header("Authorization", "Bearer " + access))
                .andExpect(status().isOk());
        mvc.perform(get("/api/admin").header("Authorization", "Bearer " + access))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("PERMISSION_DENIED"));
        mvc.perform(get("/api/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("TOKEN_INVALID"));
        log.info("[结论] 有权限=200，无权限=403 PERMISSION_DENIED，无令牌=401 TOKEN_INVALID");
    }

    @Test
    void rotationOverHttpAndReplayRevokesChain() throws Exception {
        JsonNode first = login("reader", "reader-password");
        String refresh1 = first.get("refreshToken").asText();

        MvcResult rotated = mvc.perform(post("/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + refresh1 + "\"}"))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode second = JSON.readTree(rotated.getResponse().getContentAsString());
        String access2 = second.get("accessToken").asText();

        // grace window is 0 in this test profile: replay classifies immediately
        mvc.perform(post("/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + refresh1 + "\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("REFRESH_TOKEN_REUSED"));

        mvc.perform(get("/api/me").header("Authorization", "Bearer " + access2))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("SESSION_REVOKED"))
                .andExpect(jsonPath("$.message").value(
                        org.hamcrest.Matchers.containsString("REFRESH_TOKEN_REUSE_DETECTED")));
        log.info("[结论] HTTP 层重放 -> REFRESH_TOKEN_REUSED，链上访问令牌 -> SESSION_REVOKED");
    }

    @Test
    void logoutRevokesImmediatelyWithDistinctReason() throws Exception {
        JsonNode tokens = login("reader", "reader-password");
        String access = tokens.get("accessToken").asText();

        mvc.perform(post("/auth/logout").header("Authorization", "Bearer " + access))
                .andExpect(status().isOk());
        mvc.perform(get("/api/me").header("Authorization", "Bearer " + access))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("SESSION_REVOKED"))
                .andExpect(jsonPath("$.message").value(
                        org.hamcrest.Matchers.containsString("LOGOUT")));
        log.info("[结论] 登出后旧令牌 -> SESSION_REVOKED(LOGOUT)，与过期可区分");
    }

    @Test
    void disablingAccountRevokesAndAuditIsQueryable() throws Exception {
        // dedicated victim account so other tests are unaffected
        Account victim = new Account("acc-victim", "victim",
                HexFormat.of().formatHex(AccountService.hash("victim-password")),
                Set.of("reader"), Set.of("read"));
        accounts.save(victim);
        JsonNode victimTokens = login("victim", "victim-password");
        String victimAccess = victimTokens.get("accessToken").asText();

        JsonNode adminTokens = login("admin", "admin-password");
        String adminAccess = adminTokens.get("accessToken").asText();

        mvc.perform(post("/api/admin/disable")
                        .header("Authorization", "Bearer " + adminAccess)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"accountId\":\"acc-victim\"}"))
                .andExpect(status().isOk());

        mvc.perform(get("/api/me").header("Authorization", "Bearer " + victimAccess))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("SESSION_REVOKED"))
                .andExpect(jsonPath("$.message").value(
                        org.hamcrest.Matchers.containsString("ACCOUNT_DISABLED")));

        MvcResult audit = mvc.perform(get("/api/audit")
                        .header("Authorization", "Bearer " + adminAccess)
                        .param("accountId", "acc-victim"))
                .andExpect(status().isOk())
                .andReturn();
        String body = audit.getResponse().getContentAsString();
        log.info("[判定依据] acc-victim 审计记录={}", body);
        assertTrue(body.contains("LOGIN_SUCCESS"));
        assertTrue(body.contains("SESSION_REVOKED"));
        assertTrue(body.contains("ACCOUNT_DISABLED"));
        log.info("[结论] 停用即时生效，审计端点可按账户查询到登录与撤销记录");
    }
}
