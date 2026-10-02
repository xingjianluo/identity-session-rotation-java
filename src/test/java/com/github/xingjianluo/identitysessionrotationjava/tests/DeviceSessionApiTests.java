package com.github.xingjianluo.identitysessionrotationjava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;
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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** 端到端：多设备会话的查看、单会话撤销、退出其他设备的 HTTP 行为。 */
@SpringBootTest
@AutoConfigureMockMvc
class DeviceSessionApiTests {

    private static final Logger log = LoggerFactory.getLogger(DeviceSessionApiTests.class);

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;

    private MvcResult login(String username, String password, String client)
            throws Exception {
        return mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "username", username, "password", password,
                                "client", client))))
                .andExpect(status().isOk())
                .andReturn();
    }

    private String accessToken(MvcResult loginResult) throws Exception {
        return objectMapper.readTree(loginResult.getResponse().getContentAsString())
                .get("access_token").asText();
    }

    private JsonNode listSessions(String accessToken) throws Exception {
        MvcResult result = mockMvc.perform(get("/api/sessions")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andReturn();
        return objectMapper.readTree(result.getResponse().getContentAsString());
    }

    @Test
    void listRevokeOneAndRevokeOthersOverHttp() throws Exception {
        // 三个客户端同时登录
        MvcResult mobile = login("alice", "alice-pwd", "mobile");
        MvcResult web = login("alice", "alice-pwd", "web");
        MvcResult cli = login("alice", "alice-pwd", "cli");
        String mobileToken = accessToken(mobile);
        String webToken = accessToken(web);
        String cliToken = accessToken(cli);

        // 查看：能看到全部活跃登录，含客户端标识与时间，且标记当前会话
        JsonNode sessions = listSessions(mobileToken);
        log.info("[HTTP] GET /api/sessions -> {}", sessions);
        assertThat(sessions.size()).isGreaterThanOrEqualTo(3);
        String mobileId = null;
        String webId = null;
        for (JsonNode s : sessions) {
            assertThat(s.get("client").asText()).isNotBlank();
            assertThat(s.get("created_at").asText()).isNotBlank();
            assertThat(s.get("last_active_at").asText()).isNotBlank();
            if (s.get("current").asBoolean()) {
                mobileId = s.get("session_id").asText();
                assertThat(s.get("client").asText()).isEqualTo("mobile");
            }
            if (s.get("client").asText().equals("web")) {
                webId = s.get("session_id").asText();
            }
        }
        assertThat(mobileId).as("当前会话应被标记 current=true").isNotNull();
        assertThat(webId).isNotNull();

        // 单独撤销 web：web 立即失效，mobile/cli 不受影响
        mockMvc.perform(delete("/api/sessions/" + webId)
                        .header("Authorization", "Bearer " + mobileToken))
                .andExpect(status().isNoContent());
        MvcResult webDenied = mockMvc.perform(get("/api/profile")
                        .header("Authorization", "Bearer " + webToken))
                .andReturn();
        JsonNode webError = objectMapper.readTree(
                webDenied.getResponse().getContentAsString());
        assertThat(webDenied.getResponse().getStatus()).isEqualTo(401);
        assertThat(webError.get("error").asText()).isEqualTo("session_revoked_by_user");
        mockMvc.perform(get("/api/profile")
                        .header("Authorization", "Bearer " + mobileToken))
                .andExpect(status().isOk());
        log.info("[HTTP判定] 单独撤销 web -> web={}, mobile 仍可访问",
                webError.get("error").asText());

        // 撤销他人/不存在的会话 -> 404 session_not_found
        MvcResult notFound = mockMvc.perform(delete("/api/sessions/vid_not_exists")
                        .header("Authorization", "Bearer " + mobileToken))
                .andReturn();
        JsonNode notFoundBody = objectMapper.readTree(
                notFound.getResponse().getContentAsString());
        assertThat(notFound.getResponse().getStatus()).isEqualTo(404);
        assertThat(notFoundBody.get("error").asText()).isEqualTo("session_not_found");

        // 退出其他设备：只留 mobile
        MvcResult revokeOthers = mockMvc.perform(post("/api/sessions/revoke-others")
                        .header("Authorization", "Bearer " + mobileToken))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode revokeBody = objectMapper.readTree(
                revokeOthers.getResponse().getContentAsString());
        log.info("[HTTP] POST /api/sessions/revoke-others -> {}", revokeBody);
        assertThat(revokeBody.get("revoked").asInt()).isGreaterThanOrEqualTo(1);

        MvcResult cliDenied = mockMvc.perform(get("/api/profile")
                        .header("Authorization", "Bearer " + cliToken))
                .andReturn();
        JsonNode cliError = objectMapper.readTree(
                cliDenied.getResponse().getContentAsString());
        assertThat(cliError.get("error").asText()).isEqualTo("session_revoked_by_user");
        mockMvc.perform(get("/api/profile")
                        .header("Authorization", "Bearer " + mobileToken))
                .andExpect(status().isOk());

        // 列表最终只剩当前会话
        JsonNode remaining = listSessions(mobileToken);
        assertThat(remaining.size()).isEqualTo(1);
        assertThat(remaining.get(0).get("current").asBoolean()).isTrue();
        log.info("[HTTP判定] 退出其他设备 -> cli={}, 仅当前会话保留",
                cliError.get("error").asText());
    }

    @Test
    void sessionEndpointsRequireAuthentication() throws Exception {
        MvcResult noToken = mockMvc.perform(get("/api/sessions")).andReturn();
        assertThat(noToken.getResponse().getStatus()).isEqualTo(401);
        JsonNode body = objectMapper.readTree(
                noToken.getResponse().getContentAsString());
        assertThat(body.get("error").asText()).isEqualTo("missing_token");
        log.info("[HTTP判定] 未认证访问 /api/sessions -> missing_token");
    }
}
