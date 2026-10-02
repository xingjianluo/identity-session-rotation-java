package com.github.xingjianluo.identitysessionrotationjava.web;

import com.github.xingjianluo.identitysessionrotationjava.service.DeviceSessionService;
import com.github.xingjianluo.identitysessionrotationjava.web.dto.RevokeOthersResponse;
import com.github.xingjianluo.identitysessionrotationjava.web.dto.SessionInfoResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 多设备会话管理入口（仅需有效会话，不要求额外权限）。
 *
 * <ul>
 *   <li>{@code GET  /api/sessions}：查看当前账户全部活跃设备登录</li>
 *   <li>{@code POST /api/sessions/{sessionId}/revoke}：单独撤销某设备</li>
 *   <li>{@code POST /api/sessions/revoke-others}：退出其他所有设备</li>
 * </ul>
 */
@RestController
@RequestMapping("/api/sessions")
public class SessionController {

    private final DeviceSessionService deviceSessionService;

    public SessionController(DeviceSessionService deviceSessionService) {
        this.deviceSessionService = deviceSessionService;
    }

    /** 查看当前账户的全部活跃设备登录（含登录时间、最近活跃时间、客户端/来源）。 */
    @GetMapping
    public List<SessionInfoResponse> list(HttpServletRequest request) {
        String username = (String) request.getAttribute("username");
        String familyId = (String) request.getAttribute("familyId");
        return deviceSessionService.listSessions(username, familyId);
    }

    /** 撤销指定的单个设备会话；只影响被点名的会话。 */
    @PostMapping("/{sessionId}/revoke")
    public ResponseEntity<Void> revokeOne(HttpServletRequest request,
                                          @PathVariable("sessionId") String sessionId) {
        String username = (String) request.getAttribute("username");
        deviceSessionService.revokeSession(username, sessionId);
        return ResponseEntity.noContent().build();
    }

    /** 退出其他所有设备（当前会话保留并可继续访问）。 */
    @PostMapping("/revoke-others")
    public RevokeOthersResponse revokeOthers(HttpServletRequest request) {
        String username = (String) request.getAttribute("username");
        String familyId = (String) request.getAttribute("familyId");
        int revoked = deviceSessionService.revokeOtherSessions(username, familyId);
        return new RevokeOthersResponse(revoked);
    }
}
