package com.github.xingjianluo.identitysessionrotationjava.web;

import com.github.xingjianluo.identitysessionrotationjava.service.DeviceSessionService;
import com.github.xingjianluo.identitysessionrotationjava.web.dto.DeviceSessionResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 多设备会话管理入口：查看活跃登录、撤销单个登录、退出其他设备。
 * 均要求有效会话（由拦截器保证），且只能操作本人名下的登录。
 */
@RestController
@RequestMapping("/api/sessions")
public class SessionController {

    private final DeviceSessionService deviceSessionService;

    public SessionController(DeviceSessionService deviceSessionService) {
        this.deviceSessionService = deviceSessionService;
    }

    /** 列出当前账号的活跃登录，标记出当前请求所在的那个。 */
    @GetMapping
    public List<DeviceSessionResponse> list(HttpServletRequest request) {
        String username = (String) request.getAttribute("username");
        String currentFamilyId = (String) request.getAttribute("familyId");
        return deviceSessionService.listActive(username).stream()
                .map(s -> new DeviceSessionResponse(s.getFamilyId(), s.getClient(),
                        s.getCreatedAt(), s.getLastActiveAt(),
                        s.getFamilyId().equals(currentFamilyId)))
                .toList();
    }

    /** 撤销指定的一个登录（仅限本人名下），立即生效且不影响其他登录。 */
    @DeleteMapping("/{familyId}")
    public ResponseEntity<Void> revokeOne(HttpServletRequest request,
                                          @PathVariable String familyId) {
        String username = (String) request.getAttribute("username");
        deviceSessionService.revokeOne(username, familyId);
        return ResponseEntity.noContent().build();
    }

    /** 退出其他所有设备：仅保留当前会话。 */
    @PostMapping("/revoke-others")
    public Map<String, Object> revokeOthers(HttpServletRequest request) {
        String username = (String) request.getAttribute("username");
        String currentFamilyId = (String) request.getAttribute("familyId");
        int revoked = deviceSessionService.revokeOthers(username, currentFamilyId);
        return Map.of("revoked", revoked);
    }
}
