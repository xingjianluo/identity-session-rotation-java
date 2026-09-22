package com.github.xingjianluo.identitysessionrotationjava.web;

import com.github.xingjianluo.identitysessionrotationjava.domain.AuditEvent;
import com.github.xingjianluo.identitysessionrotationjava.error.AuthException;
import com.github.xingjianluo.identitysessionrotationjava.error.ErrorCode;
import com.github.xingjianluo.identitysessionrotationjava.service.AccountService;
import com.github.xingjianluo.identitysessionrotationjava.store.AuditStore;
import com.github.xingjianluo.identitysessionrotationjava.web.dto.ChangePasswordRequest;
import com.github.xingjianluo.identitysessionrotationjava.web.dto.SetAccountStatusRequest;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** 账户自助管理与管理员接口。 */
@RestController
@RequestMapping("/api")
public class AdminController {

    private final AccountService accountService;
    private final AuditStore auditStore;

    public AdminController(AccountService accountService, AuditStore auditStore) {
        this.accountService = accountService;
        this.auditStore = auditStore;
    }

    /** 修改自己的密码（需要有效会话），成功后该账户既有令牌立即失效。 */
    @PostMapping("/account/password")
    public ResponseEntity<Void> changePassword(HttpServletRequest request,
                                               @RequestBody ChangePasswordRequest body) {
        if (body == null) {
            throw new AuthException(ErrorCode.BAD_REQUEST);
        }
        String username = (String) request.getAttribute("username");
        accountService.changePassword(username, body.oldPassword(), body.newPassword());
        return ResponseEntity.noContent().build();
    }

    /** 管理员启停账户（需要 ADMIN_AUDIT_READ 准入，见路由表）。 */
    @PostMapping("/admin/accounts/status")
    public ResponseEntity<Void> setAccountStatus(HttpServletRequest request,
                                                 @RequestBody SetAccountStatusRequest body) {
        if (body == null || body.username() == null || body.username().isBlank()) {
            throw new AuthException(ErrorCode.BAD_REQUEST);
        }
        String operator = (String) request.getAttribute("username");
        accountService.setStatus(operator, body.username(), body.active());
        return ResponseEntity.noContent().build();
    }

    /** 查询审计记录，可按类型 / 用户名过滤。 */
    @GetMapping("/admin/audit")
    public List<AuditEvent> audit(@RequestParam(required = false) String type,
                                  @RequestParam(required = false) String username) {
        if (type != null) {
            return auditStore.findByType(type);
        }
        if (username != null) {
            return auditStore.findByUsername(username);
        }
        return auditStore.findAll();
    }
}
