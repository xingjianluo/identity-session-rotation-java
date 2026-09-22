package com.github.xingjianluo.identitysessionrotationjava.api;

import com.github.xingjianluo.identitysessionrotationjava.account.AccountService;
import com.github.xingjianluo.identitysessionrotationjava.audit.AuditEvent;
import com.github.xingjianluo.identitysessionrotationjava.audit.AuditEventType;
import com.github.xingjianluo.identitysessionrotationjava.audit.AuditService;
import com.github.xingjianluo.identitysessionrotationjava.authz.AuthorizationService;
import com.github.xingjianluo.identitysessionrotationjava.error.ApiException;
import com.github.xingjianluo.identitysessionrotationjava.error.ErrorCode;
import com.github.xingjianluo.identitysessionrotationjava.token.TokenService;
import com.github.xingjianluo.identitysessionrotationjava.web.BearerToken;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * Protected endpoints used to exercise the authorization rules:
 * <ul>
 *   <li>GET /api/me &mdash; any valid session</li>
 *   <li>GET /api/read &mdash; requires permission {@code read}</li>
 *   <li>GET /api/admin &mdash; requires role {@code admin}</li>
 *   <li>POST /api/password &mdash; self password change (immediate revocation)</li>
 *   <li>POST /api/admin/disable &mdash; disable an account (admin only)</li>
 *   <li>GET /api/audit &mdash; query audit records (admin only)</li>
 * </ul>
 */
@RestController
public class ProtectedController {

    private final TokenService tokenService;
    private final AuthorizationService authorization;
    private final AccountService accountService;
    private final AuditService auditService;

    public ProtectedController(TokenService tokenService,
                               AuthorizationService authorization,
                               AccountService accountService,
                               AuditService auditService) {
        this.tokenService = tokenService;
        this.authorization = authorization;
        this.accountService = accountService;
        this.auditService = auditService;
    }

    public record PasswordChangeRequest(String accountId, String newPassword) {
    }

    public record DisableRequest(String accountId) {
    }

    @GetMapping("/api/me")
    public Map<String, Object> me(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader) {
        TokenService.AuthContext ctx = tokenService.authenticate(BearerToken.extract(authorizationHeader));
        return Map.of("accountId", ctx.accountId(),
                "sessionId", ctx.sessionId(),
                "roles", ctx.roles(),
                "permissions", ctx.permissions());
    }

    @GetMapping("/api/read")
    public Map<String, String> read(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader) {
        TokenService.AuthContext ctx = tokenService.authenticate(BearerToken.extract(authorizationHeader));
        authorization.requirePermission(ctx, "read");
        return Map.of("data", "readable resource");
    }

    @GetMapping("/api/admin")
    public Map<String, String> admin(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader) {
        TokenService.AuthContext ctx = tokenService.authenticate(BearerToken.extract(authorizationHeader));
        authorization.requireRole(ctx, "admin");
        return Map.of("data", "admin resource");
    }

    @PostMapping("/api/password")
    public Map<String, String> changePassword(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader,
            @RequestBody PasswordChangeRequest request) {
        TokenService.AuthContext ctx = tokenService.authenticate(BearerToken.extract(authorizationHeader));
        if (!ctx.accountId().equals(request.accountId())) {
            throw new ApiException(ErrorCode.PERMISSION_DENIED, "can only change own password");
        }
        accountService.changePassword(request.accountId(), request.newPassword());
        return Map.of("status", "password_changed");
    }

    @PostMapping("/api/admin/disable")
    public Map<String, String> disable(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader,
            @RequestBody DisableRequest request) {
        TokenService.AuthContext ctx = tokenService.authenticate(BearerToken.extract(authorizationHeader));
        authorization.requirePermission(ctx, "admin:disable");
        accountService.disable(request.accountId());
        return Map.of("status", "account_disabled");
    }

    @GetMapping("/api/audit")
    public List<AuditEvent> audit(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader,
            @RequestParam(required = false) String type,
            @RequestParam(required = false) String accountId) {
        TokenService.AuthContext ctx = tokenService.authenticate(BearerToken.extract(authorizationHeader));
        authorization.requirePermission(ctx, "admin:audit");
        AuditEventType eventType = type == null ? null : AuditEventType.valueOf(type);
        return auditService.query(eventType, accountId);
    }
}
