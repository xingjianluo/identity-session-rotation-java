package com.github.xingjianluo.identitysessionrotationjava.authz;

import com.github.xingjianluo.identitysessionrotationjava.audit.AuditEventType;
import com.github.xingjianluo.identitysessionrotationjava.audit.AuditService;
import com.github.xingjianluo.identitysessionrotationjava.error.ApiException;
import com.github.xingjianluo.identitysessionrotationjava.error.ErrorCode;
import com.github.xingjianluo.identitysessionrotationjava.token.TokenService;
import org.springframework.stereotype.Service;

/**
 * Role/permission based authorization over an authenticated context.
 * Every denial is audited and raises the stable PERMISSION_DENIED error.
 */
@Service
public class AuthorizationService {

    private final AuditService auditService;

    public AuthorizationService(AuditService auditService) {
        this.auditService = auditService;
    }

    /** Requires the caller to hold {@code permission}. */
    public void requirePermission(TokenService.AuthContext ctx, String permission) {
        if (ctx == null || !ctx.permissions().contains(permission)) {
            deny(ctx, "required_permission=" + permission);
        }
    }

    /** Requires the caller to hold {@code role}. */
    public void requireRole(TokenService.AuthContext ctx, String role) {
        if (ctx == null || !ctx.roles().contains(role)) {
            deny(ctx, "required_role=" + role);
        }
    }

    private void deny(TokenService.AuthContext ctx, String detail) {
        auditService.record(AuditEventType.ACCESS_DENIED,
                ctx == null ? null : ctx.accountId(),
                ctx == null ? null : ctx.sessionId(),
                detail);
        throw new ApiException(ErrorCode.PERMISSION_DENIED, detail);
    }
}
