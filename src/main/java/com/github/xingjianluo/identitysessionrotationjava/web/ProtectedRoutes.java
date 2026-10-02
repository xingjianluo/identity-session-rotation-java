package com.github.xingjianluo.identitysessionrotationjava.web;

import com.github.xingjianluo.identitysessionrotationjava.domain.Permission;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

/**
 * 受保护路由表：路径模式 -> 所需权限。
 * 值为 null 表示仅要求有效会话（不要求额外权限）。
 */
@Component
public class ProtectedRoutes {

    private final AntPathMatcher matcher = new AntPathMatcher();
    private final Map<String, Permission> routes = new LinkedHashMap<>();

    public ProtectedRoutes() {
        // 仅认证
        routes.put("/api/auth/logout", null);
        routes.put("/api/account/password", null);
        routes.put("/api/sessions", null);
        routes.put("/api/sessions/revoke-others", null);
        routes.put("/api/sessions/*/revoke", null);
        // 按权限
        routes.put("/api/profile", Permission.PROFILE_READ);
        routes.put("/api/orders", Permission.ORDER_READ);
        // 管理端：审计读取/账户管理（这里以 ADMIN_AUDIT_READ 作为管理端准入权限）
        routes.put("/api/admin/**", Permission.ADMIN_AUDIT_READ);
    }

    /** 返回匹配路由所需权限；未受保护的路径返回 OPTIONAL_EMPTY 标记。 */
    public java.util.Optional<Permission> requiredPermission(String lookupPath) {
        for (Map.Entry<String, Permission> e : routes.entrySet()) {
            if (matcher.match(e.getKey(), lookupPath)) {
                return java.util.Optional.ofNullable(e.getValue());
            }
        }
        return java.util.Optional.empty();
    }

    public boolean isProtected(String lookupPath) {
        return routes.keySet().stream().anyMatch(p -> matcher.match(p, lookupPath));
    }
}
