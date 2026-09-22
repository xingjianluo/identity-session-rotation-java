package com.github.xingjianluo.identitysessionrotationjava.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.xingjianluo.identitysessionrotationjava.domain.Permission;
import com.github.xingjianluo.identitysessionrotationjava.error.ErrorCode;
import com.github.xingjianluo.identitysessionrotationjava.service.AccessTokenService;
import com.github.xingjianluo.identitysessionrotationjava.web.dto.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * 受保护入口的授权拦截器：按声明的权限做判定，拒绝时写出稳定错误响应。
 */
@Component
public class AuthorizationInterceptor implements HandlerInterceptor {

    private final AccessTokenService accessTokenService;
    private final ProtectedRoutes protectedRoutes;
    private final ObjectMapper objectMapper;

    public AuthorizationInterceptor(AccessTokenService accessTokenService,
                                    ProtectedRoutes protectedRoutes,
                                    ObjectMapper objectMapper) {
        this.accessTokenService = accessTokenService;
        this.protectedRoutes = protectedRoutes;
        this.objectMapper = objectMapper;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response,
                             Object handler) throws IOException {
        String path = request.getRequestURI().substring(request.getContextPath().length());
        Permission required = protectedRoutes.requiredPermission(path).orElse(null);
        AccessTokenService.AccessDecision decision =
                accessTokenService.authorize(request.getHeader("Authorization"), required);

        if (decision.allowed()) {
            if (decision.username() != null) {
                request.setAttribute("username", decision.username());
                request.setAttribute("familyId", decision.familyId());
                request.setAttribute("sessionId", decision.sessionId());
            }
            return true;
        }

        ErrorCode code = resolve(decision.errorCode());
        response.setStatus(code.httpStatus());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        String requestId = MDC.get("requestId");
        ErrorResponse body = new ErrorResponse(code.code(), decision.reason(),
                requestId != null ? requestId : "-");
        objectMapper.writeValue(response.getWriter(), body);
        return false;
    }

    private ErrorCode resolve(String stableCode) {
        for (ErrorCode code : ErrorCode.values()) {
            if (code.code().equals(stableCode)) {
                return code;
            }
        }
        return ErrorCode.INVALID_TOKEN;
    }
}
