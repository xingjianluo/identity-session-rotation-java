package com.github.xingjianluo.identitysessionrotationjava.web;

import com.github.xingjianluo.identitysessionrotationjava.error.AuthException;
import com.github.xingjianluo.identitysessionrotationjava.error.ErrorCode;
import com.github.xingjianluo.identitysessionrotationjava.service.AuthService;
import com.github.xingjianluo.identitysessionrotationjava.web.dto.LoginRequest;
import com.github.xingjianluo.identitysessionrotationjava.web.dto.RefreshRequest;
import com.github.xingjianluo.identitysessionrotationjava.web.dto.TokenPairResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** 认证入口：登录 / 刷新 / 登出。 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public TokenPairResponse login(@RequestBody LoginRequest request) {
        if (request == null) {
            throw new AuthException(ErrorCode.BAD_REQUEST);
        }
        return authService.login(request);
    }

    @PostMapping("/refresh")
    public TokenPairResponse refresh(@RequestBody RefreshRequest request) {
        if (request == null) {
            throw new AuthException(ErrorCode.BAD_REQUEST);
        }
        return authService.refresh(request);
    }

    /** 登出（需要有效访问令牌，由拦截器保证），撤销其所在会话链。 */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        String token = header == null ? null
                : header.substring("Bearer ".length()).trim();
        authService.logout(token);
        return ResponseEntity.noContent().build();
    }
}
