package com.github.xingjianluo.identitysessionrotationjava.auth;

import com.github.xingjianluo.identitysessionrotationjava.account.Account;
import com.github.xingjianluo.identitysessionrotationjava.account.AccountService;
import com.github.xingjianluo.identitysessionrotationjava.token.TokenPair;
import com.github.xingjianluo.identitysessionrotationjava.token.TokenService;
import com.github.xingjianluo.identitysessionrotationjava.web.BearerToken;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Authentication endpoints: login, refresh rotation, logout.
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AccountService accountService;
    private final TokenService tokenService;

    public AuthController(AccountService accountService, TokenService tokenService) {
        this.accountService = accountService;
        this.tokenService = tokenService;
    }

    public record LoginRequest(String username, String password) {
    }

    public record RefreshRequest(String refreshToken) {
    }

    @PostMapping("/login")
    public TokenPair login(@RequestBody LoginRequest request) {
        Account account = accountService.verifyLogin(request.username(), request.password());
        return tokenService.issueSession(account);
    }

    @PostMapping("/refresh")
    public TokenPair refresh(@RequestBody RefreshRequest request) {
        return tokenService.rotate(request.refreshToken());
    }

    @PostMapping("/logout")
    public Map<String, String> logout(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        tokenService.logout(BearerToken.extract(authorization));
        return Map.of("status", "logged_out");
    }
}
