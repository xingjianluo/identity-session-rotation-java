package com.github.xingjianluo.identitysessionrotationjava.tests.support;

import com.github.xingjianluo.identitysessionrotationjava.account.AccountRepository;
import com.github.xingjianluo.identitysessionrotationjava.account.AccountService;
import com.github.xingjianluo.identitysessionrotationjava.audit.AuditService;
import com.github.xingjianluo.identitysessionrotationjava.authz.AuthorizationService;
import com.github.xingjianluo.identitysessionrotationjava.config.SecurityProperties;
import com.github.xingjianluo.identitysessionrotationjava.session.SessionStore;
import com.github.xingjianluo.identitysessionrotationjava.token.TokenService;

/**
 * Plain (non-Spring) wiring of the real components for fast unit tests.
 */
public record TestComponents(
        AccountRepository accounts,
        SessionStore sessions,
        AuditService audit,
        SecurityProperties properties,
        MutableClock clock,
        AccountService accountService,
        TokenService tokenService,
        AuthorizationService authorization) {

    public static TestComponents fresh(MutableClock clock) {
        AccountRepository accounts = new AccountRepository();
        SessionStore sessions = new SessionStore();
        AuditService audit = new AuditService();
        SecurityProperties properties = new SecurityProperties();
        TokenService tokens = new TokenService(accounts, sessions, audit, properties, clock);
        AccountService accountService = new AccountService(accounts, sessions, audit);
        AuthorizationService authorization = new AuthorizationService(audit);
        return new TestComponents(accounts, sessions, audit, properties, clock,
                accountService, tokens, authorization);
    }
}
