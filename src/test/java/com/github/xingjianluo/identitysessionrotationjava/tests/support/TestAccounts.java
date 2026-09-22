package com.github.xingjianluo.identitysessionrotationjava.tests.support;

import com.github.xingjianluo.identitysessionrotationjava.account.Account;
import com.github.xingjianluo.identitysessionrotationjava.account.AccountRepository;

import java.util.HexFormat;
import java.util.Set;

/**
 * Account factory used by tests. Passwords are stored with the same
 * demo SHA-256 hash as production.
 */
public final class TestAccounts {

    private TestAccounts() {
    }

    public static Account create(AccountRepository repo, String id, String username,
                                 String rawPassword, Set<String> roles,
                                 Set<String> permissions) {
        String hash = HexFormat.of().formatHex(
                com.github.xingjianluo.identitysessionrotationjava.account.AccountService
                        .hash(rawPassword));
        Account account = new Account(id, username, hash, roles, permissions);
        return repo.save(account);
    }
}
