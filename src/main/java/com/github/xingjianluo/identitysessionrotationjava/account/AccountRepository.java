package com.github.xingjianluo.identitysessionrotationjava.account;

import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * In-memory account store keyed by both id and username.
 */
@Repository
public class AccountRepository {

    private final ConcurrentMap<String, Account> byId = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, String> usernameToId = new ConcurrentHashMap<>();

    public Optional<Account> findByUsername(String username) {
        if (username == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(usernameToId.get(username)).map(byId::get);
    }

    public Optional<Account> findById(String id) {
        if (id == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(byId.get(id));
    }

    public Account save(Account account) {
        byId.put(account.id(), account);
        usernameToId.put(account.username(), account.id());
        return account;
    }
}
