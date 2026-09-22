package com.github.xingjianluo.identitysessionrotationjava.store;

import com.github.xingjianluo.identitysessionrotationjava.domain.Account;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/** 内存账户存储，用户名小写为键。 */
@Component
public class AccountStore {

    private final ConcurrentHashMap<String, Account> byUsername = new ConcurrentHashMap<>();

    public void save(Account account) {
        byUsername.put(key(account.getUsername()), account);
    }

    public Optional<Account> findByUsername(String username) {
        if (username == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(byUsername.get(key(username)));
    }

    public List<Account> findAll() {
        return List.copyOf(byUsername.values());
    }

    private static String key(String username) {
        return username.trim().toLowerCase();
    }
}
