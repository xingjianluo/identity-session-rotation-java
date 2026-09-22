package com.github.xingjianluo.identitysessionrotationjava.config;

import com.github.xingjianluo.identitysessionrotationjava.account.Account;
import com.github.xingjianluo.identitysessionrotationjava.account.AccountRepository;
import com.github.xingjianluo.identitysessionrotationjava.account.AccountService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HexFormat;
import java.util.Set;

/**
 * Seeds demo accounts for local verification:
 * <ul>
 *   <li>admin / admin-password &mdash; role admin, permissions read, admin:disable, admin:audit</li>
 *   <li>reader / reader-password &mdash; permission read only</li>
 * </ul>
 */
@Configuration
public class DataInitializer {

    @Bean
    public CommandLineRunner seedAccounts(AccountRepository repository) {
        return args -> {
            repository.save(new Account("acc-admin", "admin", hash("admin-password"),
                    Set.of("admin"), Set.of("read", "admin:disable", "admin:audit")));
            repository.save(new Account("acc-reader", "reader", hash("reader-password"),
                    Set.of("reader"), Set.of("read")));
        };
    }

    private static String hash(String raw) {
        return HexFormat.of().formatHex(AccountService.hash(raw));
    }
}
