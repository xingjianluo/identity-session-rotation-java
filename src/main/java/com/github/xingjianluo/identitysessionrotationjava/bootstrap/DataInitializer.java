package com.github.xingjianluo.identitysessionrotationjava.bootstrap;

import com.github.xingjianluo.identitysessionrotationjava.config.SecurityProperties;
import com.github.xingjianluo.identitysessionrotationjava.domain.Account;
import com.github.xingjianluo.identitysessionrotationjava.domain.AccountStatus;
import com.github.xingjianluo.identitysessionrotationjava.domain.Role;
import com.github.xingjianluo.identitysessionrotationjava.security.PasswordEncoder;
import com.github.xingjianluo.identitysessionrotationjava.store.AccountStore;
import java.util.EnumSet;
import java.util.Set;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/** 启动时按 app.security.bootstrap-accounts 创建本地演示账户。 */
@Component
@Order(0)
public class DataInitializer implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(DataInitializer.class);

    private final SecurityProperties properties;
    private final AccountStore accountStore;
    private final PasswordEncoder passwordEncoder;

    public DataInitializer(SecurityProperties properties, AccountStore accountStore,
                           PasswordEncoder passwordEncoder) {
        this.properties = properties;
        this.accountStore = accountStore;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(ApplicationArguments args) {
        for (SecurityProperties.BootstrapAccount cfg : properties.getBootstrapAccounts()) {
            Set<Role> roles = EnumSet.noneOf(Role.class);
            if (cfg.getRoles() != null) {
                for (String raw : cfg.getRoles()) {
                    try {
                        roles.add(Role.valueOf(raw.trim().toUpperCase()));
                    } catch (IllegalArgumentException e) {
                        log.warn("初始化账户 {} 时忽略未知角色: {}", cfg.getUsername(), raw);
                    }
                }
            }
            if (roles.isEmpty()) {
                roles.add(Role.USER);
            }
            Account account = new Account(
                    cfg.getUsername(),
                    passwordEncoder.encode(cfg.getPassword()),
                    AccountStatus.ACTIVE,
                    roles);
            accountStore.save(account);
            log.info("初始化本地账户 username={} roles={}",
                    cfg.getUsername(),
                    roles.stream().map(Enum::name).collect(Collectors.joining(",")));
        }
    }
}
