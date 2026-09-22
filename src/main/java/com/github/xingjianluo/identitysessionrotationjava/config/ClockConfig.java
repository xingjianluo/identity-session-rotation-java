package com.github.xingjianluo.identitysessionrotationjava.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/**
 * Exposes the system clock as a bean so time-dependent services (expiry,
 * rotation) can be driven by a controllable clock in tests.
 */
@Configuration
public class ClockConfig {

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }
}
