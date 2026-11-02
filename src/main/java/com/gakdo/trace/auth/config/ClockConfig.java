package com.gakdo.trace.auth.config;

import java.time.Clock;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** 만료 계산을 테스트에서 고정할 수 있게 Clock을 빈으로 둔다. */
@Configuration
@EnableConfigurationProperties(AuthProperties.class)
public class ClockConfig {

    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }
}
