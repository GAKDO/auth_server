package com.gakdo.trace.auth.social.infra;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.web.client.RestClientAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

import com.gakdo.trace.auth.config.SocialProperties;

/** 생성자가 둘이어도 스프링이 빈을 만든다(DB 없이 확인). */
class HttpSocialProviderClientWiringTest {

    @Configuration
    @EnableConfigurationProperties(SocialProperties.class)
    static class Props {
    }

    @Test
    @DisplayName("애플리케이션 컨텍스트에서 소셜 제공자 클라이언트 빈이 만들어진다")
    void beanIsCreated() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(RestClientAutoConfiguration.class))
                .withUserConfiguration(Props.class, HttpSocialProviderClient.class)
                .run(ctx -> assertThat(ctx).hasNotFailed().hasSingleBean(HttpSocialProviderClient.class));
    }
}
