// 이 파일이 확인하는 것: 소셜 제공자 클라이언트가 스프링에서 문제없이 만들어지는지(생성자가 두 개라 생길 수 있는 오류 확인).

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

    // [상황] 설정만으로 스프링을 띄운다(DB 없이).
    // [기대] 소셜 제공자 클라이언트가 하나 만들어진다.
    @Test
    @DisplayName("애플리케이션 컨텍스트에서 소셜 제공자 클라이언트 빈이 만들어진다")
    void beanIsCreated() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(RestClientAutoConfiguration.class))
                .withUserConfiguration(Props.class, HttpSocialProviderClient.class)
                .run(ctx -> assertThat(ctx).hasNotFailed().hasSingleBean(HttpSocialProviderClient.class));
    }
}
