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

    // (도구) @Configuration = 스프링 설정 묶음이라는 표시. @EnableConfigurationProperties = 설정 값(SocialProperties)을 읽어 부품으로 만들어 준다
    // 테스트용 최소 설정: 소셜 로그인 설정 값만 읽게 한다
    @Configuration
    @EnableConfigurationProperties(SocialProperties.class)
    static class Props {
    }

    // [상황] 설정만으로 스프링을 띄운다(DB 없이).
    // [기대] 소셜 제공자 클라이언트가 하나 만들어진다.
    // (도구) @Test = JUnit에게 "이 메서드가 테스트 하나"라고 알리는 표시. @DisplayName = 결과 화면에 보일 한글 이름
    @Test
    @DisplayName("애플리케이션 컨텍스트에서 소셜 제공자 클라이언트 빈이 만들어진다")
    void beanIsCreated() {
        // (도구) ApplicationContextRunner = 서버 전체 대신 고른 부품만으로 작은 스프링을 잠깐 띄워 보는 도구
        // 실행: 작은 스프링을 준비한다
        new ApplicationContextRunner()
                // HTTP 호출 도구(RestClient) 자동 설정을 넣는다(소셜 제공자 클라이언트가 필요로 함)
                .withConfiguration(AutoConfigurations.of(RestClientAutoConfiguration.class))
                // 위 설정 묶음과 시험할 소셜 제공자 클라이언트를 넣는다
                .withUserConfiguration(Props.class, HttpSocialProviderClient.class)
                // (도구) hasNotFailed() = 스프링이 오류 없이 떴는지, hasSingleBean(종류) = 그 부품이 딱 하나 만들어졌는지 본다
                // 실행+확인: 띄워 보고, 실패 없이 소셜 제공자 클라이언트가 하나 만들어져야 한다 = 생성자가 두 개여도 스프링이 헷갈리지 않는다
                .run(ctx -> assertThat(ctx).hasNotFailed().hasSingleBean(HttpSocialProviderClient.class));
    }
}
