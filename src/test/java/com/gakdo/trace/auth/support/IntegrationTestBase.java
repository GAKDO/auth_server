package com.gakdo.trace.auth.support;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;

/**
 * PostgreSQL·Redis가 있어야 하는 통합 테스트의 바탕.
 * CI(GitHub Actions)는 Testcontainers로 띄우고, Docker가 없는 Claude 세션은 TRACE_IT_LOCAL=1이면 로컬 PostgreSQL(테스트 전용 DB trace_it)·Redis(localhost:6379, DB 15)에 붙는다.
 * 개발 DB trace를 더럽히지 않게 따로 둔다. 만들기: {@code createdb -U postgres trace_it}
 * 둘 다 없으면 건너뛴다(@Testcontainers(disabledWithoutDocker = true)와 같은 효과, plan.md Complexity Tracking).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
public abstract class IntegrationTestBase {

    private static final boolean LOCAL = "1".equals(System.getenv("TRACE_IT_LOCAL"));
    private static PostgreSQLContainer<?> postgres;
    private static GenericContainer<?> redis;

    /** 하위 테스트 클래스에 @EnabledIf("…IntegrationTestBase#infrastructureAvailable")로 붙인다(@EnabledIf는 상속되지 않음). */
    public static boolean infrastructureAvailable() {
        return LOCAL || dockerAvailable();
    }

    private static boolean dockerAvailable() {
        try {
            return DockerClientFactory.instance().isDockerAvailable();
        } catch (RuntimeException e) {
            return false;
        }
    }

    @DynamicPropertySource
    static void infrastructure(DynamicPropertyRegistry registry) {
        // RabbitMQ 없이 돈다. 봉인 영수증 테스트는 리스너의 handle()을 직접 부른다
        registry.add("spring.rabbitmq.listener.simple.auto-startup", () -> "false");
        if (LOCAL) {
            registry.add("spring.datasource.url", () -> "jdbc:postgresql://localhost:5432/trace_it?currentSchema=auth");
            registry.add("spring.datasource.username", () -> "postgres");
            registry.add("spring.data.redis.host", () -> "localhost");
            registry.add("spring.data.redis.port", () -> "6379");
            registry.add("spring.data.redis.database", () -> "15");
            return;
        }
        startContainers();
        registry.add("spring.datasource.url", () -> postgres.getJdbcUrl() + "&currentSchema=auth");
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.data.redis.host", redis::getHost);
        registry.add("spring.data.redis.port", () -> redis.getMappedPort(6379));
        registry.add("spring.data.redis.database", () -> "0");
    }

    private static synchronized void startContainers() {
        if (postgres == null) {
            postgres = new PostgreSQLContainer<>("postgres:16-alpine").withDatabaseName("trace");
            postgres.start();
            redis = new GenericContainer<>("redis:7-alpine").withExposedPorts(6379);
            redis.start();
        }
    }
}
