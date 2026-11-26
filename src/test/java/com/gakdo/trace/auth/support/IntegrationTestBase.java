// 테스트 공통 바탕(테스트 자체는 아님): 진짜 PostgreSQL·Redis가 필요한 통합 테스트용.
// GitHub Actions에서는 Docker로 띄우고, Docker가 없는 곳에서는 TRACE_IT_LOCAL=1이면 로컬 테스트 전용 DB에 붙는다.
// 둘 다 없으면 통합 테스트는 건너뛴다.

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
// (도구) @SpringBootTest = 서버 전체를 띄우는 통합 테스트. MOCK = 진짜 포트는 열지 않고 가짜 웹 환경으로 띄운다
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
public abstract class IntegrationTestBase {

    // 환경 변수 TRACE_IT_LOCAL이 1이면 로컬 테스트 DB를 쓴다는 표시
    private static final boolean LOCAL = "1".equals(System.getenv("TRACE_IT_LOCAL"));
    // (도구) Testcontainers = 테스트 동안 Docker로 진짜 DB·Redis를 잠깐 띄우는 도구
    // Docker로 띄울 PostgreSQL 그릇(처음엔 비어 있음)
    private static PostgreSQLContainer<?> postgres;
    // Docker로 띄울 Redis 그릇
    private static GenericContainer<?> redis;

    /** 하위 테스트 클래스에 @EnabledIf("…IntegrationTestBase#infrastructureAvailable")로 붙인다(@EnabledIf는 상속되지 않음). */
    public static boolean infrastructureAvailable() {
        // 로컬 DB를 쓰거나 Docker가 있으면 통합 테스트를 돌릴 수 있다고 답한다
        return LOCAL || dockerAvailable();
    }

    private static boolean dockerAvailable() {
        try {
            // Docker를 쓸 수 있는지 물어본다
            return DockerClientFactory.instance().isDockerAvailable();
        } catch (RuntimeException e) {
            // 물어보다 오류가 나면 "없음"으로 본다 = 테스트를 건너뛰게
            return false;
        }
    }

    // (도구) @DynamicPropertySource = 테스트가 시작될 때 DB 주소 같은 설정 값을 코드로 정해 넣는다
    @DynamicPropertySource
    static void infrastructure(DynamicPropertyRegistry registry) {
        // RabbitMQ 없이 돈다. 봉인 영수증 테스트는 리스너의 handle()을 직접 부른다
        registry.add("spring.rabbitmq.listener.simple.auto-startup", () -> "false");
        // 로컬 모드면 로컬 PostgreSQL·Redis 주소를 넣는다
        if (LOCAL) {
            // DB 주소: 로컬 테스트 전용 DB(trace_it)의 auth 스키마
            registry.add("spring.datasource.url", () -> "jdbc:postgresql://localhost:5432/trace_it?currentSchema=auth");
            // DB 사용자 이름
            registry.add("spring.datasource.username", () -> "postgres");
            // Redis 주소
            registry.add("spring.data.redis.host", () -> "localhost");
            // Redis 포트
            registry.add("spring.data.redis.port", () -> "6379");
            // Redis 15번 DB를 써서 개발 데이터와 섞이지 않게 한다
            registry.add("spring.data.redis.database", () -> "15");
            // 로컬 설정을 마쳤으니 컨테이너는 띄우지 않고 끝낸다
            return;
        }
        // Docker로 PostgreSQL·Redis를 띄운다(이미 떴으면 그대로 쓴다)
        startContainers();
        // 띄운 PostgreSQL 주소에 auth 스키마를 붙여 넣는다
        registry.add("spring.datasource.url", () -> postgres.getJdbcUrl() + "&currentSchema=auth");
        // 컨테이너가 정한 DB 사용자 이름을 넣는다
        registry.add("spring.datasource.username", postgres::getUsername);
        // 컨테이너가 정한 DB 비밀번호를 넣는다(시험용 임시 값)
        registry.add("spring.datasource.password", postgres::getPassword);
        // 띄운 Redis 주소를 넣는다
        registry.add("spring.data.redis.host", redis::getHost);
        // Redis 6379 포트가 바깥에서 연결된 포트 번호를 넣는다
        registry.add("spring.data.redis.port", () -> redis.getMappedPort(6379));
        // Redis 0번 DB를 쓴다
        registry.add("spring.data.redis.database", () -> "0");
    }

    private static synchronized void startContainers() {
        // 아직 안 띄웠을 때만 띄운다 = 여러 테스트 클래스가 컨테이너 하나를 같이 쓴다
        if (postgres == null) {
            // PostgreSQL 16 컨테이너를 trace DB 이름으로 준비한다
            postgres = new PostgreSQLContainer<>("postgres:16-alpine").withDatabaseName("trace");
            // PostgreSQL을 띄운다
            postgres.start();
            // Redis 7 컨테이너를 6379 포트를 열도록 준비한다
            redis = new GenericContainer<>("redis:7-alpine").withExposedPorts(6379);
            // Redis를 띄운다
            redis.start();
        }
    }
}
