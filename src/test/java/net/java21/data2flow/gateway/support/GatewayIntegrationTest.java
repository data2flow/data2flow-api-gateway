package net.java21.data2flow.gateway.support;

import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.DockerImageName;


/**
 * 통합(*IT): 실제 Redis 호환 저장소(Testcontainers Valkey, design/testing §2)와 하위 서비스 대역(MockWebServer).
 * 컨테이너는 JVM 하나에 한 번 띄워 모든 IT가 같이 쓰고, 각 테스트 앞에서 키를 비운다.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(GatewayTestSupport.ClockConfig.class)
public abstract class GatewayIntegrationTest extends GatewayTestSupport {

    protected static final GenericContainer<?> VALKEY =
            new GenericContainer<>(DockerImageName.parse("valkey/valkey:8.1-alpine")).withExposedPorts(6379);

    static {
        VALKEY.start();
    }

    @Autowired
    protected ReactiveStringRedisTemplate redis;

    @DynamicPropertySource
    static void redisProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.data.redis.host", VALKEY::getHost);
        registry.add("spring.data.redis.port", () -> VALKEY.getMappedPort(6379));
    }

    @BeforeEach
    void flushRedis() {
        redis.execute(connection -> connection.serverCommands().flushAll()).blockLast();
    }
}
