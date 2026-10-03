package net.java21.data2flow.gateway.support;

import net.java21.data2flow.gateway.auth.TokenValidationCache;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.time.Duration;
import java.time.Instant;

/**
 * gateway 테스트 공통: 실제 포트로 띄운 gateway(WebTestClient) + 하위 서비스 대역(MockWebServer) + 테스트 시계.
 * 슬라이스 테스트는 Redis 쪽을 {@code @MockitoBean}으로, 통합 테스트(*IT)는 Testcontainers Valkey로 채운다.
 */
public abstract class GatewayTestSupport {

    public static final String MCP_HOST = "data2flow-mcp.java21.net";
    public static final String NOW = "2026-10-03T00:00:00Z";

    protected static final TestBackend backend = TestBackend.get();

    @LocalServerPort
    protected int port;

    @Autowired
    protected MutableClock clock;

    @Autowired
    protected TokenValidationCache cache;

    protected WebTestClient client;

    @DynamicPropertySource
    static void backendProperties(DynamicPropertyRegistry registry) {
        registry.add("data2flow.gateway.services.auth", backend::baseUrl);
        registry.add("data2flow.gateway.services.core", backend::baseUrl);
        registry.add("data2flow.gateway.services.ai", backend::baseUrl);
        registry.add("data2flow.gateway.services.mcp", backend::baseUrl);
        registry.add("data2flow.gateway.mcp-host", () -> MCP_HOST);
        registry.add("management.server.port", () -> "0");
    }

    @BeforeEach
    void resetSupport() {
        backend.reset();
        cache.clear();
        clock.setInstant(Instant.parse(NOW));
        client = WebTestClient.bindToServer()
                .baseUrl("http://localhost:" + port)
                .responseTimeout(Duration.ofSeconds(10))
                .build();
    }

    /** 지금부터 1시간 뒤 만료(epoch 초) */
    protected long expInOneHour() {
        return clock.instant().plusSeconds(3600).getEpochSecond();
    }

    @TestConfiguration(proxyBeanMethods = false)
    public static class ClockConfig {

        @Bean
        @Primary
        public MutableClock testClock() {
            return MutableClock.atUtc(NOW);
        }
    }
}
