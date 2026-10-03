package net.java21.data2flow.gateway.web;

import net.java21.data2flow.gateway.config.GatewayProperties.Limit;
import net.java21.data2flow.gateway.support.GatewaySliceTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import reactor.core.publisher.Mono;

import java.time.Duration;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;

/** ④ 인증 뒤 사용자·장기 토큰별 호출 한도 — TC-IAM-152(AT-IAM-12.5), OPS-12.05 */
class AuthorizationFilterTest extends GatewaySliceTest {

    @Test
    @DisplayName("TC-IAM-152 AT-IAM-12.5 API 키 분당 한도 600을 넘으면 429 RATE_LIMITED + Retry-After")
    void apiTokenLimit() {
        String token = backend.mcpToken("data2flow_k600", 7, 1, "55", "[\"read:telemetry\"]", 600L);
        Limit perMinute600 = new Limit(600, Duration.ofMinutes(1));
        given(rateLimiter.consume(eq("token:55"), eq(perMinute600))).willReturn(Mono.just(exceeded(600, 1)));

        client.post().uri("/mcp/messages")
                .header(HttpHeaders.HOST, MCP_HOST)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchange()
                .expectStatus().isEqualTo(429)
                .expectHeader().valueEquals(HttpHeaders.RETRY_AFTER, "1")
                .expectHeader().valueEquals("X-RateLimit-Limit", "600")
                .expectBody().jsonPath("$.header.resultCode").isEqualTo("RATE_LIMITED");
    }

    @Test
    @DisplayName("장기 토큰에 한도가 없으면 기본 api-token 한도, 로그인 사용자는 user 한도(userId 버킷)")
    void defaultLimits() {
        String mcp = backend.mcpToken("data2flow_def", 7, 1, "56", "\"read:devices\"", null);
        client.post().uri("/mcp").header(HttpHeaders.HOST, MCP_HOST)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + mcp)
                .exchange().expectStatus().isOk();
        then(rateLimiter).should().consume(eq("token:56"), eq(new Limit(600, Duration.ofSeconds(60))));

        String access = backend.accessToken("acc-u", 9, 1, "s", "j", expInOneHour());
        client.get().uri("/api/v1/core/devices").header(HttpHeaders.AUTHORIZATION, "Bearer " + access)
                .exchange().expectStatus().isOk()
                .expectHeader().valueEquals("X-RateLimit-Limit", "20");
        then(rateLimiter).should().consume(eq("user:9"), eq(new Limit(1200, Duration.ofSeconds(60))));
    }
}
