package net.java21.data2flow.gateway;

import net.java21.data2flow.gateway.support.GatewayIntegrationTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;

import static org.assertj.core.api.Assertions.assertThat;

/** IAM-05 MCP 장기 토큰의 gateway 구간 — TC-IAM-145(AT-IAM-12.1), TC-IAM-152(AT-IAM-12.5), backend.md GatewayExposureIT */
class AuthorizationIT extends GatewayIntegrationTest {

    @Test
    @DisplayName("TC-IAM-145 AT-IAM-12.1 read:telemetry MCP 토큰으로 https://data2flow-mcp.java21.net/mcp 호출 → 200, 토큰 신원만 전달")
    void mcpCallSucceeds() {
        String token = backend.mcpToken("data2flow_it145", 7, 1, "145", "[\"read:telemetry\"]", null);
        client.post().uri("/mcp")
                .header(HttpHeaders.HOST, MCP_HOST)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .header("X-USER-ID", "1")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals("X-RateLimit-Limit", "600")
                .expectHeader().valueEquals("Referrer-Policy", "no-referrer");
        assertThat(backend.lastDownstream().getHeader("X-USER-ID")).isEqualTo("7");
        assertThat(backend.lastDownstream().getHeader("X-ACCESS-TOKEN-ID")).isEqualTo("145");
    }

    @Test
    @DisplayName("TC-IAM-152 AT-IAM-12.5 분당 한도 600인 API 키의 601번째 호출 → 429 + Retry-After")
    void perTokenLimit() {
        String token = backend.mcpToken("data2flow_it152", 7, 1, "152", "[\"read:telemetry\"]", 600L);
        for (int i = 0; i < 600; i++) {
            client.post().uri("/mcp").header(HttpHeaders.HOST, MCP_HOST)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .exchange().expectStatus().isOk().expectBody().returnResult();
        }
        client.post().uri("/mcp").header(HttpHeaders.HOST, MCP_HOST)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchange()
                .expectStatus().isEqualTo(429)
                .expectHeader().valueEquals(HttpHeaders.RETRY_AFTER, "1")
                .expectBody().jsonPath("$.header.resultCode").isEqualTo("RATE_LIMITED");
    }

    @Test
    @DisplayName("GatewayExposureIT MCP 호스트에서 /api/v1/**는 404")
    void mcpHostExposure() {
        client.get().uri("/api/v1/core/public/release-notes").header(HttpHeaders.HOST, MCP_HOST)
                .exchange()
                .expectStatus().isNotFound()
                .expectBody().jsonPath("$.header.resultCode").isEqualTo("RESOURCE_NOT_FOUND");
    }
}
