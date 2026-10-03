package net.java21.data2flow.gateway;

import net.java21.data2flow.gateway.support.GatewayIntegrationTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/** IAM-07.07 로그인 호출 한도 — TC-IAM-082(AT-IAM-02.6), 실제 Redis 호환 저장소(Valkey) 토큰 버킷 */
class LoginIT extends GatewayIntegrationTest {

    @Test
    @DisplayName("TC-IAM-082 AT-IAM-02.6 같은 IP로 1분에 21번 로그인 → 21번째 429 AUTH_RATE_LIMITED + Retry-After")
    void twentyFirstLoginIsRejected() {
        for (int i = 1; i <= 20; i++) {
            client.post().uri("/api/v1/auth/login")
                    .bodyValue("{\"loginId\":\"kim.op\",\"password\":\"wrong\"}")
                    .exchange()
                    .expectStatus().isOk()
                    .expectHeader().valueEquals("X-RateLimit-Limit", "20")
                    .expectHeader().valueEquals("X-RateLimit-Remaining", Integer.toString(20 - i))
                    .expectBody().returnResult();
        }
        client.post().uri("/api/v1/auth/login")
                .bodyValue("{\"loginId\":\"kim.op\",\"password\":\"wrong\"}")
                .exchange()
                .expectStatus().isEqualTo(429)
                .expectHeader().valueEquals(HttpHeaders.RETRY_AFTER, "3")
                .expectHeader().valueEquals("X-RateLimit-Remaining", "0")
                .expectHeader().valueEquals("X-RateLimit-Reset", "60")
                .expectBody()
                .jsonPath("$.header.isSuccessful").isEqualTo(false)
                .jsonPath("$.header.resultCode").isEqualTo("AUTH_RATE_LIMITED")
                .jsonPath("$.header.resultMessage").isEqualTo("요청이 너무 많습니다. 3초 후 다시 시도해 주세요");
        assertThat(backend.downstreamRequests()).hasSize(20);

        assertThat(redis.hasKey("data2flow:gw:rl:login:ip:127.0.0.1").block()).isTrue();

        // Retry-After만큼 지나면 다시 1번 받는다(토큰 버킷 충전)
        clock.advanceBy(Duration.ofSeconds(3));
        client.post().uri("/api/v1/auth/login").exchange().expectStatus().isOk();
        client.post().uri("/api/v1/auth/login").exchange().expectStatus().isEqualTo(429);
    }
}
