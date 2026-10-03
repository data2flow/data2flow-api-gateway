package net.java21.data2flow.gateway;

import net.java21.data2flow.gateway.auth.TokenValidationCache;
import net.java21.data2flow.gateway.support.GatewayIntegrationTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

/** IAM-07.07 호출 한도(TC-IAM-200), IAM-07.10 fail-closed·폐기 즉시 반영(TC-IAM-203, AT-IAM-04.1) */
class TokenAuthIT extends GatewayIntegrationTest {

    @Autowired
    TokenValidationCache validationCache;

    private String bearer(String token) {
        return "Bearer " + token;
    }

    @Nested
    @DisplayName("TC-IAM-200 IAM-07.07 로그인·토큰 갱신·실패 시도 한도")
    class RateLimits {

        @Test
        @DisplayName("TC-IAM-200 토큰 갱신: IP당 60회 다음 요청은 429 AUTH_RATE_LIMITED")
        void refreshLimit() {
            for (int i = 0; i < 60; i++) {
                client.post().uri("/api/v1/auth/refresh-token").exchange().expectStatus().isOk().expectBody().returnResult();
            }
            client.post().uri("/api/v1/auth/refresh-token")
                    .exchange()
                    .expectStatus().isEqualTo(429)
                    .expectHeader().valueEquals(HttpHeaders.RETRY_AFTER, "1")
                    .expectBody().jsonPath("$.header.resultCode").isEqualTo("AUTH_RATE_LIMITED");
        }

        @Test
        @DisplayName("TC-IAM-200 실패 시도: 무효 토큰 20번 뒤에는 토큰 조회 없이 429 AUTH_RATE_LIMITED")
        void failedAttempts() {
            for (int i = 0; i < 20; i++) {
                client.get().uri("/api/v1/core/devices").header(HttpHeaders.AUTHORIZATION, bearer("guess-" + i))
                        .exchange().expectStatus().isUnauthorized().expectBody().returnResult();
            }
            client.get().uri("/api/v1/core/devices").header(HttpHeaders.AUTHORIZATION, bearer("guess-x"))
                    .exchange()
                    .expectStatus().isEqualTo(429)
                    .expectHeader().exists(HttpHeaders.RETRY_AFTER)
                    .expectBody().jsonPath("$.header.resultCode").isEqualTo("AUTH_RATE_LIMITED");
            assertThat(backend.introspectRequests()).hasSize(20);
        }

        @Test
        @DisplayName("OPS-12.05 로그인 사용자 요청에도 남은 한도 헤더가 붙는다(userId 버킷)")
        void userLimitHeaders() {
            String token = backend.accessToken("it-user", 7, 1, "sid-u", "jti-u", expInOneHour());
            client.get().uri("/api/v1/core/devices").header(HttpHeaders.AUTHORIZATION, bearer(token))
                    .exchange()
                    .expectStatus().isOk()
                    .expectHeader().valueEquals("X-RateLimit-Limit", "1200")
                    .expectHeader().valueEquals("X-RateLimit-Remaining", "1199");
            assertThat(redis.hasKey("data2flow:gw:rl:user:7").block()).isTrue();
        }
    }

    @Nested
    @DisplayName("TC-IAM-203 IAM-07.10 폐기와 장애")
    class Revocation {

        @Test
        @DisplayName("TC-IAM-203 AT-IAM-04.1 로그아웃(bl:sid 등록) 직후 같은 토큰 → 401 AUTH_SESSION_REVOKED (캐시에 있어도)")
        void logoutRevokesImmediately() {
            String token = backend.accessToken("it-logout", 7, 1, "sid-out", "jti-out", expInOneHour());
            client.get().uri("/api/v1/core/devices").header(HttpHeaders.AUTHORIZATION, bearer(token))
                    .exchange().expectStatus().isOk();

            // auth가 로그아웃 때 하는 일(API-IAM-03): data2flow:bl:sid:{sid} 등록
            redis.opsForValue().set("data2flow:bl:sid:sid-out", "1", Duration.ofMinutes(60)).block();

            client.get().uri("/api/v1/core/devices").header(HttpHeaders.AUTHORIZATION, bearer(token))
                    .exchange()
                    .expectStatus().isUnauthorized()
                    .expectBody().jsonPath("$.header.resultCode").isEqualTo("AUTH_SESSION_REVOKED");
            assertThat(backend.introspectRequests()).hasSize(1);
            assertThat(backend.downstreamRequests()).hasSize(1);
        }

        @Test
        @DisplayName("TC-IAM-203 Access 하나(bl:at:{jti})만 폐기돼도 바로 거부")
        void jtiRevoked() {
            String token = backend.accessToken("it-jti", 7, 1, "sid-j", "jti-x", expInOneHour());
            client.get().uri("/api/v1/core/devices").header(HttpHeaders.AUTHORIZATION, bearer(token))
                    .exchange().expectStatus().isOk();
            redis.opsForValue().set("data2flow:bl:at:jti-x", "1").block();
            client.get().uri("/api/v1/core/devices").header(HttpHeaders.AUTHORIZATION, bearer(token))
                    .exchange().expectStatus().isUnauthorized();
        }

        @Test
        @DisplayName("TC-IAM-203 폐기 이벤트(Pub/Sub data2flow:auth.revocations)를 받으면 검증 캐시에서 바로 지운다")
        void revocationEventEvictsCache() {
            String token = backend.mcpToken("data2flow_evt", 7, 1, "77", "[\"read:telemetry\"]", null);
            client.post().uri("/mcp").header(HttpHeaders.HOST, MCP_HOST).header(HttpHeaders.AUTHORIZATION, bearer(token))
                    .exchange().expectStatus().isOk();
            String key = TokenValidationCache.keyOf(token);
            assertThat(validationCache.find(key)).isPresent();

            await().atMost(Duration.ofSeconds(10)).pollInterval(Duration.ofMillis(100)).untilAsserted(() -> {
                redis.convertAndSend("data2flow:auth.revocations",
                        "{\"type\":\"TOKEN_ID\",\"value\":\"77\",\"reason\":\"API_TOKEN_REVOKED\",\"occurredAt\":\"2026-10-03T00:00:00Z\"}")
                        .block();
                assertThat(validationCache.find(key)).isEmpty();
            });

            backend.inactiveToken("data2flow_evt", "REVOKED");
            client.post().uri("/mcp").header(HttpHeaders.HOST, MCP_HOST).header(HttpHeaders.AUTHORIZATION, bearer(token))
                    .exchange()
                    .expectStatus().isUnauthorized()
                    .expectBody().jsonPath("$.header.resultCode").isEqualTo("AUTH_SESSION_REVOKED");
        }

        @Test
        @DisplayName("TC-IAM-203 블랙리스트 저장소 장애 → 인증이 필요한 요청은 503(fail-closed), 공개 경로 한도는 건너뛴다")
        void blacklistStoreDown() {
            String token = backend.accessToken("it-down", 7, 1, "sid-d", "jti-d", expInOneHour());
            client.get().uri("/api/v1/core/devices").header(HttpHeaders.AUTHORIZATION, bearer(token))
                    .exchange().expectStatus().isOk();

            VALKEY.getDockerClient().pauseContainerCmd(VALKEY.getContainerId()).exec();
            try {
                client.get().uri("/api/v1/core/devices").header(HttpHeaders.AUTHORIZATION, bearer(token))
                        .exchange()
                        .expectStatus().isEqualTo(503)
                        .expectHeader().exists(HttpHeaders.RETRY_AFTER)
                        .expectBody().jsonPath("$.header.resultCode").isEqualTo("SERVICE_UNAVAILABLE");
                client.post().uri("/api/v1/auth/login")
                        .exchange()
                        .expectStatus().isOk()
                        .expectHeader().doesNotExist("X-RateLimit-Limit");
            } finally {
                VALKEY.getDockerClient().unpauseContainerCmd(VALKEY.getContainerId()).exec();
            }
            await().atMost(Duration.ofSeconds(15)).untilAsserted(() ->
                    client.get().uri("/api/v1/core/devices").header(HttpHeaders.AUTHORIZATION, bearer(token))
                            .exchange().expectStatus().isOk());
        }

        @Test
        @DisplayName("TC-IAM-203 인증 서비스 장애 → 503, 복구되면 다시 통과")
        void authServiceDown() {
            String token = backend.accessToken("it-auth-down", 7, 1, "sid-a", "jti-a", expInOneHour());
            backend.authMode(net.java21.data2flow.gateway.support.TestBackend.AuthMode.UNAVAILABLE);
            client.get().uri("/api/v1/core/devices").header(HttpHeaders.AUTHORIZATION, bearer(token))
                    .exchange().expectStatus().isEqualTo(503);
            backend.authMode(net.java21.data2flow.gateway.support.TestBackend.AuthMode.NORMAL);
            client.get().uri("/api/v1/core/devices").header(HttpHeaders.AUTHORIZATION, bearer(token))
                    .exchange().expectStatus().isOk().expectBody().returnResult();
        }
    }
}
