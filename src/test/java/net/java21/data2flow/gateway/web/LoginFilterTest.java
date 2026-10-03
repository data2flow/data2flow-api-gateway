package net.java21.data2flow.gateway.web;

import net.java21.data2flow.gateway.config.GatewayProperties.Limit;
import net.java21.data2flow.gateway.support.GatewaySliceTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import reactor.core.publisher.Mono;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Mockito.never;

/** IAM-07.07 로그인·재발급·실패 시도 호출 한도(②, IP 기준) — TC-IAM-083(AT-IAM-02.6), OPS-12.05 */
class LoginFilterTest extends GatewaySliceTest {

    @Test
    @DisplayName("TC-IAM-083 AT-IAM-02.6 같은 IP의 로그인 한도 초과 → 429 AUTH_RATE_LIMITED + Retry-After + X-RateLimit-*")
    void loginRateLimited() {
        given(rateLimiter.consume(eq("login:ip:127.0.0.1"), any())).willReturn(Mono.just(exceeded(20, 3)));

        client.post().uri("/api/v1/auth/login")
                .bodyValue("{\"loginId\":\"kim.op\",\"password\":\"x\"}")
                .exchange()
                .expectStatus().isEqualTo(429)
                .expectHeader().valueEquals(HttpHeaders.RETRY_AFTER, "3")
                .expectHeader().valueEquals("X-RateLimit-Limit", "20")
                .expectHeader().valueEquals("X-RateLimit-Remaining", "0")
                .expectHeader().valueEquals("X-RateLimit-Reset", "3")
                .expectBody()
                .jsonPath("$.header.isSuccessful").isEqualTo(false)
                .jsonPath("$.header.resultCode").isEqualTo("AUTH_RATE_LIMITED")
                .jsonPath("$.header.resultMessage").isEqualTo("요청이 너무 많습니다. 3초 후 다시 시도해 주세요");
        assertThat(backend.downstreamRequests()).isEmpty();
        then(rateLimiter).should().consume(eq("login:ip:127.0.0.1"), eq(new Limit(20, Duration.ofSeconds(60))));
    }

    @Test
    @DisplayName("한도 안이면 통과하고 남은 한도 헤더가 붙는다(OPS-12.05)")
    void loginWithinLimit() {
        client.post().uri("/api/v1/auth/login")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals("X-RateLimit-Limit", "20")
                .expectHeader().valueEquals("X-RateLimit-Remaining", "19");
    }

    @ParameterizedTest(name = "{0} {1} → {2} {3}")
    @CsvSource({
            "POST, /api/v1/auth/login/mfa, login:ip:127.0.0.1, AUTH_RATE_LIMITED",
            "POST, /api/v1/auth/refresh-token, refresh:ip:127.0.0.1, AUTH_RATE_LIMITED",
            "POST, /api/v1/auth/logout, refresh:ip:127.0.0.1, AUTH_RATE_LIMITED",
            "POST, /api/v1/core/password-resets, account:ip:127.0.0.1, AUTH_RATE_LIMITED",
            "GET, /api/v1/core/public/release-notes, public-api:ip:127.0.0.1, RATE_LIMITED"
    })
    @DisplayName("OPS-12.05 공개 경로별 IP 버킷과 오류 코드(로그인·재발급·계정은 AUTH_RATE_LIMITED)")
    void publicPolicies(String method, String path, String bucket, String code) {
        given(rateLimiter.consume(eq(bucket), any())).willReturn(Mono.just(exceeded(60, 10)));
        client.method(HttpMethod.valueOf(method)).uri(path)
                .exchange()
                .expectStatus().isEqualTo(429)
                .expectBody().jsonPath("$.header.resultCode").isEqualTo(code);
    }

    @Test
    @DisplayName("IAM-07.07 무효 토큰 실패 시도가 한도에 이른 IP는 토큰 조회 전에 429 AUTH_RATE_LIMITED")
    void failedAttemptsBlocked() {
        given(rateLimiter.checkFailures(eq("failed-auth:ip:127.0.0.1"), any())).willReturn(Mono.just(exceeded(20, 42)));
        client.get().uri("/api/v1/core/devices")
                .header(HttpHeaders.AUTHORIZATION, "Bearer guessing")
                .exchange()
                .expectStatus().isEqualTo(429)
                .expectHeader().valueEquals(HttpHeaders.RETRY_AFTER, "42")
                .expectBody().jsonPath("$.header.resultCode").isEqualTo("AUTH_RATE_LIMITED");
        assertThat(backend.introspectRequests()).isEmpty();
    }

    @Test
    @DisplayName("토큰 없는 보호 경로는 실패 한도를 보지 않고 401")
    void noTokenSkipsFailureCheck() {
        client.get().uri("/api/v1/core/devices").exchange().expectStatus().isUnauthorized();
        then(rateLimiter).should(never()).checkFailures(anyString(), any());
    }
}
