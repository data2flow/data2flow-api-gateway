package net.java21.data2flow.gateway.web;

import net.java21.data2flow.gateway.support.GatewaySliceTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.http.HttpHeaders;
import reactor.core.publisher.Mono;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;

/** OPS-12.05 호출 한도 응답 규약 — TC-OPS-131, AT-OPS-25.6 */
class ApiConventionFilterTest extends GatewaySliceTest {

    @Test
    @DisplayName("TC-OPS-131 한도 초과 → 429, resultCode RATE_LIMITED, isSuccessful=false, '{n}초 후' 문구, Retry-After·X-RateLimit-*")
    void rateLimitedEnvelope() {
        given(rateLimiter.consume(anyString(), any())).willReturn(Mono.just(exceeded(1200, 7)));
        String token = backend.accessToken("acc-conv", 7, 1, "s", "j", expInOneHour());

        client.get().uri("/api/v1/core/devices")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchange()
                .expectStatus().isEqualTo(429)
                .expectHeader().valueEquals(HttpHeaders.RETRY_AFTER, "7")
                .expectHeader().valueEquals("X-RateLimit-Limit", "1200")
                .expectHeader().valueEquals("X-RateLimit-Remaining", "0")
                .expectHeader().valueEquals("X-RateLimit-Reset", "7")
                .expectHeader().exists("X-REQUEST-ID")
                .expectHeader().contentType("application/json")
                .expectBody()
                .jsonPath("$.header.isSuccessful").isEqualTo(false)
                .jsonPath("$.header.resultCode").isEqualTo("RATE_LIMITED")
                .jsonPath("$.header.resultMessage").isEqualTo("요청이 너무 많습니다. 7초 후 다시 시도해 주세요");
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource(delimiter = '|', value = {
            "en|Too many requests. Please try again in 7 seconds",
            "ja-JP|リクエストが多すぎます。7秒後に再度お試しください",
            "zh-Hans-CN|请求过多，请在 7 秒后重试",
            "fr|요청이 너무 많습니다. 7초 후 다시 시도해 주세요"})
    @DisplayName("TC-OPS-131 Accept-Language(ko·en·ja·zh)로 resultMessage만 현지화, 지원 밖 언어는 한국어")
    void localized(String language, String expected) {
        given(rateLimiter.consume(anyString(), any())).willReturn(Mono.just(exceeded(20, 7)));
        client.get().uri("/api/v1/core/public/release-notes")
                .header(HttpHeaders.ACCEPT_LANGUAGE, language)
                .exchange()
                .expectStatus().isEqualTo(429)
                .expectBody()
                .jsonPath("$.header.resultCode").isEqualTo("RATE_LIMITED")
                .jsonPath("$.header.resultMessage").isEqualTo(expected);
    }
}
