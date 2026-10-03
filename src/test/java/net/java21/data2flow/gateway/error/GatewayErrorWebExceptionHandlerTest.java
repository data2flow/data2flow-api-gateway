package net.java21.data2flow.gateway.error;

import net.java21.data2flow.gateway.config.GatewayProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.cloud.gateway.support.NotFoundException;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ResponseStatusException;
import tools.jackson.databind.json.JsonMapper;

import java.net.ConnectException;
import java.util.concurrent.TimeoutException;
import java.util.stream.Stream;

import org.junit.jupiter.params.provider.Arguments;

import static org.assertj.core.api.Assertions.assertThat;

/** api-rules §4 공통 실패 형식 — gateway가 만드는 모든 실패 */
class GatewayErrorWebExceptionHandlerTest {

    private final GatewayErrorWebExceptionHandler handler = new GatewayErrorWebExceptionHandler(
            JsonMapper.builder().build(), new GatewayMessages(),
            new GatewayProperties(new GatewayProperties.Services("http://a", "http://c", "http://i", "http://m"),
                    null, null, null, null, null, null));

    static Stream<Arguments> cases() {
        return Stream.of(
                Arguments.of(new ResponseStatusException(HttpStatus.NOT_FOUND), 404, "RESOURCE_NOT_FOUND"),
                Arguments.of(new ResponseStatusException(HttpStatus.METHOD_NOT_ALLOWED), 404, "RESOURCE_NOT_FOUND"),
                Arguments.of(new ResponseStatusException(HttpStatus.GATEWAY_TIMEOUT), 503, "SERVICE_UNAVAILABLE"),
                Arguments.of(new ResponseStatusException(HttpStatus.PAYLOAD_TOO_LARGE), 400, "INVALID_REQUEST"),
                Arguments.of(NotFoundException.create(true, "no instance"), 503, "SERVICE_UNAVAILABLE"),
                Arguments.of(new RuntimeException(new ConnectException("refused")), 503, "SERVICE_UNAVAILABLE"),
                Arguments.of(new TimeoutException(), 503, "SERVICE_UNAVAILABLE"),
                Arguments.of(new IllegalStateException("boom"), 500, "INTERNAL_ERROR"));
    }

    @ParameterizedTest(name = "{0} → {1} {2}")
    @MethodSource("cases")
    @DisplayName("예외를 상태·코드로 바꾸고 내부 정보는 응답에 넣지 않는다")
    void maps(Throwable ex, int status, String code) {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/v1/core/x").build());
        handler.handle(exchange, ex).block();
        assertThat(exchange.getResponse().getStatusCode().value()).isEqualTo(status);
        String body = exchange.getResponse().getBodyAsString().block();
        assertThat(body).contains("\"resultCode\":\"" + code + "\"").contains("\"isSuccessful\":false")
                .doesNotContain("boom").doesNotContain("refused");
        if (status == 503) {
            assertThat(exchange.getResponse().getHeaders().getFirst("Retry-After")).isEqualTo("5");
        }
    }
}
