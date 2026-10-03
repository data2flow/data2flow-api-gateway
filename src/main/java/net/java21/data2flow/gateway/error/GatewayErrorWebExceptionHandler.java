package net.java21.data2flow.gateway.error;

import net.java21.data2flow.contracts.error.CommonErrorCode;
import net.java21.data2flow.contracts.error.ErrorCode;
import net.java21.data2flow.gateway.config.GatewayProperties;
import net.java21.data2flow.gateway.web.CorrelationIdWebFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.webflux.error.ErrorWebExceptionHandler;
import org.springframework.cloud.gateway.support.NotFoundException;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import tools.jackson.databind.ObjectMapper;

import java.net.ConnectException;
import java.util.Map;
import java.util.concurrent.TimeoutException;

/**
 * gateway 실패 응답을 공통 형식 {@code {header:{isSuccessful:false, resultCode, resultMessage}}}으로 바꾸는 유일한 곳
 * (api-rules §4, OPS-12.01). Boot 기본 처리기(@Order(-1))보다 먼저 실행해 기본 오류 본문(timestamp, path…)이 나가지 않게 한다.
 *
 * <ul>
 *   <li>필터의 거절({@link GatewayRejectedException}) → 그 코드와 헤더 그대로</li>
 *   <li>라우트 없음 → 404 {@code RESOURCE_NOT_FOUND}(catch-all 라우트 없음, auth.md §2)</li>
 *   <li>하위 서비스 연결 실패·응답 시간 초과 → 503 {@code SERVICE_UNAVAILABLE} + Retry-After</li>
 *   <li>그 밖 → 500 {@code INTERNAL_ERROR}(문구에 요청 ID, 내부 정보는 응답에 넣지 않음)</li>
 * </ul>
 */
@Component
@Order(-2)
public class GatewayErrorWebExceptionHandler implements ErrorWebExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GatewayErrorWebExceptionHandler.class);

    private final ObjectMapper objectMapper;
    private final GatewayMessages messages;
    private final GatewayProperties properties;

    public GatewayErrorWebExceptionHandler(ObjectMapper objectMapper, GatewayMessages messages,
                                           GatewayProperties properties) {
        this.objectMapper = objectMapper;
        this.messages = messages;
        this.properties = properties;
    }

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, Throwable ex) {
        ServerHttpResponse response = exchange.getResponse();
        if (response.isCommitted()) {
            return Mono.error(ex);
        }
        String requestId = CorrelationIdWebFilter.requestId(exchange);
        GatewayRejectedException rejection = toRejection(ex, requestId);
        logRejection(exchange, ex, rejection, requestId);

        ErrorCode code = rejection.code();
        response.setStatusCode(HttpStatusCode.valueOf(code.httpStatus()));
        HttpHeaders headers = response.getHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        rejection.headers().forEach(headers::set);

        String message = messages.resolve(code,
                exchange.getRequest().getHeaders().getFirst(HttpHeaders.ACCEPT_LANGUAGE), rejection.messageArgs());
        byte[] body = objectMapper.writeValueAsBytes(GatewayErrorBody.of(code.code(), message));
        return response.writeWith(Mono.just(response.bufferFactory().wrap(body)));
    }

    private GatewayRejectedException toRejection(Throwable ex, String requestId) {
        if (ex instanceof GatewayRejectedException rejected) {
            return rejected;
        }
        if (ex instanceof NotFoundException) {
            // 라우트는 있지만 대상 인스턴스를 찾지 못함(SCG) — 하위 서비스 장애로 본다
            return unavailable();
        }
        if (ex instanceof ResponseStatusException status) {
            HttpStatusCode statusCode = status.getStatusCode();
            if (statusCode.value() == HttpStatus.NOT_FOUND.value()
                    || statusCode.value() == HttpStatus.METHOD_NOT_ALLOWED.value()) {
                return GatewayRejectedException.of(CommonErrorCode.RESOURCE_NOT_FOUND);
            }
            if (statusCode.value() == HttpStatus.GATEWAY_TIMEOUT.value()
                    || statusCode.value() == HttpStatus.SERVICE_UNAVAILABLE.value()) {
                return unavailable();
            }
            if (statusCode.is4xxClientError()) {
                return GatewayRejectedException.of(CommonErrorCode.INVALID_REQUEST);
            }
        }
        for (Throwable cause = ex; cause != null; cause = cause.getCause()) {
            if (cause instanceof ConnectException || cause instanceof TimeoutException) {
                return unavailable();
            }
        }
        return new GatewayRejectedException(CommonErrorCode.INTERNAL_ERROR, Map.of(), requestId);
    }

    private GatewayRejectedException unavailable() {
        return GatewayRejectedException.unavailable(properties.unavailableRetryAfter());
    }

    private void logRejection(ServerWebExchange exchange, Throwable ex, GatewayRejectedException rejection,
                              String requestId) {
        String method = String.valueOf(exchange.getRequest().getMethod());
        String path = exchange.getRequest().getPath().value();
        if (rejection.code() == CommonErrorCode.INTERNAL_ERROR) {
            log.atError().setCause(ex).addKeyValue("requestId", requestId)
                    .log("gateway unhandled error: {} {}", method, path);
        } else if (!(ex instanceof GatewayRejectedException)) {
            log.atWarn().addKeyValue("requestId", requestId).addKeyValue("resultCode", rejection.code().code())
                    .log("gateway error: {} {} ({})", method, path, ex.getClass().getSimpleName());
        }
    }
}
