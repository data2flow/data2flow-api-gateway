package net.java21.data2flow.gateway.web;

import net.java21.data2flow.gateway.auth.Principal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatusCode;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.util.regex.Pattern;

/**
 * ⑥ Logging — 요청마다 한 줄의 구조화 로그(staging·prod는 ECS JSON, OPS-02). 응답 머리를 보낼 때 남겨서 거절·404·스트리밍도 빠지지 않는다.
 *
 * <p>남기는 값: requestId, method, path(토큰이 들어가는 구간은 가림), status, durationMs, route, userId.
 * 남기지 않는 값: Authorization·쿠키·토큰 원문, 쿼리 문자열, 본문, IP(BR-OPS-23 비밀값·개인정보 금지).
 */
@Component
public class AccessLogWebFilter implements WebFilter, Ordered {

    public static final int ORDER = CorrelationIdWebFilter.ORDER + 1;
    private static final Logger log = LoggerFactory.getLogger("net.java21.data2flow.gateway.access");

    /** 경로에 들어가는 일회용 토큰(초대·비밀번호 재설정·가입 확인·공유 링크) 구간 */
    private static final Pattern TOKEN_SEGMENT =
            Pattern.compile("/(invitations|password-resets|signup-requests|share)/[^/]+");

    private final Clock clock;

    public AccessLogWebFilter(Clock clock) {
        this.clock = clock;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        if (exchange.getRequest().getPath().value().startsWith("/actuator")) {
            return chain.filter(exchange);   // 프로브·지표 수집은 남기지 않는다
        }
        long started = clock.millis();
        exchange.getResponse().beforeCommit(() -> {
            log(exchange, started);
            return Mono.empty();
        });
        return chain.filter(exchange);
    }

    private void log(ServerWebExchange exchange, long started) {
        HttpStatusCode status = exchange.getResponse().getStatusCode();
        Principal principal = GatewayAttributes.principal(exchange);
        String route = GatewayAttributes.routeId(exchange);
        log.atInfo()
                .addKeyValue("requestId", CorrelationIdWebFilter.requestId(exchange))
                .addKeyValue("method", String.valueOf(exchange.getRequest().getMethod()))
                .addKeyValue("path", maskPath(exchange.getRequest().getPath().value()))
                .addKeyValue("status", status == null ? 200 : status.value())
                .addKeyValue("durationMs", clock.millis() - started)
                .addKeyValue("route", route == null ? "-" : route)
                .addKeyValue("userId", principal == null ? "-" : principal.userId())
                .log("gateway request");
    }

    /** 경로 안의 일회용 토큰을 {@code ***}로 가린다 */
    public static String maskPath(String path) {
        return path == null ? null : TOKEN_SEGMENT.matcher(path).replaceAll("/$1/***");
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}
