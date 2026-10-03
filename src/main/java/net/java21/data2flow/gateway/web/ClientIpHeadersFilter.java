package net.java21.data2flow.gateway.web;

import org.springframework.cloud.gateway.filter.headers.HttpHeadersFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

/**
 * 하위 서비스로 가는 {@code X-Forwarded-For}를 확인한 사용자 IP 한 개로 다시 쓴다(auth.md §5 [보강] 사용자 IP 전달).
 * 신뢰하지 않는 출처가 보낸 값은 버려지고(SCG 기본 동작 + {@link net.java21.data2flow.gateway.ratelimit.ClientIpResolver}),
 * auth의 로그인 감사 로그 ip와 한도 판정이 같은 값을 보게 한다. SCG 머리 필터 중 가장 마지막에 실행한다.
 */
@Component
public class ClientIpHeadersFilter implements HttpHeadersFilter, Ordered {

    static final String X_FORWARDED_FOR = "X-Forwarded-For";

    @Override
    public HttpHeaders filter(HttpHeaders input, ServerWebExchange exchange) {
        String clientIp = GatewayAttributes.clientIp(exchange);
        if (clientIp == null || "unknown".equals(clientIp)) {
            return input;
        }
        HttpHeaders headers = new HttpHeaders();
        headers.putAll(input);
        headers.set(X_FORWARDED_FOR, clientIp);
        return headers;
    }

    @Override
    public boolean supports(Type type) {
        return type == Type.REQUEST;
    }

    @Override
    public int getOrder() {
        return Ordered.LOWEST_PRECEDENCE;
    }
}
