package net.java21.data2flow.gateway.web;

import net.java21.data2flow.contracts.identity.DataflowHeaders;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.UUID;
import java.util.regex.Pattern;

/**
 * ① CorrelationId(auth.md §1, api-rules §6): 들어온 {@code X-REQUEST-ID}가 안전한 값이면 유지하고, 없거나 이상하면 UUID를 새로 만든다.
 * 하위 서비스 요청과 응답 모두에 같은 값을 싣는다. 라우트 밖(404, 거절 응답)에도 붙도록 WebFilter로 가장 먼저 실행한다.
 */
@Component
public class CorrelationIdWebFilter implements WebFilter, Ordered {

    public static final String ATTRIBUTE = CorrelationIdWebFilter.class.getName() + ".requestId";
    public static final int ORDER = Ordered.HIGHEST_PRECEDENCE + 10;

    /** 로그 주입·헤더 분할을 막는다: 영숫자와 - _ . : 만, 128자까지 */
    private static final Pattern SAFE = Pattern.compile("[A-Za-z0-9._:-]{1,128}");

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String incoming = exchange.getRequest().getHeaders().getFirst(DataflowHeaders.REQUEST_ID);
        String requestId = incoming != null && SAFE.matcher(incoming).matches() ? incoming : UUID.randomUUID().toString();

        ServerHttpRequest request = exchange.getRequest().mutate()
                .headers(headers -> headers.set(DataflowHeaders.REQUEST_ID, requestId))
                .build();
        exchange.getResponse().getHeaders().set(DataflowHeaders.REQUEST_ID, requestId);
        ServerWebExchange mutated = exchange.mutate().request(request).build();
        mutated.getAttributes().put(ATTRIBUTE, requestId);
        return chain.filter(mutated);
    }

    /** 이 요청의 요청 ID. 필터를 거치지 않은 경우(이론상)에는 헤더 값 */
    public static String requestId(ServerWebExchange exchange) {
        Object value = exchange.getAttribute(ATTRIBUTE);
        return value != null ? value.toString() : exchange.getRequest().getHeaders().getFirst(DataflowHeaders.REQUEST_ID);
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}
