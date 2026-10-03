package net.java21.data2flow.gateway.web;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * ⑤ CookiePolicy(auth.md §1, crowfoot CookiePolicyGlobalFilter 준용 + 변경).
 *
 * <ul>
 *   <li>{@code data2flow_session}(BFF 세션 쿠키, auth.md §9.1)은 BFF 밖으로 나갈 이유가 없으므로 어느 서비스에도 넘기지 않는다</li>
 *   <li>{@code data2flow_refresh}(Refresh 토큰, API-IAM-01·02)는 auth 라우트에만 넘기고 core·ai·MCP로는 넘기지 않는다</li>
 * </ul>
 * 다른 쿠키는 그대로 둔다.
 */
@Component
public class CookiePolicyGlobalFilter implements GlobalFilter, Ordered {

    public static final int ORDER = -50;
    static final String SESSION_COOKIE = "data2flow_session";
    static final String REFRESH_COOKIE = "data2flow_refresh";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        List<String> cookieHeaders = exchange.getRequest().getHeaders().get(HttpHeaders.COOKIE);
        if (cookieHeaders == null || cookieHeaders.isEmpty()) {
            return chain.filter(exchange);
        }
        Set<String> blocked = GatewayAttributes.ROUTE_AUTH.equals(GatewayAttributes.routeId(exchange))
                ? Set.of(SESSION_COOKIE)
                : Set.of(SESSION_COOKIE, REFRESH_COOKIE);
        List<String> kept = cookieHeaders.stream()
                .map(header -> withoutCookies(header, blocked))
                .filter(header -> !header.isEmpty())
                .toList();
        if (kept.equals(cookieHeaders)) {
            return chain.filter(exchange);
        }
        ServerHttpRequest request = exchange.getRequest().mutate()
                .headers(headers -> {
                    headers.remove(HttpHeaders.COOKIE);
                    if (!kept.isEmpty()) {
                        headers.put(HttpHeaders.COOKIE, kept);
                    }
                })
                .build();
        return chain.filter(exchange.mutate().request(request).build());
    }

    static String withoutCookies(String cookieHeader, Set<String> blocked) {
        return Arrays.stream(cookieHeader.split(";"))
                .map(String::trim)
                .filter(pair -> !pair.isEmpty())
                .filter(pair -> !blocked.contains(pair.split("=", 2)[0].trim()))
                .collect(Collectors.joining("; "));
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}
