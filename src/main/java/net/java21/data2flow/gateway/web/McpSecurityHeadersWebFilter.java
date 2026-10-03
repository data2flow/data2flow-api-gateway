package net.java21.data2flow.gateway.web;

import net.java21.data2flow.gateway.config.GatewayProperties;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Locale;

/**
 * 외부 공개 MCP 호스트 응답에 보안 헤더를 단다(auth.md §5 [보강] 보안 헤더, §11 10번).
 * 사용자 API는 BFF가 같은 헤더를 달고, gateway의 내부 경로에는 필요 없다.
 */
@Component
public class McpSecurityHeadersWebFilter implements WebFilter, Ordered {

    public static final int ORDER = CorrelationIdWebFilter.ORDER + 3;

    private final String mcpHost;

    public McpSecurityHeadersWebFilter(GatewayProperties properties) {
        this.mcpHost = properties.mcpHost() == null ? null : properties.mcpHost().toLowerCase(Locale.ROOT);
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        if (mcpHost != null && mcpHost.equals(host(exchange))) {
            exchange.getResponse().beforeCommit(() -> {
                HttpHeaders headers = exchange.getResponse().getHeaders();
                headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
                headers.set("X-Content-Type-Options", "nosniff");
                headers.set("X-Frame-Options", "DENY");
                headers.set("Referrer-Policy", "no-referrer");
                headers.set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
                return Mono.empty();
            });
        }
        return chain.filter(exchange);
    }

    static String host(ServerWebExchange exchange) {
        String host = exchange.getRequest().getHeaders().getFirst(HttpHeaders.HOST);
        if (host == null) {
            return null;
        }
        int colon = host.lastIndexOf(':');
        String name = colon > 0 && host.indexOf(']') < colon ? host.substring(0, colon) : host;
        return name.toLowerCase(Locale.ROOT);
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}
