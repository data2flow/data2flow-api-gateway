package net.java21.data2flow.gateway.ratelimit;

import org.springframework.cloud.gateway.config.GatewayProperties;
import org.springframework.cloud.gateway.filter.headers.TrustedProxies;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;

import java.net.InetSocketAddress;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * 사용자 IP(auth.md §5 [보강] 사용자 IP 전달). 모든 요청이 BFF(또는 MCP 호스트의 Ingress)를 거치므로 접속 주소는 프록시다.
 * 신뢰 프록시({@code spring.cloud.gateway.server.webflux.trusted-proxies} 정규식)에서 온 요청만 {@code X-Forwarded-For}
 * 첫 항목(BFF가 사용자 IP 하나로 다시 쓴 값)을 믿고, 그 밖에서 온 값은 버리고 접속 주소를 쓴다.
 * 로그인 시도 한도와 하위 서비스(감사 로그 ip)가 이 값을 쓴다.
 */
@Component
public class ClientIpResolver {

    static final String X_FORWARDED_FOR = "X-Forwarded-For";
    private static final String UNKNOWN = "unknown";
    private static final Pattern IP_LIKE = Pattern.compile("[0-9A-Fa-f:.]{2,45}");

    private final TrustedProxies trustedProxies;

    public ClientIpResolver(GatewayProperties gatewayProperties) {
        String pattern = gatewayProperties.getTrustedProxies();
        this.trustedProxies = StringUtils.hasText(pattern) ? TrustedProxies.from(pattern) : null;
    }

    public String resolve(ServerWebExchange exchange) {
        String remote = remoteAddress(exchange);
        return forwarded(exchange, remote).orElse(remote);
    }

    private Optional<String> forwarded(ServerWebExchange exchange, String remote) {
        if (trustedProxies == null || UNKNOWN.equals(remote) || !trustedProxies.isTrusted(remote)) {
            return Optional.empty();
        }
        String header = exchange.getRequest().getHeaders().getFirst(X_FORWARDED_FOR);
        if (!StringUtils.hasText(header)) {
            return Optional.empty();
        }
        String first = header.split(",")[0].trim();
        return IP_LIKE.matcher(first).matches() ? Optional.of(first) : Optional.empty();
    }

    private static String remoteAddress(ServerWebExchange exchange) {
        InetSocketAddress remote = exchange.getRequest().getRemoteAddress();
        if (remote == null || remote.getAddress() == null) {
            return UNKNOWN;
        }
        return remote.getAddress().getHostAddress();
    }
}
