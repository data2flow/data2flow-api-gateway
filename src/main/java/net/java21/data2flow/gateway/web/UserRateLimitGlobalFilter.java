package net.java21.data2flow.gateway.web;

import net.java21.data2flow.contracts.error.CommonErrorCode;
import net.java21.data2flow.gateway.auth.Principal;
import net.java21.data2flow.gateway.config.GatewayProperties;
import net.java21.data2flow.gateway.config.GatewayProperties.Limit;
import net.java21.data2flow.gateway.ratelimit.RateLimiter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * ④ RateLimit(userId·토큰) — 인증 뒤 사용자(장기 토큰은 토큰 ID)별 토큰 버킷(auth.md §5 [보강], OPS-12.05).
 * 장기 토큰은 토큰 조회 결과의 {@code rateLimitPerMin}(IAM-05.04)이 있으면 그 분당 한도를 쓴다.
 * 넘으면 429 {@code RATE_LIMITED} + Retry-After·X-RateLimit-*.
 */
@Component
public class UserRateLimitGlobalFilter implements GlobalFilter, Ordered {

    public static final int ORDER = AuthenticationGlobalFilter.ORDER + 10;
    private static final Logger log = LoggerFactory.getLogger(UserRateLimitGlobalFilter.class);

    private final RateLimiter rateLimiter;
    private final GatewayProperties.RateLimit settings;

    public UserRateLimitGlobalFilter(RateLimiter rateLimiter, GatewayProperties properties) {
        this.rateLimiter = rateLimiter;
        this.settings = properties.rateLimit();
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        Principal principal = GatewayAttributes.principal(exchange);
        if (principal == null || !settings.enabled()) {
            return chain.filter(exchange);
        }
        String bucket = principal.longLived() ? "token:" + principal.tokenId() : "user:" + principal.userId();
        return rateLimiter.consume(bucket, limitFor(principal))
                .flatMap(decision -> {
                    if (!decision.allowed()) {
                        log.atWarn().addKeyValue("requestId", CorrelationIdWebFilter.requestId(exchange))
                                .addKeyValue("userId", principal.userId())
                                .addKeyValue("rateLimitPolicy", principal.longLived() ? "API_TOKEN" : "USER")
                                .log("호출 한도 초과");
                        return Mono.error(decision.rejection(CommonErrorCode.RATE_LIMITED));
                    }
                    GatewayAttributes.putResponseHeaders(exchange, decision.headers());
                    return chain.filter(exchange);
                });
    }

    Limit limitFor(Principal principal) {
        if (!principal.longLived()) {
            return settings.user();
        }
        Long perMinute = principal.rateLimitPerMin();
        return perMinute != null && perMinute > 0
                ? new Limit(perMinute, java.time.Duration.ofMinutes(1))
                : settings.apiToken();
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}
