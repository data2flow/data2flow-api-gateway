package net.java21.data2flow.gateway.web;

import net.java21.data2flow.contracts.error.CommonErrorCode;
import net.java21.data2flow.gateway.auth.BearerToken;
import net.java21.data2flow.gateway.auth.PublicPaths;
import net.java21.data2flow.gateway.config.GatewayProperties;
import net.java21.data2flow.gateway.ratelimit.ClientIpResolver;
import net.java21.data2flow.gateway.ratelimit.IpRateLimitPolicy;
import net.java21.data2flow.gateway.ratelimit.RateLimiter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Optional;

/**
 * ② RateLimit(IP) — 인증 전에 사용자 IP로 센다(auth.md §1·§5, IAM-07.07, OPS-12.05).
 *
 * <ul>
 *   <li>공개 경로: 경로별 정책(로그인 IP당 분당 20회 등)의 토큰 버킷. 넘으면 429 + Retry-After·X-RateLimit-*</li>
 *   <li>토큰을 단 보호 경로: 그 IP의 무효 토큰 시도 수가 한도에 이르렀으면 429 {@code AUTH_RATE_LIMITED}("실패 시도" 한도)</li>
 * </ul>
 * 한도를 넘으면 경고 로그로 남긴다(IAM-07.07 "기록한다"). 저장소 장애면 검사를 건너뛴다.
 */
@Component
public class IpRateLimitGlobalFilter implements GlobalFilter, Ordered {

    public static final int ORDER = -200;
    private static final Logger log = LoggerFactory.getLogger(IpRateLimitGlobalFilter.class);

    private final ClientIpResolver clientIpResolver;
    private final PublicPaths publicPaths;
    private final RateLimiter rateLimiter;
    private final GatewayProperties.RateLimit settings;

    public IpRateLimitGlobalFilter(ClientIpResolver clientIpResolver, PublicPaths publicPaths, RateLimiter rateLimiter,
                                   GatewayProperties properties) {
        this.clientIpResolver = clientIpResolver;
        this.publicPaths = publicPaths;
        this.rateLimiter = rateLimiter;
        this.settings = properties.rateLimit();
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String clientIp = clientIpResolver.resolve(exchange);
        exchange.getAttributes().put(GatewayAttributes.CLIENT_IP, clientIp);
        if (!settings.enabled()) {
            return chain.filter(exchange);
        }
        ServerHttpRequest request = exchange.getRequest();
        Optional<IpRateLimitPolicy> policy = publicPaths.match(request.getMethod(), request.getPath().value());
        if (policy.isPresent()) {
            IpRateLimitPolicy p = policy.get();
            return rateLimiter.consume(p.bucket(clientIp), p.limit(settings))
                    .flatMap(decision -> {
                        if (!decision.allowed()) {
                            logExceeded(exchange, p.name());
                            return Mono.error(decision.rejection(p.errorCode()));
                        }
                        GatewayAttributes.putResponseHeaders(exchange, decision.headers());
                        return chain.filter(exchange);
                    });
        }
        if (BearerToken.from(request).isEmpty()) {
            return chain.filter(exchange);
        }
        return rateLimiter.checkFailures(failedAuthBucket(clientIp), settings.failedAuth())
                .flatMap(decision -> {
                    if (!decision.allowed()) {
                        logExceeded(exchange, "FAILED_AUTH");
                        return Mono.error(decision.rejection(CommonErrorCode.AUTH_RATE_LIMITED));
                    }
                    return chain.filter(exchange);
                });
    }

    /** 무효 토큰 시도 버킷 이름 */
    public static String failedAuthBucket(String clientIp) {
        return "failed-auth:ip:" + clientIp;
    }

    private static void logExceeded(ServerWebExchange exchange, String policy) {
        log.atWarn().addKeyValue("requestId", CorrelationIdWebFilter.requestId(exchange))
                .addKeyValue("rateLimitPolicy", policy)
                .log("호출 한도 초과: {} {}", exchange.getRequest().getMethod(),
                        AccessLogWebFilter.maskPath(exchange.getRequest().getPath().value()));
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}
