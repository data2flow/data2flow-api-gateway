package net.java21.data2flow.gateway.web;

import net.java21.data2flow.contracts.error.CommonErrorCode;
import net.java21.data2flow.contracts.identity.DataflowHeaders;
import net.java21.data2flow.gateway.auth.BearerToken;
import net.java21.data2flow.gateway.auth.IdentityHeaders;
import net.java21.data2flow.gateway.auth.IntrospectionClient;
import net.java21.data2flow.gateway.auth.IntrospectionResult;
import net.java21.data2flow.gateway.auth.Principal;
import net.java21.data2flow.gateway.auth.PublicPaths;
import net.java21.data2flow.gateway.auth.RevocationStore;
import net.java21.data2flow.gateway.auth.TokenValidationCache;
import net.java21.data2flow.gateway.config.GatewayProperties;
import net.java21.data2flow.gateway.error.GatewayRejectedException;
import net.java21.data2flow.gateway.ratelimit.RateLimiter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * ③ Authentication(introspection) — IAM-07.02, IAM-07.09, IAM-07.10, BR-IAM-37, auth.md §5.
 *
 * <ol>
 *   <li>외부 요청의 신원 헤더({@code X-USER-ID}, {@code X-ORG-ID}, {@code X-SESSION-ID}, {@code X-ACCESS-TOKEN-ID}, {@code X-TOKEN-*},
 *       {@code X-INTERNAL-*}, {@code X-CALLER-SERVICE})를 <b>항상 먼저</b> 지우고, {@code X-CALLER-SERVICE: data2flow-api-gateway}를 단다</li>
 *   <li>공개 경로면 신원 없이 통과</li>
 *   <li>Bearer가 없으면 401 {@code AUTH_TOKEN_INVALID} + {@code WWW-Authenticate: Bearer}</li>
 *   <li>캐시(키 SHA-256(token), 수명 ≤ 30초) 적중이면 폐기 목록을 MGET 1회로 다시 확인 → 폐기면 401 {@code AUTH_SESSION_REVOKED}</li>
 *   <li>캐시에 없으면 인증 서비스에 조회 → 비활성은 사유별 401(EXPIRED·REVOKED·INVALID), 장애는 503(fail-closed)</li>
 *   <li>장기 토큰은 MCP 라우트에서만, 웹 Access 토큰은 MCP 밖에서만 → 어긋나면 403 {@code PERMISSION_DENIED}</li>
 *   <li>성공이면 {@code X-USER-ID}, {@code X-ORG-ID}를 넣는다. 웹 Access 토큰이면 로그인 세션 {@code X-SESSION-ID}(introspection
 *       {@code sid})를, 장기 토큰이면 {@code X-ACCESS-TOKEN-ID}, {@code X-TOKEN-SCOPE}를 더한다</li>
 * </ol>
 * 무효 토큰(INVALID)은 IP별 실패 시도로 센다(IAM-07.07). 하위 서비스에는 Authorization을 넘기지 않는다(auth 라우트 제외):
 * 하위 서비스는 토큰이 아니라 신원 헤더를 믿는다(ADR-021).
 */
@Component
public class AuthenticationGlobalFilter implements GlobalFilter, Ordered {

    public static final int ORDER = -100;

    private final PublicPaths publicPaths;
    private final TokenValidationCache cache;
    private final IntrospectionClient introspectionClient;
    private final RevocationStore revocationStore;
    private final RateLimiter rateLimiter;
    private final GatewayProperties properties;

    public AuthenticationGlobalFilter(PublicPaths publicPaths, TokenValidationCache cache,
                                      IntrospectionClient introspectionClient, RevocationStore revocationStore,
                                      RateLimiter rateLimiter, GatewayProperties properties) {
        this.publicPaths = publicPaths;
        this.cache = cache;
        this.introspectionClient = introspectionClient;
        this.revocationStore = revocationStore;
        this.rateLimiter = rateLimiter;
        this.properties = properties;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest original = exchange.getRequest();
        String routeId = GatewayAttributes.routeId(exchange);
        boolean authRoute = GatewayAttributes.ROUTE_AUTH.equals(routeId);
        ServerHttpRequest.Builder builder = original.mutate().headers(headers -> {
            stripIdentityHeaders(headers);
            headers.set(DataflowHeaders.CALLER_SERVICE, IdentityHeaders.CALLER);
            if (!authRoute) {
                headers.remove(HttpHeaders.AUTHORIZATION);
            }
        });

        if (publicPaths.isPublic(original.getMethod(), original.getPath().value())) {
            return chain.filter(exchange.mutate().request(builder.build()).build());
        }

        Optional<String> token = BearerToken.from(original);
        if (token.isEmpty()) {
            return Mono.error(GatewayRejectedException.unauthorized(CommonErrorCode.AUTH_TOKEN_INVALID,
                    GatewayRejectedException.BEARER_CHALLENGE));
        }

        String key = TokenValidationCache.keyOf(token.get());
        Optional<Principal> cached = cache.find(key);
        Mono<Principal> principal = cached.isPresent()
                ? recheckRevocation(key, cached.get())
                : introspect(exchange, key, token.get());
        return principal.flatMap(p -> proceed(exchange, chain, builder, routeId, p));
    }

    /** 캐시에 있던 신원도 폐기 목록을 다시 본다(이벤트를 놓쳐도 바로 거부, 저장소 장애면 503) */
    private Mono<Principal> recheckRevocation(String key, Principal principal) {
        return revocationStore.isRevoked(principal).flatMap(revoked -> {
            if (revoked) {
                cache.evict(key);
                return Mono.error(GatewayRejectedException.unauthorized(CommonErrorCode.AUTH_SESSION_REVOKED,
                        GatewayRejectedException.INVALID_TOKEN_CHALLENGE));
            }
            return Mono.just(principal);
        });
    }

    private Mono<Principal> introspect(ServerWebExchange exchange, String key, String token) {
        return introspectionClient.introspect(token, CorrelationIdWebFilter.requestId(exchange))
                .flatMap(result -> {
                    if (result.active()) {
                        cache.put(key, result.principal());
                        return Mono.just(result.principal());
                    }
                    return Mono.error(inactive(result.inactiveReason()));
                })
                .onErrorResume(GatewayRejectedException.class, ex -> isInvalid(ex)
                        ? recordFailure(exchange).then(Mono.error(ex))
                        : Mono.error(ex));
    }

    private static GatewayRejectedException inactive(IntrospectionResult.InactiveReason reason) {
        CommonErrorCode code = switch (reason) {
            case EXPIRED -> CommonErrorCode.AUTH_TOKEN_EXPIRED;
            case REVOKED -> CommonErrorCode.AUTH_SESSION_REVOKED;
            case INVALID -> CommonErrorCode.AUTH_TOKEN_INVALID;
        };
        return GatewayRejectedException.unauthorized(code, GatewayRejectedException.INVALID_TOKEN_CHALLENGE);
    }

    private static boolean isInvalid(GatewayRejectedException ex) {
        return ex.code() == CommonErrorCode.AUTH_TOKEN_INVALID;
    }

    private Mono<Void> recordFailure(ServerWebExchange exchange) {
        String clientIp = GatewayAttributes.clientIp(exchange);
        if (clientIp == null || !properties.rateLimit().enabled()) {
            return Mono.empty();
        }
        return rateLimiter.recordFailure(IpRateLimitGlobalFilter.failedAuthBucket(clientIp),
                properties.rateLimit().failedAuth());
    }

    private Mono<Void> proceed(ServerWebExchange exchange, GatewayFilterChain chain, ServerHttpRequest.Builder builder,
                               String routeId, Principal principal) {
        boolean mcpRoute = GatewayAttributes.ROUTE_MCP.equals(routeId);
        if (principal.longLived() != mcpRoute) {
            return Mono.error(GatewayRejectedException.of(CommonErrorCode.PERMISSION_DENIED));
        }
        builder.headers(headers -> {
            headers.set(DataflowHeaders.USER_ID, principal.userId());
            headers.set(DataflowHeaders.ORG_ID, principal.orgId());
            if (!principal.longLived() && principal.sid() != null) {
                headers.set(DataflowHeaders.SESSION_ID, principal.sid());
            }
            if (principal.longLived()) {
                headers.set(DataflowHeaders.ACCESS_TOKEN_ID, principal.tokenId());
                if (!principal.scopes().isEmpty()) {
                    headers.set(DataflowHeaders.TOKEN_SCOPE, String.join(",", principal.scopes()));
                }
            }
        });
        exchange.getAttributes().put(GatewayAttributes.PRINCIPAL, principal);
        return chain.filter(exchange.mutate().request(builder.build()).build());
    }

    /** gateway만 넣을 수 있는 헤더를 모두 지운다(대소문자 무시, BR-IAM-37) */
    static void stripIdentityHeaders(HttpHeaders headers) {
        List<String> owned = new ArrayList<>();
        for (String name : headers.headerNames()) {
            if (DataflowHeaders.isGatewayOwned(name)) {
                owned.add(name);
            }
        }
        owned.forEach(headers::remove);
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}
