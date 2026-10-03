package net.java21.data2flow.gateway.config;

import net.java21.data2flow.gateway.web.GatewayAttributes;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.BooleanSpec;
import org.springframework.cloud.gateway.route.builder.PredicateSpec;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.cloud.gateway.support.RouteMetadataUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 라우트(auth.md §2, api-rules §2). 외부 {@code /api/v1/{service}/**} → {@code stripPrefix(2)} → {@code http://data2flow-<svc>/{service}/**}.
 *
 * <ul>
 *   <li>auth: 로그인·2단계 인증·재발급·로그아웃 4개 경로만 연다. 그 밖의 {@code /api/v1/auth/**}(oauth2, signup, sso 등)는
 *       라우트가 없어 404(IAM-07.11, ADR-016·028)</li>
 *   <li>core-stream: {@code /api/v1/core/stream/**} SSE·WebSocket. 응답 시간 제한 없음(장시간 연결), core 라우트보다 먼저 본다</li>
 *   <li>core, ai: 공통 응답 시간 제한 10초({@code spring.cloud.gateway.server.webflux.httpclient.response-timeout})</li>
 *   <li>mcp: MCP 호스트의 {@code /mcp}, {@code /mcp/**}만, 접두사 유지, 응답 시간 제한 300초. MCP 호스트에서는 다른 라우트가 맞지 않아 404</li>
 * </ul>
 * catch-all 라우트는 없다. 정의되지 않은 경로는 404 {@code RESOURCE_NOT_FOUND}(GatewayErrorWebExceptionHandler).
 * 조직 생성처럼 v1에 없는 경로({@code POST /api/v1/core/organizations}, ADR-004)는 PathGuardWebFilter가 인증보다 먼저 404로 막는다(TC-IAM-050).
 */
@Configuration
public class RouteConfig {

    static final String[] AUTH_PATHS = {
            "/api/v1/auth/login", "/api/v1/auth/login/mfa", "/api/v1/auth/refresh-token", "/api/v1/auth/logout"};

    @Bean
    public RouteLocator data2flowRoutes(RouteLocatorBuilder builder, GatewayProperties properties) {
        GatewayProperties.Services services = properties.services();
        String mcpHost = properties.mcpHost();
        return builder.routes()
                .route(GatewayAttributes.ROUTE_AUTH, spec -> api(spec, mcpHost, AUTH_PATHS)
                        .filters(f -> f.stripPrefix(2))
                        .uri(services.auth()))
                .route(GatewayAttributes.ROUTE_CORE_STREAM, spec -> api(spec.order(-1), mcpHost, "/api/v1/core/stream/**")
                        .filters(f -> f.stripPrefix(2))
                        .metadata(RouteMetadataUtils.RESPONSE_TIMEOUT_ATTR, -1L)
                        .uri(services.core()))
                .route(GatewayAttributes.ROUTE_CORE, spec -> api(spec, mcpHost, "/api/v1/core/**")
                        .filters(f -> f.stripPrefix(2))
                        .uri(services.core()))
                .route(GatewayAttributes.ROUTE_AI, spec -> api(spec, mcpHost, "/api/v1/ai/**")
                        .filters(f -> f.stripPrefix(2))
                        .uri(services.ai()))
                .route(GatewayAttributes.ROUTE_MCP, spec -> mcp(spec, mcpHost)
                        .metadata(RouteMetadataUtils.RESPONSE_TIMEOUT_ATTR, properties.mcpResponseTimeout().toMillis())
                        .uri(services.mcp()))
                .build();
    }

    /** 사용자 API: MCP 호스트로 들어온 요청은 받지 않는다(MCP 호스트가 API 전체의 또 다른 입구가 되지 않게) */
    private static BooleanSpec api(PredicateSpec spec, String mcpHost, String... paths) {
        BooleanSpec path = spec.path(paths);
        return mcpHost == null ? path : path.and().not(p -> p.host(mcpHost, mcpHost + ":*"));
    }

    /** MCP: MCP 호스트의 /mcp, /mcp/**. 호스트가 설정되지 않았으면(local) 경로만 본다 */
    private static BooleanSpec mcp(PredicateSpec spec, String mcpHost) {
        BooleanSpec path = spec.path("/mcp", "/mcp/**");
        return mcpHost == null ? path : path.and().host(mcpHost, mcpHost + ":*");
    }
}
