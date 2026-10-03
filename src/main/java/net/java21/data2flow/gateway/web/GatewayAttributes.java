package net.java21.data2flow.gateway.web;

import net.java21.data2flow.gateway.auth.Principal;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.web.server.ServerWebExchange;

import java.util.Map;

/** 필터 사이에 넘기는 요청 속성과 라우트 ID */
public final class GatewayAttributes {

    public static final String CLIENT_IP = GatewayAttributes.class.getName() + ".clientIp";
    public static final String PRINCIPAL = GatewayAttributes.class.getName() + ".principal";

    public static final String ROUTE_AUTH = "auth";
    public static final String ROUTE_CORE = "core";
    public static final String ROUTE_CORE_STREAM = "core-stream";
    public static final String ROUTE_AI = "ai";
    public static final String ROUTE_MCP = "mcp";

    private GatewayAttributes() {
    }

    public static String routeId(ServerWebExchange exchange) {
        Route route = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
        return route == null ? null : route.getId();
    }

    public static Principal principal(ServerWebExchange exchange) {
        return exchange.getAttribute(PRINCIPAL);
    }

    public static String clientIp(ServerWebExchange exchange) {
        return exchange.getAttribute(CLIENT_IP);
    }

    /** 정상 응답에도 남은 한도 헤더를 붙인다(OPS-12.05). 나중 단계(④)가 앞 단계(②) 값을 덮어쓴다 */
    public static void putResponseHeaders(ServerWebExchange exchange, Map<String, String> headers) {
        headers.forEach(exchange.getResponse().getHeaders()::set);
    }
}
