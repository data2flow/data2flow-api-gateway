package net.java21.data2flow.gateway.web;

import net.java21.data2flow.contracts.error.CommonErrorCode;
import net.java21.data2flow.gateway.error.GatewayRejectedException;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Locale;

/**
 * 경로 정규화 차이를 이용한 우회를 막는다. gateway는 외부 경로로 공개 여부를 판정하는데
 * ({@code /api/v1/core/public/..%2f..%2fdevices}처럼) 하위 서비스가 경로를 다르게 해석하면 인증 없이 보호 경로에 닿을 수 있다.
 * 점 구간({@code .}·{@code ..}), 인코딩된 점·슬래시·역슬래시, 경로 매개변수({@code ;}), 빈 구간({@code //})이 있으면 400으로 거절한다.
 * v1에서 제공하지 않는 경로도 인증보다 먼저 404로 막는다.
 */
@Component
public class PathGuardWebFilter implements WebFilter, Ordered {

    public static final int ORDER = AccessLogWebFilter.ORDER + 1;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String rawPath = exchange.getRequest().getURI().getRawPath();
        if (isSuspicious(rawPath)) {
            return Mono.error(GatewayRejectedException.of(CommonErrorCode.INVALID_REQUEST));
        }
        if (isNotOffered(exchange.getRequest().getMethod(), exchange.getRequest().getPath().value())) {
            return Mono.error(GatewayRejectedException.of(CommonErrorCode.RESOURCE_NOT_FOUND));
        }
        return chain.filter(exchange);
    }

    /**
     * v1에서 제공하지 않는 경로. 로그인 여부와 관계없이 404(TC-IAM-050): 단일 조직이라 조직 생성(셀프 가입) 경로가 없다(ADR-004).
     * {@code /api/v1/auth/**}의 signup·oauth2·sso는 auth 라우트가 4개 경로만 열어서 따로 막지 않아도 404다.
     */
    static boolean isNotOffered(HttpMethod method, String path) {
        return HttpMethod.POST.equals(method) && "/api/v1/core/organizations".equals(path);
    }

    static boolean isSuspicious(String rawPath) {
        if (rawPath == null || rawPath.isEmpty()) {
            return false;
        }
        String lower = rawPath.toLowerCase(Locale.ROOT);
        if (lower.contains("%2e") || lower.contains("%2f") || lower.contains("%5c") || lower.contains("%25")
                || lower.contains("\\") || lower.contains(";") || lower.contains("//")) {
            return true;
        }
        for (String segment : lower.split("/")) {
            if (segment.equals(".") || segment.equals("..")) {
                return true;
            }
        }
        return false;
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}
