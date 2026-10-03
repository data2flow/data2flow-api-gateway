package net.java21.data2flow.gateway.auth;

import net.java21.data2flow.gateway.ratelimit.IpRateLimitPolicy;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.PathContainer;
import org.springframework.stereotype.Component;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;

import java.util.List;
import java.util.Optional;

/**
 * 토큰 없이 통과하는 공개 경로(auth.md §3.3, design/api/IAM-api.md "공개", DSH-api 공유 대시보드, OPS-api 릴리스 노트).
 * gateway가 스스로 정하지 않고 문서의 공개 표시만 옮긴다. 판정은 (메서드, 외부 경로) 쌍이고 stripPrefix 전 경로 기준이다.
 * 같은 경로라도 다른 메서드는 공개가 아니다(기본 거부).
 *
 * <p>기업 SSO({@code /api/v1/auth/sso/**})와 소셜 로그인({@code /api/v1/auth/oauth2/**})은 범위 밖이라 없다(ADR-016, ADR-028).
 * 공개 경로에 토큰이 붙어 와도 검증하지 않고 신원 헤더 없이 넘긴다(위조 헤더는 이미 지움).
 */
@Component
public class PublicPaths {

    private static final PathPatternParser PARSER = PathPatternParser.defaultInstance;

    private static final List<Entry> ENTRIES = List.of(
            // auth (API-IAM-01·62·02·03)
            entry(HttpMethod.POST, "/api/v1/auth/login", IpRateLimitPolicy.LOGIN),
            entry(HttpMethod.POST, "/api/v1/auth/login/mfa", IpRateLimitPolicy.LOGIN),
            entry(HttpMethod.POST, "/api/v1/auth/refresh-token", IpRateLimitPolicy.REFRESH),
            entry(HttpMethod.POST, "/api/v1/auth/logout", IpRateLimitPolicy.REFRESH),
            // core 계정 (API-IAM-10·10a·11·13·14·67·68)
            entry(HttpMethod.GET, "/api/v1/core/invitations/{token}", IpRateLimitPolicy.ACCOUNT),
            entry(HttpMethod.GET, "/api/v1/core/invitations/{token}/login-id-availability", IpRateLimitPolicy.ACCOUNT),
            entry(HttpMethod.POST, "/api/v1/core/invitations/{token}/accept", IpRateLimitPolicy.ACCOUNT),
            entry(HttpMethod.POST, "/api/v1/core/password-resets", IpRateLimitPolicy.ACCOUNT),
            entry(HttpMethod.POST, "/api/v1/core/password-resets/{token}/confirm", IpRateLimitPolicy.ACCOUNT),
            entry(HttpMethod.POST, "/api/v1/core/signup-requests", IpRateLimitPolicy.ACCOUNT),
            entry(HttpMethod.POST, "/api/v1/core/signup-requests/{token}/verify", IpRateLimitPolicy.ACCOUNT),
            // core 익명 공개 화면 (auth.md §3.3, API-OPS-98·101, DSH-api 공유 대시보드 위젯 데이터)
            entry(HttpMethod.GET, "/api/v1/core/public/**", IpRateLimitPolicy.PUBLIC_API),
            entry(HttpMethod.POST, "/api/v1/core/public/share/{share-token}/widgets/{widget-id}/data",
                    IpRateLimitPolicy.PUBLIC_API)
    );

    /** 공개 경로면 그 경로의 IP 한도 정책 */
    public Optional<IpRateLimitPolicy> match(HttpMethod method, String path) {
        PathContainer container = PathContainer.parsePath(path);
        return ENTRIES.stream()
                .filter(e -> e.method().equals(method) && e.pattern().matches(container))
                .map(Entry::policy)
                .findFirst();
    }

    public boolean isPublic(HttpMethod method, String path) {
        return match(method, path).isPresent();
    }

    private static Entry entry(HttpMethod method, String pattern, IpRateLimitPolicy policy) {
        return new Entry(method, PARSER.parse(pattern), policy);
    }

    private record Entry(HttpMethod method, PathPattern pattern, IpRateLimitPolicy policy) {
    }
}
