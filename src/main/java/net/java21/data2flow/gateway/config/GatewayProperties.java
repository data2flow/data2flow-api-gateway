package net.java21.data2flow.gateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.util.Objects;

/**
 * {@code data2flow.gateway.*} 정책 설정(design/auth.md §2·§4.2·§5). 값은 application*.yml에 두고, 주소는 환경변수로 바꾼다.
 *
 * @param services              라우트 대상 서비스 주소(k8s Service 이름, ADR-013·017)
 * @param mcpHost               MCP 외부 호스트. 이 호스트에서는 {@code /mcp/**}만 받는다. 비우면(local) 경로로만 가른다
 * @param mcpResponseTimeout    MCP 라우트 응답 타임아웃(기본 300초, 스트리밍 응답 대비)
 * @param unavailableRetryAfter 503 응답의 Retry-After(초 단위로 내림)
 * @param introspection         인증 서비스 토큰 조회 설정
 * @param revocation            폐기 목록(블랙리스트)·폐기 이벤트 설정
 * @param rateLimit             호출 한도 설정
 */
@ConfigurationProperties(prefix = "data2flow.gateway")
public record GatewayProperties(
        Services services,
        String mcpHost,
        Duration mcpResponseTimeout,
        Duration unavailableRetryAfter,
        Introspection introspection,
        Revocation revocation,
        RateLimit rateLimit
) {

    /** IAM-07.10: 검증 결과 캐시는 30초를 넘지 않는다 */
    public static final Duration CACHE_TTL_CEILING = Duration.ofSeconds(30);

    public GatewayProperties {
        Objects.requireNonNull(services, "data2flow.gateway.services");
        introspection = introspection == null ? new Introspection(null, null, null, null, 0) : introspection;
        revocation = revocation == null ? new Revocation(null, null, null) : revocation;
        rateLimit = rateLimit == null
                ? new RateLimit(true, null, null, null, null, null, null, null, null, null) : rateLimit;
        mcpHost = StringUtils.hasText(mcpHost) ? mcpHost.trim() : null;
        mcpResponseTimeout = mcpResponseTimeout == null ? Duration.ofSeconds(300) : mcpResponseTimeout;
        unavailableRetryAfter = unavailableRetryAfter == null ? Duration.ofSeconds(5) : unavailableRetryAfter;
    }

    /**
     * @param auth 인증 서비스(토큰 조회도 여기로 간다)
     * @param core core-api
     * @param ai   ai(일반 API)
     * @param mcp  MCP 엔드포인트를 가진 서비스(기본은 ai)
     */
    public record Services(String auth, String core, String ai, String mcp) {
    }

    /**
     * @param path           인증 서비스의 토큰 조회 경로(API-IAM-34)
     * @param connectTimeout 연결 타임아웃(auth.md §5: 1초)
     * @param responseTimeout 응답 타임아웃(auth.md §5: 2초)
     * @param cacheTtl       검증 결과 캐시 수명. 30초를 넘으면 30초로 줄인다
     * @param cacheMaxEntries 캐시 최대 항목 수(넘으면 만료분을 지우고, 그래도 넘으면 비운다)
     */
    public record Introspection(String path, Duration connectTimeout, Duration responseTimeout,
                                Duration cacheTtl, int cacheMaxEntries) {

        public Introspection {
            path = StringUtils.hasText(path) ? path : "/internal/auth/introspect";
            connectTimeout = connectTimeout == null ? Duration.ofSeconds(1) : connectTimeout;
            responseTimeout = responseTimeout == null ? Duration.ofSeconds(2) : responseTimeout;
            if (cacheTtl == null || cacheTtl.compareTo(CACHE_TTL_CEILING) > 0) {
                cacheTtl = CACHE_TTL_CEILING;
            }
            cacheMaxEntries = cacheMaxEntries <= 0 ? 100_000 : cacheMaxEntries;
        }
    }

    /**
     * @param keyPrefix   폐기 목록 키 접두사. 실제 키는 {@code <prefix>at:{jti}}, {@code <prefix>sid:{sid}}(auth.md §4.2)
     * @param channel     폐기 이벤트 Redis Pub/Sub 채널(EVT-IAM-03)
     * @param timeout     폐기 목록 조회 타임아웃. 넘으면 장애로 보고 503(fail-closed)
     */
    public record Revocation(String keyPrefix, String channel, Duration timeout) {

        public Revocation {
            keyPrefix = StringUtils.hasText(keyPrefix) ? keyPrefix : "data2flow:bl:";
            channel = StringUtils.hasText(channel) ? channel : "data2flow:auth.revocations";
            timeout = timeout == null ? Duration.ofSeconds(1) : timeout;
        }
    }

    /**
     * 정책별 한도. 모두 "창(window) 안 허용 수"로 적고, 토큰 버킷(용량 = limit, 창 동안 limit개 충전)으로 센다.
     *
     * @param enabled    끄면 한도를 보지 않는다(테스트·장애 대응용)
     * @param keyPrefix  Redis 키 접두사({@code data2flow:} 아래, ADR-022)
     * @param timeout    Redis 응답 타임아웃. 넘으면 한도 검사를 건너뛴다(fail-open, 인증은 별도로 fail-closed)
     * @param login      로그인·2단계 인증: IP당(BR-IAM-23, 분당 20회)
     * @param refresh    재발급·로그아웃: IP당(sid당 한도는 auth가 센다)
     * @param account    초대·비밀번호 재설정·가입 신청 등 공개 계정 API: IP당
     * @param publicApi  익명 공개 화면 API({@code /api/v1/core/public/**}): IP당
     * @param failedAuth 무효 토큰 시도: IP당 고정 창. 넘으면 그 IP의 토큰 요청을 막는다(IAM-07.07 "실패 시도")
     * @param user       로그인 사용자: userId당
     * @param apiToken   장기 토큰(MCP·API 키): 토큰 ID당. 토큰 조회 결과에 rateLimitPerMin이 있으면 그 값을 쓴다
     */
    public record RateLimit(boolean enabled, String keyPrefix, Duration timeout,
                            Limit login, Limit refresh, Limit account, Limit publicApi,
                            Limit failedAuth, Limit user, Limit apiToken) {

        public RateLimit {
            keyPrefix = StringUtils.hasText(keyPrefix) ? keyPrefix : "data2flow:gw:rl:";
            timeout = timeout == null ? Duration.ofMillis(500) : timeout;
            login = login == null ? new Limit(20, Duration.ofMinutes(1)) : login;
            refresh = refresh == null ? new Limit(60, Duration.ofMinutes(1)) : refresh;
            account = account == null ? new Limit(20, Duration.ofMinutes(1)) : account;
            publicApi = publicApi == null ? new Limit(120, Duration.ofMinutes(1)) : publicApi;
            failedAuth = failedAuth == null ? new Limit(20, Duration.ofMinutes(1)) : failedAuth;
            user = user == null ? new Limit(1200, Duration.ofMinutes(1)) : user;
            apiToken = apiToken == null ? new Limit(600, Duration.ofMinutes(1)) : apiToken;
        }
    }

    /** 창 안 허용 수와 창 길이 */
    public record Limit(long limit, Duration window) {

        public Limit {
            if (limit <= 0) {
                throw new IllegalArgumentException("limit은 1 이상이어야 합니다");
            }
            window = window == null ? Duration.ofMinutes(1) : window;
        }
    }
}
