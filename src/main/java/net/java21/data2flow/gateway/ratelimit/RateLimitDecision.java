package net.java21.data2flow.gateway.ratelimit;

import net.java21.data2flow.contracts.error.ErrorCode;
import net.java21.data2flow.contracts.ratelimit.RateLimitHeaders;
import net.java21.data2flow.contracts.ratelimit.RateLimitInfo;
import net.java21.data2flow.gateway.error.GatewayRejectedException;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 한도 검사 한 번의 결과(OPS-12.05, BR-OPS-22).
 *
 * @param allowed           이번 요청을 받아도 되는가
 * @param limit             창 안 허용 수({@code X-RateLimit-Limit})
 * @param remaining         남은 수({@code X-RateLimit-Remaining})
 * @param resetSeconds      다시 가득 찰 때까지 남은 초({@code X-RateLimit-Reset})
 * @param retryAfterSeconds 거절일 때 다시 시도해도 되는 초({@code Retry-After}, 최소 1)
 */
public record RateLimitDecision(boolean allowed, long limit, long remaining, long resetSeconds, long retryAfterSeconds) {

    public RateLimitDecision {
        remaining = Math.max(0, remaining);
        resetSeconds = Math.max(0, resetSeconds);
        retryAfterSeconds = allowed ? 0 : Math.max(1, retryAfterSeconds);
    }

    /** Redis를 쓸 수 없어 검사를 건너뛴 결과(fail-open). 헤더는 붙이지 않는다 */
    public static RateLimitDecision skipped() {
        return new RateLimitDecision(true, -1, 0, 0, 0);
    }

    public boolean isSkipped() {
        return limit < 0;
    }

    /** 정상 응답에도 붙이는 남은 한도 헤더 */
    public Map<String, String> headers() {
        if (isSkipped()) {
            return new LinkedHashMap<>();
        }
        return new LinkedHashMap<>(new RateLimitInfo(limit, remaining, resetSeconds).headers());
    }

    /** 429 거절: 남은 한도 헤더 + Retry-After, 문구의 {0}은 Retry-After 초 */
    public GatewayRejectedException rejection(ErrorCode code) {
        Map<String, String> headers = headers();
        headers.put(RateLimitHeaders.RETRY_AFTER, Long.toString(retryAfterSeconds));
        return new GatewayRejectedException(code, headers, retryAfterSeconds);
    }
}
