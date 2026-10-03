package net.java21.data2flow.gateway.error;

import net.java21.data2flow.contracts.error.CommonErrorCode;
import net.java21.data2flow.contracts.error.ErrorCode;
import org.springframework.http.HttpHeaders;

import java.time.Duration;
import java.util.Map;

/**
 * 필터가 요청을 거절할 때 {@code Mono.error}로 보내는 신호. {@link GatewayErrorWebExceptionHandler}가
 * 상태 코드, 공통 실패 본문, 덧붙일 응답 헤더(WWW-Authenticate, Retry-After, X-RateLimit-*)로 바꾼다.
 */
public class GatewayRejectedException extends RuntimeException {

    /** 토큰이 없을 때의 401 챌린지(RFC 6750) */
    public static final String BEARER_CHALLENGE = "Bearer";
    /** 토큰이 무효·만료·폐기일 때의 401 챌린지(api-rules §4.2) */
    public static final String INVALID_TOKEN_CHALLENGE = "Bearer error=\"invalid_token\"";

    private final transient ErrorCode code;
    private final transient Map<String, String> headers;
    private final transient Object[] messageArgs;

    public GatewayRejectedException(ErrorCode code, Map<String, String> headers, Object... messageArgs) {
        super(code.code());
        this.code = code;
        this.headers = Map.copyOf(headers);
        this.messageArgs = messageArgs.clone();
    }

    public static GatewayRejectedException of(ErrorCode code) {
        return new GatewayRejectedException(code, Map.of());
    }

    /** 401: 토큰 없음은 {@code Bearer}, 그 밖은 {@code Bearer error="invalid_token"} */
    public static GatewayRejectedException unauthorized(ErrorCode code, String challenge) {
        return new GatewayRejectedException(code, Map.of(HttpHeaders.WWW_AUTHENTICATE, challenge));
    }

    /** 503 SERVICE_UNAVAILABLE + Retry-After(초, 최소 1) — 인증 서비스·폐기 목록·하위 서비스 장애(fail-closed, IAM-07.10) */
    public static GatewayRejectedException unavailable(Duration retryAfter) {
        return new GatewayRejectedException(CommonErrorCode.SERVICE_UNAVAILABLE,
                Map.of(HttpHeaders.RETRY_AFTER, Long.toString(Math.max(1, retryAfter.toSeconds()))));
    }

    public ErrorCode code() {
        return code;
    }

    public Map<String, String> headers() {
        return headers;
    }

    public Object[] messageArgs() {
        return messageArgs.clone();
    }
}
