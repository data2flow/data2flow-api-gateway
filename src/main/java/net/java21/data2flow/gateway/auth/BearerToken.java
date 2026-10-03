package net.java21.data2flow.gateway.auth;

import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;

import java.util.Optional;

/** {@code Authorization: Bearer <토큰>}에서 토큰을 꺼낸다. 스킴은 대소문자를 가리지 않고, 다른 스킴은 없는 것으로 본다 */
public final class BearerToken {

    private static final String PREFIX = "Bearer ";
    /** 이보다 긴 값은 토큰으로 보지 않는다(조회 요청 크기 상한) */
    private static final int MAX_LENGTH = 8192;

    private BearerToken() {
    }

    public static Optional<String> from(ServerHttpRequest request) {
        return parse(request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION));
    }

    static Optional<String> parse(String authorization) {
        if (authorization == null || authorization.length() <= PREFIX.length()
                || !authorization.regionMatches(true, 0, PREFIX, 0, PREFIX.length())) {
            return Optional.empty();
        }
        String token = authorization.substring(PREFIX.length()).trim();
        if (token.isEmpty() || token.length() > MAX_LENGTH) {
            return Optional.empty();
        }
        return Optional.of(token);
    }
}
