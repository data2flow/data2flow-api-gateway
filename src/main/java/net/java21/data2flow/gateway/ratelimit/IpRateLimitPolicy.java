package net.java21.data2flow.gateway.ratelimit;

import net.java21.data2flow.contracts.error.CommonErrorCode;
import net.java21.data2flow.contracts.error.ErrorCode;
import net.java21.data2flow.gateway.config.GatewayProperties;
import net.java21.data2flow.gateway.config.GatewayProperties.Limit;

import java.util.Locale;
import java.util.function.Function;

/**
 * 인증 전(②) IP 기준 한도 정책. 로그인·재발급·계정 경로는 {@code AUTH_RATE_LIMITED}, 그 밖은 {@code RATE_LIMITED}(OPS-12.05).
 */
public enum IpRateLimitPolicy {

    /** 로그인·2단계 인증(BR-IAM-23: IP당 분당 20회) */
    LOGIN(CommonErrorCode.AUTH_RATE_LIMITED, GatewayProperties.RateLimit::login),
    /** 재발급·로그아웃 */
    REFRESH(CommonErrorCode.AUTH_RATE_LIMITED, GatewayProperties.RateLimit::refresh),
    /** 초대·비밀번호 재설정·가입 신청(API-IAM-13: AUTH_RATE_LIMITED, IP 기준) */
    ACCOUNT(CommonErrorCode.AUTH_RATE_LIMITED, GatewayProperties.RateLimit::account),
    /** 익명 공개 화면 API */
    PUBLIC_API(CommonErrorCode.RATE_LIMITED, GatewayProperties.RateLimit::publicApi);

    private final ErrorCode errorCode;
    private final Function<GatewayProperties.RateLimit, Limit> limit;

    IpRateLimitPolicy(ErrorCode errorCode, Function<GatewayProperties.RateLimit, Limit> limit) {
        this.errorCode = errorCode;
        this.limit = limit;
    }

    public ErrorCode errorCode() {
        return errorCode;
    }

    public Limit limit(GatewayProperties.RateLimit settings) {
        return limit.apply(settings);
    }

    /** Redis 버킷 이름: {@code login:ip:<ip>} */
    public String bucket(String clientIp) {
        return name().toLowerCase(Locale.ROOT).replace('_', '-') + ":ip:" + clientIp;
    }
}
