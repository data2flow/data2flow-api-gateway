package net.java21.data2flow.gateway.ratelimit;

import net.java21.data2flow.gateway.config.GatewayProperties.Limit;
import reactor.core.publisher.Mono;

/**
 * 호출 한도 저장소(Redis). 저장소 장애일 때는 오류 대신 {@link RateLimitDecision#skipped()}를 돌려준다.
 * 한도는 보호 장치이고, 인증의 fail-closed(IAM-07.10)는 폐기 목록·토큰 조회가 맡는다.
 */
public interface RateLimiter {

    /**
     * 토큰 버킷에서 1개를 꺼낸다(auth.md §5 [보강] Redis 토큰 버킷).
     *
     * @param bucket 버킷 이름(예: {@code login:ip:203.0.113.7})
     */
    Mono<RateLimitDecision> consume(String bucket, Limit limit);

    /**
     * 고정 창 실패 횟수가 한도에 이르렀는지 본다. 세지는 않는다.
     */
    Mono<RateLimitDecision> checkFailures(String bucket, Limit limit);

    /** 실패 1회를 센다(고정 창). 결과는 기다리지 않아도 된다 */
    Mono<Void> recordFailure(String bucket, Limit limit);
}
