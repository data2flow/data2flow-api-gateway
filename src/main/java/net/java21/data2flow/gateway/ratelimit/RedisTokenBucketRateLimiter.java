package net.java21.data2flow.gateway.ratelimit;

import net.java21.data2flow.gateway.config.GatewayProperties;
import net.java21.data2flow.gateway.config.GatewayProperties.Limit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.util.List;

/**
 * Redis 토큰 버킷과 실패 횟수 고정 창(auth.md §5 [보강] 11번: 인스턴스 수와 관계없이 한도가 하나).
 *
 * <p>키는 {@code data2flow:gw:rl:<bucket>}(ADR-022 접두사). 버킷 상태는 Redis가 재시작해 사라져도 되는 값이다.
 * 현재 시각은 주입한 {@link Clock}에서 넘겨서 테스트가 시간을 정할 수 있게 한다. Redis 장애·지연이면 검사를 건너뛴다(fail-open).
 */
@Component
public class RedisTokenBucketRateLimiter implements RateLimiter {

    private static final Logger log = LoggerFactory.getLogger(RedisTokenBucketRateLimiter.class);

    /** 반환: {허용(1/0), 남은 토큰(내림), 재시도까지 ms, 가득 찰 때까지 ms} */
    @SuppressWarnings({"rawtypes", "unchecked"})
    static final RedisScript<List<Long>> TOKEN_BUCKET = (RedisScript) RedisScript.of("""
            local capacity = tonumber(ARGV[1])
            local window = tonumber(ARGV[2])
            local now = tonumber(ARGV[3])
            local rate = capacity / window
            local state = redis.call('HMGET', KEYS[1], 't', 'ts')
            local tokens = tonumber(state[1])
            local ts = tonumber(state[2])
            if tokens == nil or ts == nil then
              tokens = capacity
              ts = now
            end
            if now > ts then
              tokens = math.min(capacity, tokens + (now - ts) * rate)
              ts = now
            end
            local allowed = 0
            if tokens >= 1 then
              tokens = tokens - 1
              allowed = 1
            end
            redis.call('HSET', KEYS[1], 't', tostring(tokens), 'ts', tostring(ts))
            redis.call('PEXPIRE', KEYS[1], window)
            local retry = 0
            if allowed == 0 then
              retry = math.ceil((1 - tokens) / rate)
            end
            return {allowed, math.floor(tokens), retry, math.ceil((capacity - tokens) / rate)}
            """, List.class);

    /** 반환: {현재 실패 수, 남은 ms} */
    @SuppressWarnings({"rawtypes", "unchecked"})
    static final RedisScript<List<Long>> FAILURE_CHECK = (RedisScript) RedisScript.of("""
            local count = tonumber(redis.call('GET', KEYS[1]) or '0')
            return {count, redis.call('PTTL', KEYS[1])}
            """, List.class);

    static final RedisScript<Long> FAILURE_RECORD = RedisScript.of("""
            local count = redis.call('INCR', KEYS[1])
            if count == 1 then
              redis.call('PEXPIRE', KEYS[1], ARGV[1])
            end
            return count
            """, Long.class);

    private final ReactiveStringRedisTemplate redis;
    private final Clock clock;
    private final GatewayProperties.RateLimit settings;

    public RedisTokenBucketRateLimiter(ReactiveStringRedisTemplate redis, Clock clock, GatewayProperties properties) {
        this.redis = redis;
        this.clock = clock;
        this.settings = properties.rateLimit();
    }

    @Override
    public Mono<RateLimitDecision> consume(String bucket, Limit limit) {
        long windowMs = Math.max(1, limit.window().toMillis());
        return redis.execute(TOKEN_BUCKET, List.of(key(bucket)),
                        List.of(Long.toString(limit.limit()), Long.toString(windowMs), Long.toString(clock.millis())))
                .next()
                .map(result -> new RateLimitDecision(result.get(0) == 1L, limit.limit(), result.get(1),
                        seconds(result.get(3)), seconds(result.get(2))))
                .timeout(settings.timeout())
                .onErrorResume(RedisTokenBucketRateLimiter::skipped);
    }

    @Override
    public Mono<RateLimitDecision> checkFailures(String bucket, Limit limit) {
        return redis.execute(FAILURE_CHECK, List.of(key(bucket)), List.of())
                .next()
                .map(result -> {
                    long count = result.get(0);
                    long ttlSeconds = result.get(1) > 0 ? seconds(result.get(1)) : 0;
                    return new RateLimitDecision(count < limit.limit(), limit.limit(), limit.limit() - count,
                            ttlSeconds, ttlSeconds);
                })
                .timeout(settings.timeout())
                .onErrorResume(RedisTokenBucketRateLimiter::skipped);
    }

    @Override
    public Mono<Void> recordFailure(String bucket, Limit limit) {
        return redis.execute(FAILURE_RECORD, List.of(key(bucket)),
                        List.of(Long.toString(Math.max(1, limit.window().toMillis()))))
                .then()
                .timeout(settings.timeout())
                .onErrorResume(ex -> {
                    log.atWarn().log("실패 횟수를 기록하지 못했습니다: {}", ex.toString());
                    return Mono.empty();
                });
    }

    private String key(String bucket) {
        return settings.keyPrefix() + bucket;
    }

    private static Mono<RateLimitDecision> skipped(Throwable ex) {
        log.atWarn().log("호출 한도 저장소를 쓸 수 없어 검사를 건너뜁니다: {}", ex.toString());
        return Mono.just(RateLimitDecision.skipped());
    }

    static long seconds(long millis) {
        return (millis + 999) / 1000;
    }
}
