package net.java21.data2flow.gateway.auth;

import net.java21.data2flow.gateway.config.GatewayProperties;
import net.java21.data2flow.gateway.error.GatewayRejectedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * 폐기 목록(블랙리스트) 조회(auth.md §4.2). 키 {@code data2flow:bl:at:{jti}}, {@code data2flow:bl:sid:{sid}}는 auth가 쓰고
 * gateway는 읽기만 한다. 캐시에 있던 토큰도 매 요청 {@code MGET} 1회로 다시 확인해, 폐기 이벤트를 놓쳐도 바로 거부한다.
 * 저장소 장애·시간 초과는 503(fail-closed, IAM-07.10).
 */
@Component
public class RevocationStore {

    private static final Logger log = LoggerFactory.getLogger(RevocationStore.class);

    private final ReactiveStringRedisTemplate redis;
    private final GatewayProperties properties;

    public RevocationStore(ReactiveStringRedisTemplate redis, GatewayProperties properties) {
        this.redis = redis;
        this.properties = properties;
    }

    /** 이 토큰(jti)이나 로그인(sid)이 폐기됐는가. 확인할 ID가 없으면(장기 토큰) false */
    public Mono<Boolean> isRevoked(Principal principal) {
        String prefix = properties.revocation().keyPrefix();
        List<String> keys = new ArrayList<>(2);
        if (principal.jti() != null) {
            keys.add(prefix + "at:" + principal.jti());
        }
        if (principal.sid() != null) {
            keys.add(prefix + "sid:" + principal.sid());
        }
        if (keys.isEmpty()) {
            return Mono.just(false);
        }
        return redis.opsForValue().multiGet(keys)
                .map(values -> values.stream().anyMatch(Objects::nonNull))
                .defaultIfEmpty(false)
                .timeout(properties.revocation().timeout())
                .onErrorMap(ex -> {
                    log.atWarn().log("폐기 목록을 조회하지 못해 503으로 거절합니다(fail-closed): {}", ex.getClass().getSimpleName());
                    return GatewayRejectedException.unavailable(properties.unavailableRetryAfter());
                });
    }
}
