package net.java21.data2flow.gateway.auth;

import net.java21.data2flow.gateway.config.GatewayProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.SmartLifecycle;
import org.springframework.data.redis.connection.ReactiveRedisConnectionFactory;
import org.springframework.data.redis.listener.ChannelTopic;
import org.springframework.data.redis.listener.ReactiveRedisMessageListenerContainer;
import org.springframework.stereotype.Component;
import reactor.core.Disposable;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.time.Duration;

/**
 * 폐기 이벤트 구독(EVT-IAM-03, Redis Pub/Sub {@code data2flow:auth.revocations}). 모든 gateway 인스턴스가 받아 검증 캐시에서
 * 해당 sid·jti·토큰 ID를 바로 지운다(IAM-07.05, auth.md §4.2 [보강]). 페이로드 {@code {type: SID|JTI|TOKEN_ID, value, reason, occurredAt}}.
 *
 * <p>Redis가 끊기면 1초부터 30초까지 늘려 가며 다시 구독한다. 그동안에도 캐시 적중 요청은 폐기 목록을 매번 확인하고(RevocationStore),
 * 캐시 수명은 30초 이하라 폐기가 늦어도 상한이 있다(IAM-07.10).
 */
@Component
public class RevocationEventListener implements SmartLifecycle {

    private static final Logger log = LoggerFactory.getLogger(RevocationEventListener.class);

    private final ReactiveRedisConnectionFactory connectionFactory;
    private final TokenValidationCache cache;
    private final ObjectMapper objectMapper;
    private final String channel;
    private volatile Disposable subscription;

    public RevocationEventListener(ReactiveRedisConnectionFactory connectionFactory, TokenValidationCache cache,
                                   ObjectMapper objectMapper, GatewayProperties properties) {
        this.connectionFactory = connectionFactory;
        this.cache = cache;
        this.objectMapper = objectMapper;
        this.channel = properties.revocation().channel();
    }

    @Override
    public void start() {
        // 다시 연결할 때마다 새 컨테이너(연결)를 만든다. 끊긴 연결을 재사용하지 않기 위해서다
        subscription = Flux.usingWhen(
                        Mono.fromSupplier(() -> new ReactiveRedisMessageListenerContainer(connectionFactory)),
                        container -> container.receive(ChannelTopic.of(channel)),
                        ReactiveRedisMessageListenerContainer::destroyLater)
                .doOnSubscribe(s -> log.info("폐기 이벤트 구독 시작: {}", channel))
                .retryWhen(Retry.backoff(Long.MAX_VALUE, Duration.ofSeconds(1)).maxBackoff(Duration.ofSeconds(30))
                        .doBeforeRetry(signal -> log.atWarn()
                                .log("폐기 이벤트 구독이 끊겨 다시 연결합니다: {}", signal.failure().toString())))
                .subscribe(message -> handle(message.getMessage()),
                        ex -> log.error("폐기 이벤트 구독 종료", ex));
    }

    /** 페이로드 한 건을 캐시에 반영한다. 형식이 틀리면 기록만 하고 무시한다 */
    int handle(String payload) {
        try {
            JsonNode node = objectMapper.readTree(payload);
            TokenValidationCache.RevocationType type =
                    TokenValidationCache.RevocationType.valueOf(node.path("type").asString(""));
            int evicted = cache.evict(type, node.path("value").asString(null));
            log.atInfo().addKeyValue("revocationType", type.name()).addKeyValue("evicted", evicted)
                    .log("폐기 이벤트 반영");
            return evicted;
        } catch (RuntimeException ex) {
            log.atWarn().log("폐기 이벤트 형식이 맞지 않아 무시합니다: {}", ex.getClass().getSimpleName());
            return 0;
        }
    }

    @Override
    public void stop() {
        Disposable current = subscription;
        if (current != null) {
            current.dispose();
        }
        subscription = null;
    }

    @Override
    public boolean isRunning() {
        return subscription != null && !subscription.isDisposed();
    }
}
