package net.java21.data2flow.gateway.auth;

import net.java21.data2flow.gateway.config.GatewayProperties;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;

/**
 * 토큰 조회 결과 캐시(auth.md §5 3번, IAM-07.10). 인스턴스 메모리에 두고 키는 토큰 원문의 SHA-256이다(원문은 보관하지 않는다).
 *
 * <ul>
 *   <li>활성 결과만 담는다. 수명은 min(설정 TTL ≤ 30초, 토큰 만료 시각)</li>
 *   <li>폐기 이벤트(EVT-IAM-03)를 받으면 sid·jti·토큰 ID가 같은 항목을 바로 지운다(IAM-07.05)</li>
 *   <li>항목 수가 상한을 넘으면 만료분을 지우고, 그래도 넘으면 모두 비운다(다시 조회하면 될 뿐이다)</li>
 * </ul>
 */
@Component
public class TokenValidationCache {

    private final ConcurrentHashMap<String, Entry> entries = new ConcurrentHashMap<>();
    private final Clock clock;
    private final Duration ttl;
    private final int maxEntries;

    public TokenValidationCache(Clock clock, GatewayProperties properties) {
        this.clock = clock;
        this.ttl = properties.introspection().cacheTtl();
        this.maxEntries = properties.introspection().cacheMaxEntries();
    }

    public Optional<Principal> find(String key) {
        Entry entry = entries.get(key);
        if (entry == null) {
            return Optional.empty();
        }
        if (entry.expiresAtMillis() <= clock.millis()) {
            entries.remove(key, entry);
            return Optional.empty();
        }
        return Optional.of(entry.principal());
    }

    public void put(String key, Principal principal) {
        long now = clock.millis();
        long expiresAt = now + ttl.toMillis();
        if (principal.expEpochSeconds() != null) {
            expiresAt = Math.min(expiresAt, principal.expEpochSeconds() * 1000);
        }
        if (expiresAt <= now) {
            return;
        }
        if (entries.size() >= maxEntries) {
            entries.values().removeIf(e -> e.expiresAtMillis() <= now);
            if (entries.size() >= maxEntries) {
                entries.clear();
            }
        }
        entries.put(key, new Entry(principal, expiresAt));
    }

    public void evict(String key) {
        entries.remove(key);
    }

    /** 폐기 이벤트 반영(EVT-IAM-03 {@code type: SID|JTI|TOKEN_ID}). 지운 항목 수 */
    public int evict(RevocationType type, String value) {
        if (value == null || value.isBlank()) {
            return 0;
        }
        Predicate<Principal> matches = switch (type) {
            case SID -> p -> Objects.equals(p.sid(), value);
            case JTI -> p -> Objects.equals(p.jti(), value);
            case TOKEN_ID -> p -> Objects.equals(p.tokenId(), value);
        };
        int before = entries.size();
        entries.values().removeIf(e -> matches.test(e.principal()));
        return before - entries.size();
    }

    public int size() {
        return entries.size();
    }

    public void clear() {
        entries.clear();
    }

    /** 캐시 키: 토큰 원문의 SHA-256(hex) */
    public static String keyOf(String token) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** 폐기 이벤트 종류(EVT-IAM-03) */
    public enum RevocationType {
        SID, JTI, TOKEN_ID
    }

    private record Entry(Principal principal, long expiresAtMillis) {
    }
}
