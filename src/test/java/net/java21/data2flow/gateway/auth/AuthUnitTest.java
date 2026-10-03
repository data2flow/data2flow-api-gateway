package net.java21.data2flow.gateway.auth;

import net.java21.data2flow.gateway.config.GatewayProperties;
import net.java21.data2flow.gateway.support.MutableClock;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import tools.jackson.databind.json.JsonMapper;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** 인증 구성 요소 단위 테스트(IAM-07.02·07.05·07.10) */
class AuthUnitTest {

    static GatewayProperties properties(Duration ttl, int maxEntries) {
        return new GatewayProperties(new GatewayProperties.Services("http://localhost:1", "x", "x", "x"), " ", null, null,
                new GatewayProperties.Introspection(null, null, null, ttl, maxEntries), null, null);
    }

    static Principal access(String sid, String jti, Long exp) {
        return new Principal("7", "1", Principal.TokenType.ACCESS, jti, sid, null, null, null, exp);
    }

    @Nested
    class Cache {

        MutableClock clock = MutableClock.atUtc("2026-10-03T00:00:00Z");

        @Test
        @DisplayName("IAM-07.10 TTL은 30초를 넘지 않고, 토큰 만료가 더 빠르면 그때까지만")
        void ttl() {
            TokenValidationCache cache = new TokenValidationCache(clock, properties(Duration.ofMinutes(5), 10));
            long now = clock.instant().getEpochSecond();
            cache.put("a", access("s1", "j1", null));
            cache.put("b", access("s2", "j2", now + 10));
            cache.put("c", access("s3", "j3", now - 1));
            assertThat(cache.find("c")).isEmpty();
            clock.advanceBy(Duration.ofSeconds(10));
            assertThat(cache.find("b")).isEmpty();
            assertThat(cache.find("a")).isPresent();
            clock.advanceBy(Duration.ofSeconds(20));
            assertThat(cache.find("a")).isEmpty();
            assertThat(cache.find("zzz")).isEmpty();
        }

        @Test
        @DisplayName("IAM-07.05 폐기 이벤트(SID·JTI·TOKEN_ID)로 해당 항목만 지운다")
        void evictByEvent() {
            TokenValidationCache cache = new TokenValidationCache(clock, properties(null, 10));
            cache.put("a", access("s1", "j1", null));
            cache.put("b", access("s1", "j2", null));
            cache.put("c", access("s2", "j3", null));
            cache.put("d", new Principal("7", "1", Principal.TokenType.MCP, null, null, "41", List.of("read:devices"), 60L, null));
            assertThat(cache.evict(TokenValidationCache.RevocationType.SID, "s1")).isEqualTo(2);
            assertThat(cache.evict(TokenValidationCache.RevocationType.JTI, "j3")).isEqualTo(1);
            assertThat(cache.evict(TokenValidationCache.RevocationType.TOKEN_ID, "41")).isEqualTo(1);
            assertThat(cache.evict(TokenValidationCache.RevocationType.SID, " ")).isZero();
            assertThat(cache.size()).isZero();
        }

        @Test
        @DisplayName("상한을 넘으면 만료분을 지우고, 그래도 넘으면 비운다")
        void bounded() {
            TokenValidationCache cache = new TokenValidationCache(clock, properties(null, 2));
            cache.put("a", access("s", "j", null));
            cache.put("b", access("s", "j", null));
            cache.put("c", access("s", "j", null));
            assertThat(cache.size()).isEqualTo(1);
            assertThat(TokenValidationCache.keyOf("t")).hasSize(64).isEqualTo(TokenValidationCache.keyOf("t"));
        }
    }

    @Nested
    class Introspection {

        IntrospectionClient client = new IntrospectionClient(JsonMapper.builder().build(), properties(null, 10));

        @Test
        @DisplayName("API-IAM-34 응답 해석: 활성 장기 토큰, 범위 문자열, 숫자 문자열")
        void parseActive() {
            IntrospectionResult result = client.parse("""
                    {"header":{"isSuccessful":true},"response":{"active":true,"sub":7,"org":"1","typ":"API_KEY",
                     "tokenId":"9","scopes":"read:telemetry read:devices","rateLimitPerMin":"100","exp":null}}""");
            assertThat(result.active()).isTrue();
            assertThat(result.principal().scopes()).containsExactly("read:telemetry", "read:devices");
            assertThat(result.principal().rateLimitPerMin()).isEqualTo(100L);
            assertThat(result.principal().longLived()).isTrue();
        }

        @Test
        @DisplayName("계약 위반은 예외(→ 503 fail-closed)")
        void contractViolations() {
            for (String body : List.of(
                    "{\"header\":{\"isSuccessful\":false},\"response\":{\"active\":true}}",
                    "{\"header\":{\"isSuccessful\":true}}",
                    "{\"active\":true,\"sub\":\"x\",\"org\":\"1\"}",
                    "{\"active\":true,\"sub\":\"1\"}",
                    "{\"active\":true,\"sub\":\"1\",\"org\":\"1\",\"typ\":\"MCP\"}",
                    "{\"active\":true,\"sub\":\"1\",\"org\":\"1\",\"typ\":\"WEIRD\"}",
                    "[]")) {
                assertThatThrownBy(() -> client.parse(body)).as(body).isInstanceOf(RuntimeException.class);
            }
        }

        @Test
        @DisplayName("비활성 사유가 없거나 모르면 INVALID")
        void inactive() {
            assertThat(client.parse("{\"active\":false}").inactiveReason())
                    .isEqualTo(IntrospectionResult.InactiveReason.INVALID);
            assertThat(client.parse("{\"active\":false,\"inactiveReason\":\"expired\"}").inactiveReason())
                    .isEqualTo(IntrospectionResult.InactiveReason.EXPIRED);
        }
    }

    @Nested
    class Misc {

        @Test
        @DisplayName("Bearer 추출")
        void bearer() {
            assertThat(BearerToken.parse("bearer abc")).contains("abc");
            assertThat(BearerToken.parse("Bearer ")).isEmpty();
            assertThat(BearerToken.parse("Bearer    ")).isEmpty();
            assertThat(BearerToken.parse(null)).isEmpty();
            assertThat(BearerToken.parse("Bearer " + "x".repeat(9000))).isEmpty();
        }

        @Test
        @DisplayName("공개 경로 판정은 (메서드, 경로) 쌍")
        void publicPaths() {
            PublicPaths paths = new PublicPaths();
            assertThat(paths.isPublic(HttpMethod.POST, "/api/v1/auth/login")).isTrue();
            assertThat(paths.isPublic(HttpMethod.GET, "/api/v1/auth/login")).isFalse();
            assertThat(paths.isPublic(HttpMethod.GET, "/api/v1/core/public/a/b/c")).isTrue();
            assertThat(paths.isPublic(HttpMethod.GET, "/api/v1/core/devices")).isFalse();
        }

        @Test
        @DisplayName("설정 기본값과 캐시 상한")
        void propertiesDefaults() {
            GatewayProperties p = properties(Duration.ofMinutes(10), 0);
            assertThat(p.mcpHost()).isNull();
            assertThat(p.introspection().cacheTtl()).isEqualTo(Duration.ofSeconds(30));
            assertThat(p.introspection().cacheMaxEntries()).isEqualTo(100_000);
            assertThat(p.rateLimit().login().limit()).isEqualTo(20);
            assertThat(p.revocation().channel()).isEqualTo("data2flow:auth.revocations");
            assertThatThrownBy(() -> new GatewayProperties.Limit(0, null)).isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("EVT-IAM-03 페이로드 반영, 형식이 틀리면 무시")
        void revocationPayload() {
            MutableClock clock = MutableClock.atUtc("2026-10-03T00:00:00Z");
            TokenValidationCache cache = new TokenValidationCache(clock, properties(null, 10));
            cache.put("a", access("s1", "j1", null));
            RevocationEventListener listener = new RevocationEventListener(null, cache, JsonMapper.builder().build(),
                    properties(null, 10));
            assertThat(listener.handle("{\"type\":\"SID\",\"value\":\"s1\",\"reason\":\"LOGOUT\"}")).isEqualTo(1);
            assertThat(listener.handle("{\"type\":\"NOPE\",\"value\":\"s1\"}")).isZero();
            assertThat(listener.handle("not json")).isZero();
            assertThat(listener.isRunning()).isFalse();
            listener.stop();
        }
    }
}
