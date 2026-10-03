package net.java21.data2flow.gateway.web;

import net.java21.data2flow.gateway.auth.Principal;
import net.java21.data2flow.gateway.error.GatewayRejectedException;
import net.java21.data2flow.gateway.support.GatewaySliceTest;
import net.java21.data2flow.gateway.support.TestBackend;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.http.HttpHeaders;
import reactor.core.publisher.Mono;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Mockito.never;

/**
 * IAM-07.09 게이트웨이 신원 전달, IAM-07.02 introspection, IAM-07.10 fail-closed·캐시 (TC-IAM-202, AT-IAM-21.3·21.4).
 */
class TokenAuthFilterTest extends GatewaySliceTest {

    private String userToken() {
        return backend.accessToken("access-kim", 7, 1, "sid-1", "jti-1", expInOneHour());
    }

    @Nested
    @DisplayName("IAM-07.09 신원 헤더")
    class IdentityHeaders {

        @Test
        @DisplayName("TC-IAM-202 AT-IAM-21.3 위조 X-USER-ID·X-ORG-ID·X-TOKEN-*·X-INTERNAL-*를 지우고 토큰의 신원만 넣는다")
        void forgedIdentityHeadersAreReplaced() {
            client.get().uri("/api/v1/core/devices?page=1")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + userToken())
                    .header("X-USER-ID", "1")
                    .header("x-org-id", "999")
                    .header("X-ACCESS-TOKEN-ID", "evil")
                    .header("X-TOKEN-SCOPE", "control:devices")
                    .header("X-Internal-Auth", "forged")
                    .header("X-CALLER-SERVICE", "data2flow-flow-engine")
                    .header("X-SESSION-ID", "sid-forged")
                    .exchange()
                    .expectStatus().isOk();

            RecordedRequest forwarded = backend.lastDownstream();
            assertThat(forwarded.getPath()).isEqualTo("/core/devices?page=1");
            assertThat(forwarded.getHeaders().values("X-USER-ID")).containsExactly("7");
            assertThat(forwarded.getHeaders().values("X-ORG-ID")).containsExactly("1");
            assertThat(forwarded.getHeaders().values("X-SESSION-ID")).as("현재 세션은 토큰의 sid만").containsExactly("sid-1");
            assertThat(forwarded.getHeader("X-ACCESS-TOKEN-ID")).isNull();
            assertThat(forwarded.getHeader("X-TOKEN-SCOPE")).isNull();
            assertThat(forwarded.getHeader("X-Internal-Auth")).isNull();
            assertThat(forwarded.getHeaders().values("X-CALLER-SERVICE")).containsExactly("data2flow-api-gateway");
            assertThat(forwarded.getHeader(HttpHeaders.AUTHORIZATION)).as("하위 서비스에는 토큰을 넘기지 않는다").isNull();
            assertThat(forwarded.getHeader("X-REQUEST-ID")).isNotBlank();
        }

        @Test
        @DisplayName("TC-IAM-202 공개 경로도 위조 신원 헤더를 지우고 신원 없이 넘긴다")
        void publicPathStripsIdentity() {
            client.post().uri("/api/v1/auth/login")
                    .header("X-USER-ID", "1")
                    .header("X-SESSION-ID", "sid-forged")
                    .header("X-ORG-ID", "1")
                    .bodyValue("{\"loginId\":\"kim.op\",\"password\":\"x\"}")
                    .exchange()
                    .expectStatus().isOk();

            RecordedRequest forwarded = backend.lastDownstream();
            assertThat(forwarded.getPath()).isEqualTo("/auth/login");
            assertThat(forwarded.getHeader("X-USER-ID")).isNull();
            assertThat(forwarded.getHeader("X-ORG-ID")).isNull();
            assertThat(forwarded.getHeader("X-SESSION-ID")).isNull();
            assertThat(backend.introspectRequests()).isEmpty();
        }

        @Test
        @DisplayName("TC-IAM-202 캐시 적중이어도 X-SESSION-ID는 토큰의 sid로 넣는다(위조 값은 지운다)")
        void sessionIdFromCachedPrincipal() {
            String token = userToken();
            client.get().uri("/api/v1/core/accounts/me/sessions")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .exchange().expectStatus().isOk();
            client.get().uri("/api/v1/core/accounts/me/sessions")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .header("x-session-id", "sid-other")
                    .exchange().expectStatus().isOk();

            assertThat(backend.introspectRequests()).as("두 번째는 캐시 적중").hasSize(1);
            assertThat(backend.lastDownstream().getHeaders().values("X-SESSION-ID")).containsExactly("sid-1");
        }

        @Test
        @DisplayName("TC-IAM-202 토큰 조회 요청 계약: POST form token=…, X-CALLER-SERVICE, X-REQUEST-ID")
        void introspectionRequestContract() {
            client.get().uri("/api/v1/ai/conversations")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + userToken())
                    .header("X-REQUEST-ID", "req-abc-1")
                    .exchange()
                    .expectStatus().isOk()
                    .expectHeader().valueEquals("X-REQUEST-ID", "req-abc-1");

            RecordedRequest introspect = backend.introspectRequests().get(0);
            assertThat(introspect.getMethod()).isEqualTo("POST");
            assertThat(introspect.getHeader("Content-Type")).startsWith("application/x-www-form-urlencoded");
            assertThat(introspect.getHeader("X-CALLER-SERVICE")).isEqualTo("data2flow-api-gateway");
            assertThat(introspect.getHeader("X-REQUEST-ID")).isEqualTo("req-abc-1");
            assertThat(backend.lastDownstream().getPath()).isEqualTo("/ai/conversations");
        }
    }

    @Nested
    @DisplayName("IAM-07.02 토큰 판정")
    class Verdicts {

        @Test
        @DisplayName("토큰이 없으면 401 AUTH_TOKEN_INVALID + WWW-Authenticate: Bearer")
        void missingToken() {
            client.get().uri("/api/v1/core/devices")
                    .exchange()
                    .expectStatus().isUnauthorized()
                    .expectHeader().valueEquals(HttpHeaders.WWW_AUTHENTICATE, GatewayRejectedException.BEARER_CHALLENGE)
                    .expectBody()
                    .jsonPath("$.header.isSuccessful").isEqualTo(false)
                    .jsonPath("$.header.resultCode").isEqualTo("AUTH_TOKEN_INVALID")
                    .jsonPath("$.response").doesNotExist();
            assertThat(backend.downstreamRequests()).isEmpty();
        }

        @Test
        @DisplayName("Bearer가 아닌 스킴은 토큰 없음과 같다")
        void nonBearerScheme() {
            client.get().uri("/api/v1/core/devices")
                    .header(HttpHeaders.AUTHORIZATION, "Basic dXNlcjpwYXNz")
                    .exchange()
                    .expectStatus().isUnauthorized();
        }

        @ParameterizedTest(name = "{0} → {1}")
        @CsvSource({"EXPIRED,AUTH_TOKEN_EXPIRED", "REVOKED,AUTH_SESSION_REVOKED", "INVALID,AUTH_TOKEN_INVALID",
                "SOMETHING_NEW,AUTH_TOKEN_INVALID"})
        @DisplayName("비활성 사유별 401 + WWW-Authenticate: Bearer error=\"invalid_token\"")
        void inactiveReasons(String reason, String code) {
            String token = backend.inactiveToken("inactive-" + reason, reason);
            client.get().uri("/api/v1/core/devices")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .exchange()
                    .expectStatus().isUnauthorized()
                    .expectHeader().valueEquals(HttpHeaders.WWW_AUTHENTICATE, GatewayRejectedException.INVALID_TOKEN_CHALLENGE)
                    .expectBody().jsonPath("$.header.resultCode").isEqualTo(code);
            assertThat(backend.downstreamRequests()).isEmpty();
        }

        @Test
        @DisplayName("IAM-07.07 무효 토큰은 IP별 실패 시도로 센다(만료는 세지 않는다)")
        void invalidTokenIsCountedAsFailure() {
            client.get().uri("/api/v1/core/devices").header(HttpHeaders.AUTHORIZATION, "Bearer unknown")
                    .exchange().expectStatus().isUnauthorized();
            then(rateLimiter).should().recordFailure(eq("failed-auth:ip:127.0.0.1"), any());

            String expired = backend.inactiveToken("expired", "EXPIRED");
            client.get().uri("/api/v1/core/devices").header(HttpHeaders.AUTHORIZATION, "Bearer " + expired)
                    .exchange().expectStatus().isUnauthorized();
            then(rateLimiter).should(org.mockito.Mockito.times(1)).recordFailure(any(), any());
        }

        @Test
        @DisplayName("공통 머리 없이 판정만 오는 응답도 받는다")
        void bareIntrospectionBody() {
            String token = backend.rawResponse("bare",
                    "{\"active\":true,\"sub\":\"8\",\"org\":\"1\",\"sid\":\"s\",\"jti\":\"j\",\"exp\":" + expInOneHour() + "}");
            client.get().uri("/api/v1/core/devices").header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .exchange().expectStatus().isOk();
            assertThat(backend.lastDownstream().getHeader("X-USER-ID")).isEqualTo("8");
        }

        @Test
        @DisplayName("Accept-Language에 따라 resultMessage만 바뀐다(OPS-12.01, ADR-037)")
        void localizedMessage() {
            client.get().uri("/api/v1/core/devices").header(HttpHeaders.ACCEPT_LANGUAGE, "en-US,en;q=0.9")
                    .exchange()
                    .expectBody()
                    .jsonPath("$.header.resultCode").isEqualTo("AUTH_TOKEN_INVALID")
                    .jsonPath("$.header.resultMessage").isEqualTo("Please sign in again");
            client.get().uri("/api/v1/core/devices")
                    .exchange()
                    .expectBody().jsonPath("$.header.resultMessage").isEqualTo("다시 로그인해 주세요");
        }
    }

    @Nested
    @DisplayName("IAM-07.10 fail-closed")
    class FailClosed {

        @ParameterizedTest(name = "인증 서비스 {0}")
        @CsvSource({"UNAVAILABLE", "DISCONNECT", "GARBAGE"})
        @DisplayName("TC-IAM-203 인증 서비스 장애·계약 위반이면 503 SERVICE_UNAVAILABLE + Retry-After")
        void authServiceFailure(TestBackend.AuthMode mode) {
            backend.authMode(mode);
            client.get().uri("/api/v1/core/devices")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + userToken())
                    .exchange()
                    .expectStatus().isEqualTo(503)
                    .expectHeader().valueEquals(HttpHeaders.RETRY_AFTER, "5")
                    .expectBody().jsonPath("$.header.resultCode").isEqualTo("SERVICE_UNAVAILABLE");
            assertThat(backend.downstreamRequests()).isEmpty();
            then(rateLimiter).should(never()).recordFailure(any(), any());
        }

        @Test
        @DisplayName("TC-IAM-203 캐시 적중이어도 폐기 목록 저장소 장애면 503")
        void blacklistStoreFailure() {
            String token = userToken();
            client.get().uri("/api/v1/core/devices").header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .exchange().expectStatus().isOk();
            given(revocationStore.isRevoked(any(Principal.class)))
                    .willReturn(Mono.error(GatewayRejectedException.unavailable(Duration.ofSeconds(5))));

            client.get().uri("/api/v1/core/devices").header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .exchange()
                    .expectStatus().isEqualTo(503)
                    .expectBody().jsonPath("$.header.resultCode").isEqualTo("SERVICE_UNAVAILABLE");
        }
    }

    @Nested
    @DisplayName("IAM-07.10 검증 결과 캐시")
    class Cache {

        @Test
        @DisplayName("TC-IAM-203 30초 안의 같은 토큰은 다시 조회하지 않고, 30초가 지나면 다시 조회한다")
        void cacheUpTo30Seconds() {
            String token = userToken();
            for (int i = 0; i < 3; i++) {
                client.get().uri("/api/v1/core/devices").header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .exchange().expectStatus().isOk();
            }
            assertThat(backend.introspectRequests()).hasSize(1);

            clock.advanceBy(Duration.ofSeconds(30));
            client.get().uri("/api/v1/core/devices").header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .exchange().expectStatus().isOk();
            assertThat(backend.introspectRequests()).hasSize(2);
        }

        @Test
        @DisplayName("TC-IAM-203 AT-IAM-04.1 캐시에 있던 토큰도 폐기 목록에 오르면 바로 401 AUTH_SESSION_REVOKED")
        void cachedTokenRevoked() {
            String token = userToken();
            client.get().uri("/api/v1/core/devices").header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .exchange().expectStatus().isOk();
            given(revocationStore.isRevoked(any(Principal.class))).willReturn(Mono.just(true));

            client.get().uri("/api/v1/core/devices").header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .exchange()
                    .expectStatus().isUnauthorized()
                    .expectBody().jsonPath("$.header.resultCode").isEqualTo("AUTH_SESSION_REVOKED");
            assertThat(backend.downstreamRequests()).hasSize(1);
        }
    }

    @Nested
    @DisplayName("토큰 종류와 경로(auth.md §5 6번, ADR-028)")
    class TokenKind {

        @Test
        @DisplayName("웹 Access 토큰으로 MCP를 부르면 403 PERMISSION_DENIED")
        void accessTokenOnMcp() {
            client.post().uri("/mcp")
                    .header(HttpHeaders.HOST, MCP_HOST)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + userToken())
                    .exchange()
                    .expectStatus().isForbidden()
                    .expectBody().jsonPath("$.header.resultCode").isEqualTo("PERMISSION_DENIED");
        }

        @Test
        @DisplayName("장기 토큰으로 일반 API를 부르면 403 PERMISSION_DENIED(공개 REST API 없음)")
        void longLivedTokenOnApi() {
            String token = backend.mcpToken("data2flow_mcp1", 7, 1, "41", "[\"read:telemetry\"]", null);
            client.get().uri("/api/v1/core/devices").header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .exchange()
                    .expectStatus().isForbidden();
            assertThat(backend.downstreamRequests()).isEmpty();
        }
    }
}
