package net.java21.data2flow.gateway.web;

import net.java21.data2flow.gateway.support.GatewaySliceTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 라우트·노출 범위(auth.md §2, IAM-07.11, ADR-004·024·028). TC-IAM-050(AT-IAM-20.1·20.2), backend.md GatewayExposure.
 */
class PublicRouteExposureFilterTest extends GatewaySliceTest {

    @ParameterizedTest(name = "{0} {1}")
    @CsvSource({
            "POST, /api/v1/auth/signup",
            "POST, /api/v1/core/organizations",
            "GET, /api/v1/auth/oauth2/github",
            "GET, /api/v1/auth/sso/authorize",
            "GET, /api/v1/unknown/things",
            "GET, /internal/core/users",
            "GET, /core/devices",
            "GET, /mcp"
    })
    @DisplayName("TC-IAM-050 AT-IAM-20.2 IAM-07.11 v1에 없는 경로·범위 밖 경로는 비로그인이어도 404 RESOURCE_NOT_FOUND이고 하위 서비스에 닿지 않는다")
    void undefinedPathsAre404(String method, String path) {
        client.method(HttpMethod.valueOf(method)).uri(path)
                .exchange()
                .expectStatus().isNotFound()
                .expectHeader().exists("X-REQUEST-ID")
                .expectBody()
                .jsonPath("$.header.isSuccessful").isEqualTo(false)
                .jsonPath("$.header.resultCode").isEqualTo("RESOURCE_NOT_FOUND")
                .jsonPath("$.response").doesNotExist();
        assertThat(backend.downstreamRequests()).isEmpty();
        assertThat(backend.introspectRequests()).isEmpty();
    }

    @Test
    @DisplayName("GatewayExposure: MCP 호스트에서는 /mcp/**만 받고 /api/v1/**는 404")
    void mcpHostOnlyServesMcp() {
        String token = backend.accessToken("t-exp", 7, 1, "s", "j", expInOneHour());
        client.get().uri("/api/v1/core/devices")
                .header(HttpHeaders.HOST, MCP_HOST)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchange()
                .expectStatus().isNotFound()
                .expectHeader().valueEquals("X-Frame-Options", "DENY");
        client.post().uri("/api/v1/auth/login")
                .header(HttpHeaders.HOST, MCP_HOST + ":443")
                .exchange()
                .expectStatus().isNotFound();
        assertThat(backend.downstreamRequests()).isEmpty();
    }

    @ParameterizedTest(name = "{0} {1}")
    @CsvSource({
            "POST, /api/v1/auth/login, /auth/login",
            "POST, /api/v1/auth/login/mfa, /auth/login/mfa",
            "POST, /api/v1/auth/refresh-token, /auth/refresh-token",
            "POST, /api/v1/auth/logout, /auth/logout",
            "GET, /api/v1/core/invitations/abc, /core/invitations/abc",
            "GET, /api/v1/core/invitations/abc/login-id-availability, /core/invitations/abc/login-id-availability",
            "POST, /api/v1/core/invitations/abc/accept, /core/invitations/abc/accept",
            "POST, /api/v1/core/password-resets, /core/password-resets",
            "POST, /api/v1/core/password-resets/abc/confirm, /core/password-resets/abc/confirm",
            "POST, /api/v1/core/signup-requests, /core/signup-requests",
            "POST, /api/v1/core/signup-requests/abc/verify, /core/signup-requests/abc/verify",
            "GET, /api/v1/core/public/release-notes, /core/public/release-notes",
            "POST, /api/v1/core/public/share/tok/widgets/3/data, /core/public/share/tok/widgets/3/data"
    })
    @DisplayName("auth.md §3.3 공개 경로는 토큰 없이 stripPrefix(2)로 넘어간다")
    void publicPathsPassWithoutToken(String method, String external, String internal) {
        client.method(HttpMethod.valueOf(method)).uri(external)
                .exchange()
                .expectStatus().isOk();
        assertThat(backend.lastDownstream().getPath()).isEqualTo(internal);
        assertThat(backend.introspectRequests()).isEmpty();
    }

    @Test
    @DisplayName("같은 공개 경로라도 다른 메서드는 보호 경로다(기본 거부)")
    void publicPathOtherMethodNeedsToken() {
        client.delete().uri("/api/v1/core/password-resets")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    @DisplayName("실시간 경로 /api/v1/core/stream/**는 core로 가고 인증을 거친다")
    void streamRoute() {
        client.get().uri("/api/v1/core/stream/live?topics=alarms")
                .exchange()
                .expectStatus().isUnauthorized();
        String token = backend.accessToken("t-stream", 7, 1, "s", "j", expInOneHour());
        client.get().uri("/api/v1/core/stream/live?topics=alarms")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchange()
                .expectStatus().isOk();
        assertThat(backend.lastDownstream().getPath()).isEqualTo("/core/stream/live?topics=alarms");
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource({
            "/api/v1/core/public/%2e%2e/devices",
            "/api/v1/core/public/..%2fdevices",
            "/api/v1/core/public;x/../devices",
            "/api/v1/core//devices"
    })
    @DisplayName("경로 정규화 우회 시도는 400 INVALID_REQUEST")
    void pathTraversalRejected(String path) {
        client.get().uri(java.net.URI.create("http://localhost:" + port + path))
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody().jsonPath("$.header.resultCode").isEqualTo("INVALID_REQUEST");
        assertThat(backend.downstreamRequests()).isEmpty();
    }

    @Test
    @DisplayName("api-rules §6 X-REQUEST-ID가 없으면 만들어 응답·하위 요청에 싣고, 이상한 값은 바꾼다")
    void requestIdGenerated() {
        client.post().uri("/api/v1/auth/logout")
                .header("X-REQUEST-ID", "bad value <script>")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().value("X-REQUEST-ID", id -> assertThat(id).matches("[0-9a-f-]{36}"));
        assertThat(backend.lastDownstream().getHeader("X-REQUEST-ID")).matches("[0-9a-f-]{36}");
    }

    @Test
    @DisplayName("하위 서비스의 오류 응답은 gateway가 바꾸지 않고 그대로 전달한다")
    void downstreamErrorPassesThrough() {
        backend.downstreamStatus(404);
        client.post().uri("/api/v1/auth/logout")
                .exchange()
                .expectStatus().isNotFound();
    }
}
