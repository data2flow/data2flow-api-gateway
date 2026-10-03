package net.java21.data2flow.gateway.web;

import net.java21.data2flow.gateway.support.GatewaySliceTest;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;

import static org.assertj.core.api.Assertions.assertThat;

/** IAM-01.01 조직 소속 — 외부(MCP 호스트)에서 보낸 위조 신원 헤더 (TC-IAM-006, AT-IAM-11.4, AT-IAM-21.4) */
class AccountMembershipFilterTest extends GatewaySliceTest {

    @Test
    @DisplayName("TC-IAM-006 AT-IAM-11.4 X-USER-ID: 1을 붙여 MCP 호스트로 요청 → 토큰이 없으면 401, 하위 서비스에 닿지 않는다")
    void forgedUserIdWithoutToken() {
        client.post().uri("/mcp")
                .header(HttpHeaders.HOST, MCP_HOST)
                .header("X-USER-ID", "1")
                .exchange()
                .expectStatus().isUnauthorized()
                .expectBody()
                .jsonPath("$.header.isSuccessful").isEqualTo(false)
                .jsonPath("$.header.resultCode").isEqualTo("AUTH_TOKEN_INVALID");
        assertThat(backend.downstreamRequests()).isEmpty();
    }

    @Test
    @DisplayName("AT-IAM-21.4 MCP 호스트 + 위조 X-ORG-ID + 유효 장기 토큰 → 위조 헤더는 지워지고 토큰의 조직·토큰 ID·범위만 간다")
    void forgedOrgWithMcpToken() {
        String token = backend.mcpToken("data2flow_abc", 7, 1, "41", "[\"read:telemetry\",\"read:devices\"]", null);
        client.post().uri("/mcp")
                .header(HttpHeaders.HOST, MCP_HOST)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .header("X-ORG-ID", "2")
                .header("X-ACCESS-TOKEN-ID", "999")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals("X-Content-Type-Options", "nosniff")
                .expectHeader().exists("Strict-Transport-Security");

        RecordedRequest forwarded = backend.lastDownstream();
        assertThat(forwarded.getPath()).as("MCP는 접두사를 유지한다").isEqualTo("/mcp");
        assertThat(forwarded.getHeaders().values("X-ORG-ID")).containsExactly("1");
        assertThat(forwarded.getHeaders().values("X-USER-ID")).containsExactly("7");
        assertThat(forwarded.getHeaders().values("X-ACCESS-TOKEN-ID")).containsExactly("41");
        assertThat(forwarded.getHeader("X-TOKEN-SCOPE")).isEqualTo("read:telemetry,read:devices");
        assertThat(forwarded.getHeader(HttpHeaders.AUTHORIZATION)).isNull();
    }
}
