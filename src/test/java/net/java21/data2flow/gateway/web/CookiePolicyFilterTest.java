package net.java21.data2flow.gateway.web;

import net.java21.data2flow.gateway.support.GatewaySliceTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/** ⑤ CookiePolicy(auth.md §1·§9.1): 세션 쿠키는 어디에도, Refresh 쿠키는 auth에만 */
class CookiePolicyFilterTest extends GatewaySliceTest {

    @Test
    @DisplayName("auth 라우트에는 data2flow_refresh를 넘기고 data2flow_session은 지운다")
    void authRouteKeepsRefresh() {
        client.post().uri("/api/v1/auth/refresh-token")
                .header(HttpHeaders.COOKIE, "data2flow_session=s; data2flow_refresh=r; lang=ko")
                .exchange().expectStatus().isOk();
        assertThat(backend.lastDownstream().getHeader(HttpHeaders.COOKIE)).isEqualTo("data2flow_refresh=r; lang=ko");
    }

    @Test
    @DisplayName("core 라우트에는 두 쿠키 모두 넘기지 않고 다른 쿠키는 남긴다")
    void coreRouteDropsTokens() {
        String token = backend.accessToken("acc-cookie", 7, 1, "s", "j", expInOneHour());
        client.get().uri("/api/v1/core/devices")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .header(HttpHeaders.COOKIE, "data2flow_refresh=r; data2flow_session=s")
                .exchange().expectStatus().isOk();
        assertThat(backend.lastDownstream().getHeader(HttpHeaders.COOKIE)).isNull();

        client.get().uri("/api/v1/core/public/release-notes")
                .header(HttpHeaders.COOKIE, "lang=en")
                .exchange().expectStatus().isOk();
        assertThat(backend.lastDownstream().getHeader(HttpHeaders.COOKIE)).isEqualTo("lang=en");
    }

    @Test
    @DisplayName("쿠키 문자열 처리")
    void withoutCookies() {
        assertThat(CookiePolicyGlobalFilter.withoutCookies("a=1;  data2flow_session=x ;b=2", Set.of("data2flow_session")))
                .isEqualTo("a=1; b=2");
        assertThat(CookiePolicyGlobalFilter.withoutCookies("data2flow_session=x", Set.of("data2flow_session"))).isEmpty();
    }
}
