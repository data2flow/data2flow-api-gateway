package net.java21.data2flow.gateway.web;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpMethod;

import static org.assertj.core.api.Assertions.assertThat;

class PathGuardWebFilterTest {

    @ParameterizedTest
    @ValueSource(strings = {"/a/../b", "/a/./b", "/a/%2E%2E/b", "/a%2fb", "/a%5cb", "/a\\b", "/a;x", "/a//b", "/a/%252e"})
    @DisplayName("정규화 우회 경로는 의심한다")
    void suspicious(String path) {
        assertThat(PathGuardWebFilter.isSuspicious(path)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "/", "/api/v1/core/devices/12", "/api/v1/core/public/release-notes", "/mcp"})
    @DisplayName("일반 경로는 통과")
    void normal(String path) {
        assertThat(PathGuardWebFilter.isSuspicious(path)).isFalse();
    }

    @Test
    @DisplayName("TC-IAM-050 조직 생성 경로는 v1에 없다")
    void notOffered() {
        assertThat(PathGuardWebFilter.isNotOffered(HttpMethod.POST, "/api/v1/core/organizations")).isTrue();
        assertThat(PathGuardWebFilter.isNotOffered(HttpMethod.GET, "/api/v1/core/organizations")).isFalse();
        assertThat(PathGuardWebFilter.isSuspicious(null)).isFalse();
    }

    @Test
    @DisplayName("로그용 경로 가림")
    void maskPath() {
        assertThat(AccessLogWebFilter.maskPath("/api/v1/core/invitations/secret/accept"))
                .isEqualTo("/api/v1/core/invitations/***/accept");
        assertThat(AccessLogWebFilter.maskPath("/api/v1/core/public/share/tok/widgets/1/data"))
                .isEqualTo("/api/v1/core/public/share/***/widgets/1/data");
        assertThat(AccessLogWebFilter.maskPath(null)).isNull();
    }
}
