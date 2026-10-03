package net.java21.data2flow.gateway.ratelimit;

import net.java21.data2flow.contracts.error.CommonErrorCode;
import net.java21.data2flow.gateway.error.GatewayRejectedException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.config.GatewayProperties;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;

import java.net.InetSocketAddress;

import static org.assertj.core.api.Assertions.assertThat;

/** OPS-12.05 한도 헤더, auth.md §5 사용자 IP */
class RateLimitUnitTest {

    @Test
    @DisplayName("BR-OPS-22 거절에는 Retry-After(최소 1초)와 X-RateLimit-*가 붙는다")
    void decision() {
        GatewayRejectedException ex = new RateLimitDecision(false, 20, -3, 0, 0).rejection(CommonErrorCode.RATE_LIMITED);
        assertThat(ex.headers()).containsEntry("Retry-After", "1").containsEntry("X-RateLimit-Remaining", "0")
                .containsEntry("X-RateLimit-Limit", "20").containsEntry("X-RateLimit-Reset", "0");
        assertThat(ex.messageArgs()).containsExactly(1L);
        assertThat(RateLimitDecision.skipped().headers()).isEmpty();
        assertThat(RateLimitDecision.skipped().allowed()).isTrue();
        assertThat(RedisTokenBucketRateLimiter.seconds(1)).isEqualTo(1);
        assertThat(RedisTokenBucketRateLimiter.seconds(3000)).isEqualTo(3);
        assertThat(IpRateLimitPolicy.PUBLIC_API.bucket("1.2.3.4")).isEqualTo("public-api:ip:1.2.3.4");
    }

    @Test
    @DisplayName("신뢰 프록시(BFF)에서 온 X-Forwarded-For 첫 항목만 사용자 IP로 믿는다")
    void clientIp() {
        GatewayProperties trusting = new GatewayProperties();
        trusting.setTrustedProxies("10\\.244\\..*");
        ClientIpResolver resolver = new ClientIpResolver(trusting);
        assertThat(resolver.resolve(exchange("10.244.1.5", "203.0.113.7, 10.244.1.9"))).isEqualTo("203.0.113.7");
        assertThat(resolver.resolve(exchange("192.168.0.9", "203.0.113.7"))).isEqualTo("192.168.0.9");
        assertThat(resolver.resolve(exchange("10.244.1.5", "not-an-ip"))).isEqualTo("10.244.1.5");
        assertThat(resolver.resolve(exchange("10.244.1.5", null))).isEqualTo("10.244.1.5");

        ClientIpResolver none = new ClientIpResolver(new GatewayProperties());
        assertThat(none.resolve(exchange("10.244.1.5", "203.0.113.7"))).isEqualTo("10.244.1.5");
        assertThat(none.resolve(MockServerWebExchange.from(MockServerHttpRequest.get("/").build()))).isEqualTo("unknown");
    }

    private static MockServerWebExchange exchange(String remote, String xff) {
        MockServerHttpRequest.BaseBuilder<?> builder = MockServerHttpRequest.get("/")
                .remoteAddress(new InetSocketAddress(remote, 40000));
        if (xff != null) {
            builder.header("X-Forwarded-For", xff);
        }
        return MockServerWebExchange.from(builder.build());
    }
}
