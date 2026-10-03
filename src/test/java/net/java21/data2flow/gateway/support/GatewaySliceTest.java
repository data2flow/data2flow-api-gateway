package net.java21.data2flow.gateway.support;

import net.java21.data2flow.gateway.auth.Principal;
import net.java21.data2flow.gateway.auth.RevocationEventListener;
import net.java21.data2flow.gateway.auth.RevocationStore;
import net.java21.data2flow.gateway.ratelimit.RateLimitDecision;
import net.java21.data2flow.gateway.ratelimit.RateLimiter;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import reactor.core.publisher.Mono;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;

/**
 * 슬라이스: gateway 필터 체인 전체를 WebTestClient로 부르고, Redis에 닿는 부분(호출 한도·폐기 목록·폐기 이벤트)은 목으로 바꾼다
 * (test-plan "MockMvc/WebTestClient, @MockitoBean"). 기본값은 "한도 여유, 폐기 안 됨".
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(GatewayTestSupport.ClockConfig.class)
public abstract class GatewaySliceTest extends GatewayTestSupport {

    @MockitoBean
    protected RateLimiter rateLimiter;

    @MockitoBean
    protected RevocationStore revocationStore;

    @MockitoBean
    protected RevocationEventListener revocationEventListener;

    @BeforeEach
    void defaultMocks() {
        given(rateLimiter.consume(anyString(), any())).willReturn(Mono.just(allowed(20, 19)));
        given(rateLimiter.checkFailures(anyString(), any())).willReturn(Mono.just(allowed(20, 20)));
        given(rateLimiter.recordFailure(anyString(), any())).willReturn(Mono.empty());
        given(revocationStore.isRevoked(any(Principal.class))).willReturn(Mono.just(false));
    }

    protected static RateLimitDecision allowed(long limit, long remaining) {
        return new RateLimitDecision(true, limit, remaining, 3, 0);
    }

    protected static RateLimitDecision exceeded(long limit, long retryAfter) {
        return new RateLimitDecision(false, limit, 0, retryAfter, retryAfter);
    }
}
