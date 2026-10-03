package net.java21.data2flow.gateway.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/**
 * 공통 빈. 캐시 수명·한도 계산은 이 {@link Clock}을 따른다(테스트는 MutableClock으로 바꾼다, design/testing §3).
 */
@Configuration
@EnableConfigurationProperties(GatewayProperties.class)
public class GatewayConfig {

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }
}
