package net.java21.data2flow.gateway;

import net.java21.data2flow.contracts.web.ContractsWebAutoConfiguration;
import net.java21.data2flow.gateway.support.GatewaySliceTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.web.server.WebFilter;

import static org.assertj.core.api.Assertions.assertThat;

/** data2flow-contracts의 서블릿 자동 구성은 리액티브 gateway에서 켜지지 않는다(상수·오류 코드·한도 헤더만 쓴다) */
class ContractsCompatibilityTest extends GatewaySliceTest {

    @Autowired
    ApplicationContext context;

    @Test
    @DisplayName("contracts 서블릿 자동 구성(필터·예외 처리기·LocaleResolver)이 없다")
    void servletAutoConfigurationInactive() {
        assertThat(context.getBeanNamesForType(ContractsWebAutoConfiguration.class)).isEmpty();
        assertThat(context.containsBean("data2flowRequestIdFilter")).isFalse();
        assertThat(context.containsBean("data2flowGlobalExceptionHandler")).isFalse();
        assertThat(context.getBeansOfType(WebFilter.class).keySet())
                .noneMatch(name -> name.toLowerCase().contains("contracts"));
    }
}
