package net.java21.data2flow.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** data2flow-api-gateway: 외부 요청 라우팅(/api/v1/{service}/** → stripPrefix(2)), 토큰 확인(introspection)과 신원 헤더 주입, 호출 한도. 외부 공개는 MCP 호스트만 */
@SpringBootApplication
public class GatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }
}
