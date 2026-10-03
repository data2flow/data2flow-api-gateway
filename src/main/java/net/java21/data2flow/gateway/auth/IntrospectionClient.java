package net.java21.data2flow.gateway.auth;

import io.netty.channel.ChannelOption;
import net.java21.data2flow.contracts.identity.DataflowHeaders;
import net.java21.data2flow.gateway.config.GatewayProperties;
import net.java21.data2flow.gateway.error.GatewayRejectedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * 인증 서비스에 토큰이 유효한지 묻는다(API-IAM-34, auth.md §5 4번). gateway는 JWT를 해석하지 않는다(IAM-07.02).
 *
 * <pre>
 * POST {services.auth}/internal/auth/introspect
 * Content-Type: application/x-www-form-urlencoded   본문 token=&lt;토큰 원문&gt;
 * X-REQUEST-ID: &lt;요청 ID&gt;, X-CALLER-SERVICE: data2flow-api-gateway, Accept: application/json
 * → 200 {"header":{"isSuccessful":true,…},"response":{active, sub, org, jti, sid, typ, tokenId, scopes, spaceScope, exp, inactiveReason}}
 * </pre>
 *
 * <p>비활성(active=false)은 정상 판정이다. 연결 실패, 시간 초과(연결 1초·응답 2초), 2xx가 아닌 응답(인증 서비스의 503 포함),
 * 계약에 맞지 않는 본문은 모두 503 {@code SERVICE_UNAVAILABLE}로 거절한다(fail-closed, IAM-07.10, BR-IAM-24).
 * 공통 머리({@code header})가 없는 본문도 받아들이고 최상위를 {@code response}로 본다.
 */
@Component
public class IntrospectionClient {

    private static final Logger log = LoggerFactory.getLogger(IntrospectionClient.class);
    private static final Pattern NUMERIC_ID = Pattern.compile("[0-9]{1,19}");

    private final WebClient webClient;
    private final ObjectMapper objectMapper;
    private final GatewayProperties properties;

    public IntrospectionClient(ObjectMapper objectMapper, GatewayProperties properties) {
        GatewayProperties.Introspection settings = properties.introspection();
        HttpClient httpClient = HttpClient.create()
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, (int) settings.connectTimeout().toMillis())
                .responseTimeout(settings.responseTimeout());
        this.webClient = WebClient.builder()
                .baseUrl(properties.services().auth())
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .build();
        this.objectMapper = objectMapper;
        this.properties = properties;
    }

    public Mono<IntrospectionResult> introspect(String token, String requestId) {
        GatewayProperties.Introspection settings = properties.introspection();
        return webClient.post()
                .uri(settings.path())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .accept(MediaType.APPLICATION_JSON)
                .headers(headers -> {
                    headers.set(DataflowHeaders.CALLER_SERVICE, IdentityHeaders.CALLER);
                    if (requestId != null) {
                        headers.set(DataflowHeaders.REQUEST_ID, requestId);
                    }
                })
                .body(BodyInserters.fromFormData("token", token))
                .retrieve()
                .bodyToMono(String.class)
                .switchIfEmpty(Mono.error(() -> new IllegalStateException("empty introspection body")))
                .map(this::parse)
                // 응답 타임아웃 위에 전체 상한을 한 번 더 둔다(연결 + 응답)
                .timeout(settings.connectTimeout().plus(settings.responseTimeout()).plus(Duration.ofMillis(500)))
                .onErrorMap(ex -> !(ex instanceof GatewayRejectedException), ex -> {
                    log.atWarn().addKeyValue("requestId", requestId)
                            .log("토큰 조회 실패, 503으로 거절합니다(fail-closed): {}", ex.getClass().getSimpleName());
                    return GatewayRejectedException.unavailable(properties.unavailableRetryAfter());
                });
    }

    IntrospectionResult parse(String body) {
        JsonNode root = objectMapper.readTree(body);
        JsonNode header = root.get("header");
        JsonNode node = root;
        if (header != null && !header.isNull()) {
            if (!header.path("isSuccessful").asBoolean(false)) {
                throw new IllegalStateException("introspection header not successful");
            }
            node = root.get("response");
        }
        if (node == null || !node.isObject() || !node.has("active")) {
            throw new IllegalStateException("non-contract introspection body");
        }
        if (!node.get("active").asBoolean(false)) {
            return IntrospectionResult.inactive(IntrospectionResult.InactiveReason.parse(text(node, "inactiveReason")));
        }
        String sub = text(node, "sub");
        String org = text(node, "org");
        if (sub == null || !NUMERIC_ID.matcher(sub).matches() || org == null || !NUMERIC_ID.matcher(org).matches()) {
            throw new IllegalStateException("active introspection without numeric sub/org");
        }
        String typ = text(node, "typ");
        Principal.TokenType type = typ == null ? Principal.TokenType.ACCESS : Principal.TokenType.valueOf(typ);
        String tokenId = text(node, "tokenId");
        if (type.longLived() && tokenId == null) {
            throw new IllegalStateException("long-lived token without tokenId");
        }
        return IntrospectionResult.active(new Principal(sub, org, type, text(node, "jti"), text(node, "sid"), tokenId,
                scopes(node.get("scopes")), number(node, "rateLimitPerMin"), number(node, "exp")));
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || value.isNull()) {
            return null;
        }
        String text = value.asString();
        return text == null || text.isBlank() ? null : text;
    }

    private static Long number(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || value.isNull()) {
            return null;
        }
        if (value.isNumber()) {
            return value.asLong();
        }
        String text = value.asString();
        return text != null && NUMERIC_ID.matcher(text).matches() ? Long.parseLong(text) : null;
    }

    /** 배열 또는 공백·쉼표로 구분한 문자열 */
    private static List<String> scopes(JsonNode value) {
        List<String> scopes = new ArrayList<>();
        if (value == null || value.isNull()) {
            return scopes;
        }
        if (value.isArray()) {
            value.forEach(item -> {
                String scope = item.asString();
                if (scope != null && !scope.isBlank()) {
                    scopes.add(scope.trim());
                }
            });
            return scopes;
        }
        for (String scope : value.asString().split("[\\s,]+")) {
            if (!scope.isBlank()) {
                scopes.add(scope);
            }
        }
        return scopes;
    }
}
