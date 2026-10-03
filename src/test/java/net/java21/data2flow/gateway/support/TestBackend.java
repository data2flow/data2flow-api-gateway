package net.java21.data2flow.gateway.support;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import okhttp3.mockwebserver.SocketPolicy;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 하위 서비스 대역(MockWebServer, design/testing/backend.md). 한 서버가 auth(토큰 조회)·core·ai·MCP를 모두 흉내 낸다.
 *
 * <ul>
 *   <li>{@code POST /internal/auth/introspect}: 등록한 토큰이면 그 판정, 아니면 {@code active:false, inactiveReason:INVALID}</li>
 *   <li>그 밖의 경로: 200 공통 성공 본문. 받은 요청은 {@link #downstreamRequests()}에 남는다</li>
 * </ul>
 * 테스트 사이에 공유하므로(스프링 컨텍스트 캐시) 각 테스트 앞에서 {@link #reset()}한다.
 */
public final class TestBackend {

    public static final String INTROSPECT_PATH = "/internal/auth/introspect";
    private static final String OK_BODY = "{\"header\":{\"isSuccessful\":true,\"resultCode\":\"SUCCESS\",\"resultMessage\":\"SUCCESS\"}}";

    private static final TestBackend INSTANCE = new TestBackend();

    private final MockWebServer server = new MockWebServer();
    private final Map<String, String> introspections = new ConcurrentHashMap<>();
    private final List<RecordedRequest> downstream = new CopyOnWriteArrayList<>();
    private final List<RecordedRequest> introspectRequests = new CopyOnWriteArrayList<>();
    private final AtomicReference<AuthMode> authMode = new AtomicReference<>(AuthMode.NORMAL);
    private final AtomicInteger downstreamStatus = new AtomicInteger(200);

    public enum AuthMode {
        NORMAL,
        /** 인증 서비스가 503을 준다(폐기 목록 저장소 장애 등, API-IAM-34) */
        UNAVAILABLE,
        /** 연결을 끊는다 */
        DISCONNECT,
        /** 계약에 맞지 않는 본문 */
        GARBAGE
    }

    private TestBackend() {
        server.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                if (INTROSPECT_PATH.equals(request.getPath())) {
                    introspectRequests.add(request);
                    return introspect(request);
                }
                downstream.add(request);
                return new MockResponse().setResponseCode(downstreamStatus.get())
                        .setHeader("Content-Type", "application/json").setBody(OK_BODY);
            }
        });
        try {
            server.start();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static TestBackend get() {
        return INSTANCE;
    }

    public String baseUrl() {
        return "http://localhost:" + server.getPort();
    }

    public void reset() {
        introspections.clear();
        downstream.clear();
        introspectRequests.clear();
        authMode.set(AuthMode.NORMAL);
        downstreamStatus.set(200);
    }

    public void authMode(AuthMode mode) {
        authMode.set(mode);
    }

    public void downstreamStatus(int status) {
        downstreamStatus.set(status);
    }

    /** 로그인 사용자 Access 토큰을 등록한다 */
    public String accessToken(String token, long userId, long orgId, String sid, String jti, long exp) {
        introspections.put(token, """
                {"header":{"isSuccessful":true,"resultCode":"SUCCESS","resultMessage":"SUCCESS"},
                 "response":{"active":true,"sub":"%d","org":"%d","jti":"%s","sid":"%s","typ":"ACCESS","exp":%d}}
                """.formatted(userId, orgId, jti, sid, exp));
        return token;
    }

    /** 장기 토큰(MCP) */
    public String mcpToken(String token, long userId, long orgId, String tokenId, String scopesJson, Long rateLimitPerMin) {
        introspections.put(token, """
                {"header":{"isSuccessful":true,"resultCode":"SUCCESS","resultMessage":"SUCCESS"},
                 "response":{"active":true,"sub":"%d","org":"%d","typ":"MCP","tokenId":"%s","scopes":%s%s}}
                """.formatted(userId, orgId, tokenId, scopesJson,
                rateLimitPerMin == null ? "" : ",\"rateLimitPerMin\":" + rateLimitPerMin));
        return token;
    }

    /** 비활성 판정(EXPIRED·REVOKED·INVALID) */
    public String inactiveToken(String token, String reason) {
        introspections.put(token, """
                {"header":{"isSuccessful":true,"resultCode":"SUCCESS","resultMessage":"SUCCESS"},
                 "response":{"active":false,"inactiveReason":"%s"}}
                """.formatted(reason));
        return token;
    }

    /** 공통 머리 없이 판정만 보내는 응답(호환) */
    public String rawResponse(String token, String json) {
        introspections.put(token, json);
        return token;
    }

    public List<RecordedRequest> downstreamRequests() {
        return List.copyOf(downstream);
    }

    public RecordedRequest lastDownstream() {
        if (downstream.isEmpty()) {
            throw new AssertionError("하위 서비스가 받은 요청이 없습니다");
        }
        return downstream.get(downstream.size() - 1);
    }

    public List<RecordedRequest> introspectRequests() {
        return List.copyOf(introspectRequests);
    }

    private MockResponse introspect(RecordedRequest request) {
        switch (authMode.get()) {
            case UNAVAILABLE -> {
                return new MockResponse().setResponseCode(503).setHeader("Content-Type", "application/json")
                        .setBody("{\"header\":{\"isSuccessful\":false,\"resultCode\":\"SERVICE_UNAVAILABLE\",\"resultMessage\":\"x\"}}");
            }
            case DISCONNECT -> {
                return new MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AT_START);
            }
            case GARBAGE -> {
                return new MockResponse().setHeader("Content-Type", "application/json").setBody("{\"unexpected\":1}");
            }
            default -> {
                // NORMAL은 아래로
            }
        }
        String form = request.getBody().readUtf8();
        String token = null;
        for (String pair : form.split("&")) {
            if (pair.startsWith("token=")) {
                token = URLDecoder.decode(pair.substring(6), StandardCharsets.UTF_8);
            }
        }
        String body = token == null ? null : introspections.get(token);
        if (body == null) {
            body = """
                    {"header":{"isSuccessful":true,"resultCode":"SUCCESS","resultMessage":"SUCCESS"},
                     "response":{"active":false,"inactiveReason":"INVALID"}}
                    """;
        }
        return new MockResponse().setHeader("Content-Type", "application/json").setBody(body);
    }
}
