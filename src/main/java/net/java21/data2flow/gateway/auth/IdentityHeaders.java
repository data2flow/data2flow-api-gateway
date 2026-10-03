package net.java21.data2flow.gateway.auth;

/** gateway가 하위 서비스로 갈 때 붙이는 호출자 표시({@code X-CALLER-SERVICE}, ADR-021, 인증 수단 아님) */
public final class IdentityHeaders {

    public static final String CALLER = "data2flow-api-gateway";

    private IdentityHeaders() {
    }
}
