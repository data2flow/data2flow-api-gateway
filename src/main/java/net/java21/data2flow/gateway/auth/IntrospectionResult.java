package net.java21.data2flow.gateway.auth;

/**
 * 토큰 조회 판정. 활성이면 {@link #principal()}이 있고, 비활성이면 사유가 있다.
 *
 * @param principal      활성일 때의 신원
 * @param inactiveReason 비활성 사유(EXPIRED, REVOKED, INVALID). 모르는 값은 INVALID로 본다
 */
public record IntrospectionResult(Principal principal, InactiveReason inactiveReason) {

    public static IntrospectionResult active(Principal principal) {
        return new IntrospectionResult(principal, null);
    }

    public static IntrospectionResult inactive(InactiveReason reason) {
        return new IntrospectionResult(null, reason == null ? InactiveReason.INVALID : reason);
    }

    public boolean active() {
        return principal != null;
    }

    public enum InactiveReason {
        EXPIRED, REVOKED, INVALID;

        static InactiveReason parse(String value) {
            if (value == null) {
                return INVALID;
            }
            for (InactiveReason reason : values()) {
                if (reason.name().equalsIgnoreCase(value)) {
                    return reason;
                }
            }
            return INVALID;
        }
    }
}
