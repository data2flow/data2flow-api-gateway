package net.java21.data2flow.gateway.auth;

import java.util.List;

/**
 * 토큰 조회(introspection)로 확인한 신원. 하위 서비스 헤더와 폐기·한도 판정에 필요한 값만 담는다.
 *
 * @param userId          사용자 ID(sub) → {@code X-USER-ID}
 * @param orgId           조직 ID(org) → {@code X-ORG-ID}
 * @param type            토큰 종류(ACCESS, API_KEY, MCP)
 * @param jti             Access 토큰 ID(폐기 목록 {@code bl:at:{jti}})
 * @param sid             로그인 세션 ID(폐기 목록 {@code bl:sid:{sid}})
 * @param tokenId         장기 토큰 ID → {@code X-ACCESS-TOKEN-ID}
 * @param scopes          장기 토큰 범위 → {@code X-TOKEN-SCOPE}
 * @param rateLimitPerMin 장기 토큰의 분당 한도(IAM-05.04). 없으면 기본값
 * @param expEpochSeconds 만료 시각(캐시 수명 상한)
 */
public record Principal(String userId, String orgId, TokenType type, String jti, String sid, String tokenId,
                        List<String> scopes, Long rateLimitPerMin, Long expEpochSeconds) {

    public Principal {
        scopes = scopes == null ? List.of() : List.copyOf(scopes);
    }

    public boolean longLived() {
        return type.longLived();
    }

    /** 토큰 종류(API-IAM-34 {@code typ}) */
    public enum TokenType {
        ACCESS, API_KEY, MCP;

        /** MCP·API 키처럼 사람이 아닌 프로그램이 쓰는 장기 토큰인가(auth.md §4) */
        public boolean longLived() {
            return this != ACCESS;
        }
    }
}
