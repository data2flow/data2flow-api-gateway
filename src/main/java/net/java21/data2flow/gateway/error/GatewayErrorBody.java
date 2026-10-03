package net.java21.data2flow.gateway.error;

import net.java21.data2flow.contracts.web.ApiHeader;

/**
 * gateway가 직접 내보내는 실패 본문 {@code {"header":{isSuccessful,resultCode,resultMessage}}}(api-rules §4.1).
 * 실패에는 {@code response}가 없으므로 필드 자체를 두지 않는다(api-rules §3.2, null로 보내지 않음).
 */
public record GatewayErrorBody(ApiHeader header) {

    public static GatewayErrorBody of(String resultCode, String resultMessage) {
        return new GatewayErrorBody(ApiHeader.failure(resultCode, resultMessage));
    }
}
