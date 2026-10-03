package net.java21.data2flow.gateway.error;

import net.java21.data2flow.contracts.error.CommonErrorCode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

/** OPS-12.01 resultMessage 현지화(ADR-037) */
class GatewayMessagesTest {

    private final GatewayMessages messages = new GatewayMessages();

    @ParameterizedTest(name = "\"{0}\" → {1}")
    @CsvSource(nullValues = "NULL", value = {
            "NULL, ko", "'', ko", "en, en", "en-US;q=0.9, en", "ja-JP, ja", "zh-TW, zh", "zh_Hans, zh",
            "'fr-FR, de;q=0.8, ja;q=0.5', ja", "fr, ko"})
    @DisplayName("Accept-Language에서 지원 언어 하나를 고른다")
    void language(String header, String expected) {
        assertThat(GatewayMessages.language(header)).isEqualTo(expected);
    }

    @Test
    @DisplayName("자리표시자를 채우고, 모르는 코드는 코드 자체를 돌려준다")
    void resolve() {
        assertThat(messages.resolve(CommonErrorCode.RATE_LIMITED, "ko", 3L)).isEqualTo("요청이 너무 많습니다. 3초 후 다시 시도해 주세요");
        assertThat(messages.resolve(CommonErrorCode.PERMISSION_DENIED, "en")).isEqualTo("You do not have permission to do this");
        assertThat(messages.resolve(new net.java21.data2flow.contracts.error.ErrorCode() {
            public String code() {
                return "NOPE_CODE";
            }

            public int httpStatus() {
                return 400;
            }
        }, "ja")).isEqualTo("NOPE_CODE");
    }
}
