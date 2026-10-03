package net.java21.data2flow.gateway.error;

import net.java21.data2flow.contracts.error.ErrorCode;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.text.MessageFormat;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

/**
 * gateway가 직접 거절할 때의 {@code resultMessage}를 Accept-Language(ko·en·ja·zh)로 찾는다(api-rules §3.1, ADR-037).
 *
 * <p>문구 원천은 data2flow-contracts의 공통 번들({@code data2flow/contracts/messages_*.properties}, 키 {@code error.<코드>})이다.
 * gateway는 새 코드나 새 문구를 만들지 않는다(api-rules §4.4). 기동할 때 4개 언어를 메모리에 올려 두고, 요청 처리(이벤트 루프)에서는
 * 조회만 한다. 없는 문구는 ja·zh → en → ko 순서로 찾고(ADR-037), 그래도 없으면 코드 자체를 돌려준다.
 */
@Component
public class GatewayMessages {

    static final List<String> LANGUAGES = List.of("ko", "en", "ja", "zh");
    static final String DEFAULT_LANGUAGE = "ko";
    private static final String BUNDLE = "data2flow/contracts/messages_%s.properties";

    private final Map<String, Properties> bundles = new HashMap<>();

    public GatewayMessages() {
        for (String language : LANGUAGES) {
            bundles.put(language, load(BUNDLE.formatted(language)));
        }
    }

    /**
     * @param code           오류 코드
     * @param acceptLanguage 요청의 Accept-Language 헤더(없으면 null)
     * @param args           문구 자리표시자 {0}… 값
     */
    public String resolve(ErrorCode code, String acceptLanguage, Object... args) {
        String language = language(acceptLanguage);
        for (String candidate : fallbackChain(language)) {
            String pattern = bundles.get(candidate).getProperty(code.messageKey());
            if (pattern != null) {
                return args.length == 0 ? pattern : new MessageFormat(pattern, Locale.of(candidate)).format(args);
            }
        }
        return code.code();
    }

    /** 첫 번째로 지원하는 언어. q값은 보지 않고 적힌 순서대로 본다. zh-Hans·zh-TW 등은 모두 zh */
    static String language(String header) {
        if (header == null || header.isBlank()) {
            return DEFAULT_LANGUAGE;
        }
        for (String part : header.split(",")) {
            String primary = part.split(";")[0].trim().toLowerCase(Locale.ROOT).split("[-_]")[0];
            if (LANGUAGES.contains(primary)) {
                return primary;
            }
        }
        return DEFAULT_LANGUAGE;
    }

    private static List<String> fallbackChain(String language) {
        return switch (language) {
            case "ja", "zh" -> List.of(language, "en", "ko");
            case "en" -> List.of("en", "ko");
            default -> List.of("ko");
        };
    }

    private static Properties load(String path) {
        Properties properties = new Properties();
        try (InputStream stream = GatewayMessages.class.getClassLoader().getResourceAsStream(path)) {
            if (stream != null) {
                properties.load(new InputStreamReader(stream, StandardCharsets.UTF_8));
            }
        } catch (IOException e) {
            throw new IllegalStateException(path + " 읽기 실패", e);
        }
        return properties;
    }
}
