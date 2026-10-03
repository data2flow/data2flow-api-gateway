# data2flow-api-gateway

외부 요청 라우팅(/api/v1/{service}/** → stripPrefix(2)), 토큰 확인(introspection)과 신원 헤더 주입, 호출 한도. 외부 공개는 MCP 호스트만.

- 관련 스펙: IAM-07, NFR-03 (정본은 비공개 저장소 `data2flow-docs`)
- 패키지: `net.java21.data2flow.gateway` · Spring Boot 4.0.8 · Java 21 · Maven Wrapper
- 포트: API 8080, actuator 8081(프로브·지표 전용)

## 빌드와 실행

```bash
./mvnw verify                 # 단위·통합 테스트 + 커버리지 80% 검사
./mvnw spring-boot:run        # 로컬 실행(프로필 local)
```

공통 라이브러리 `data2flow-contracts`는 GitHub Packages에 있어서 읽기에도 토큰이 필요합니다. `~/.m2/settings.xml`에 서버 `github`(사용자 이름 + `read:packages` 권한 토큰)를 넣거나, `data2flow-contracts`를 받아 `./mvnw install`로 로컬 저장소에 설치합니다.

## 설정(환경변수)

| 환경변수 | 기본값 | 뜻 |
|---|---|---|
| `DATA2FLOW_AUTH_URI` / `DATA2FLOW_CORE_URI` / `DATA2FLOW_AI_URI` / `DATA2FLOW_MCP_URI` | `http://data2flow-auth` / `http://data2flow-core-api` / `http://data2flow-ai` / `http://data2flow-ai` | 라우트 대상(k8s Service) |
| `DATA2FLOW_MCP_HOST` | `data2flow-mcp.java21.net`(local은 비움) | 이 호스트에서는 `/mcp/**`만 받는다 |
| `DATA2FLOW_GATEWAY_TRUSTED_PROXIES` | 비움(아무도 믿지 않음) | `X-Forwarded-For`를 믿을 BFF·Ingress 파드 IP 정규식. 비우면 모든 사용자가 BFF IP 하나로 한도를 나눠 쓴다 |
| `DATA2FLOW_REDIS_HOST` / `_PORT` / `_USERNAME` / `_PASSWORD` / `_DATABASE` | `localhost`(staging·prod `10.116.64.14`) / `6379` / – / – / `0` | 호출 한도·폐기 목록·폐기 이벤트 |

정책 값(한도, 캐시 30초 등)은 `application.yml`의 `data2flow.gateway.*`에 있습니다.

## 작업 규칙

스펙 ID에서 시작하고(인수 테스트 → 테스트 케이스 → 구현), 브랜치·PR·테스트 이름에 스펙 ID를 남깁니다. 1.0 전에는 `main` + `feat/<스펙ID>-<요약>`, 1.0 뒤에는 버전 브랜치 `feature/vX.Y`를 씁니다(ADR-039).
