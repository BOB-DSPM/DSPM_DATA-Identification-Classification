# Data Identification & Classification Analyzer

> 개인정보 및 민감정보를 자동으로 **식별하고 분류**하는 분석기입니다.  
> 다양한 데이터 소스에서 수집한 텍스트·CSV·JSON 등을 분석해 결과를 민감도 수준별로 저장합니다.

---

## 🚀 개요

이 Analyzer는 **AI 기반 PII 탐지 모델**과 룰 기반 패턴 매칭을 결합하여 **한국형 데이터 환경**에서의 개인정보 탐지 품질을 극대화했습니다.  
분석 결과는 개인정보보호법 기준(개인정보·민감정보·고유식별정보)에 맞게 분류됩니다.

---

## 🧠 개인정보 식별 주요 기능

- **AI 기반 탐지 엔진**: 토큰 분류 기반 딥러닝 모델로 문맥을 고려한 정확한 PII 탐지
- **하이브리드 방식**: AI 탐지 + 룰 기반 정규식 병합으로 높은 재현율(Recall) 보장
- **법 기준 분류**: 개인정보보호법에 따른 **개인정보 / 민감정보 / 고유식별정보** 자동 분류 및 저장
- **클라우드 분석**: AWS 상의 데이터 분석 가능
- **정책 기반 설정**: `config/detector.yaml`로 탐지 기준·민감도·예외 규칙 구성
- **가상환경 권장 실행**: Python venv 기반 실행 가이드 제공
- **실시간 탐지 로그**: AI 탐지 과정 및 결과를 상세하게 출력

---

## 🤖 AI 기반 탐지 엔진

### 모델 정보
- **모델 URL**: `http://211.44.183.248:8900/infer`
- **방식**: 토큰 분류(Token Classification) 기반 NER
- **지원 라벨**: NAME, PHONE, EMAIL, ADDRESS, DOB, RRN_KR
- **특징**:
  - 문맥 기반 탐지 (단순 패턴 매칭보다 정확)
  - 신뢰도 점수(confidence score) 제공
  - 한국어/영어 혼용 텍스트 지원

### 동작 방식
```
1. 룰 기반 스캔 (정규식)
   ↓
2. AI 모델 스캔 (딥러닝)
   ↓
3. 결과 병합 및 중복 제거
   ↓
4. 분류 및 저장 (public/sensitive/identifiers)
```

**AI 실패 시**: 룰 기반 결과만 사용 (최소 탐지 보장)

---

## 🔎 식별 가능한 정보 유형

| 분류 | AI 라벨 | 내부 엔티티 | 예시 |
|------|---------|-------------|------|
| **이름** | `NAME`, `B-NAME`, `I-NAME` | `KR_NAME` | `홍길동`, `John Doe` |
| **전화번호** | `PHONE`, `B-PHONE`, `I-PHONE` | `PHONE_NUMBER` | `010-1234-5678`, `+82-10-1234-5678` |
| **이메일** | `EMAIL`, `B-EMAIL`, `I-EMAIL` | `EMAIL_ADDRESS` | `example@domain.com` |
| **주소** | `ADDRESS`, `B-ADDRESS`, `I-ADDRESS` | `KOREAN_ADDRESS` | `서울특별시 강남구 테헤란로 123` |
| **생년월일** | `DOB`, `B-DOB`, `I-DOB` | `DATE_OF_BIRTH` | `1990-01-01`, `19900101` |
| **주민등록번호** | `RRN_KR`, `B-RRN_KR`, `I-RRN_KR` | `KR_RRN` | `900101-1234567` |
| **금융정보** | (룰 기반) | `CREDIT_CARD`, `KR_BANK_ACCOUNT` | `1234-5678-9012-3456` |
| **고유식별정보** | (룰 기반) | `KR_PASSPORT`, `KR_DRIVER_LICENSE` | `M12345678` |

### 추가 식별 정보 (룰 기반 + Lexicon)
| 분류 | 세부 유형 | 예시 |
|------|------------|------|
| **정치적 견해** | PIPA 민감정보 | `보수`, `진보`, `정당` |
| **신념·종교** | PIPA 민감정보 | `불교`, `기독교`, `무신론` |
| **노동조합** | PIPA 민감정보 | `노조`, `조합원`, `파업` |
| **건강정보** | PIPA 민감정보 | `당뇨`, `고혈압`, `우울증` |
| **성생활 정보** | PIPA 민감정보 | `성적 지향`, `임신` |

> AI 모델이 주요 개인정보를 탐지하고, 룰 기반이 보완 및 추가 패턴을 처리합니다.

---

# DSPM Analyzer — Install & Run (Tested Command Guide)

---

## 0) 요구 사항
- Python 3.10+ (권장 3.11)
- OS: macOS / Linux / Windows
- **AI PII 모델 서버**: `http://211.44.183.248:8900/infer` (접근 가능해야 함)

---

## 1) 설치

```bash
# 1) 레포 클론
git clone --branch analyzer --single-branch https://github.com/BOB-DSPM/DSPM_DATA-Identification-Classification.git DSPM_DATA-IC-analyzer
cd DSPM_DATA-IC-analyzer

# 2) 가상환경 생성 및 활성화
python3 -m venv .venv
# Windows
.\.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate

# 3) 필수 패키지 설치
cd dspm-analyzer
pip install -r requirements.txt
pip install fastapi uvicorn[standard]
```

> `requirements.txt`에는 Presidio/kiwipiepy/spaCy만 포함되어 있어 **FastAPI/uvicorn은 별도 설치**가 필요합니다.

선택(한국어 토큰 품질):
```bash
pip install presidio-analyzer presidio-anonymizer
python -m spacy download ko_core_news_sm
```

---

## 2) 샘플 분석(배치) — 결과 파일 생성

`main.py`의 출력 파일을 **`var/results/`** 아래로 지정하면, `server.py`의 API들이 바로 읽을 수 있습니다.

```bash
# 샘플 입력 생성
cat > sample_payload.json << 'JSON'
[
  {
    "key": "s3/my-bucket/sample-dir/doc-001.txt",
    "content": { "text": "홍길동 010-1234-5678, 이메일 test@example.com, 주민등록번호 900101-1234567" }
  },
  {
    "key": "s3/my-bucket/sample-dir/customers.csv",
    "content": { "text": "name,phone,email\n이순신,010-9876-5432,lee@example.com" }
  }
]
JSON

# 분석 실행 (AI 자동 활성화)
python main.py -i sample_payload.json -o var/results/results.json
```

### 예상 로그 출력 (AI 탐지 과정)

```bash
[AI] 평문 분석 중: s3/my-bucket/sample-dir/doc-001.txt
================================================================================
[AI 분석 완료] 총 5건 탐지 (NAME:1, PHONE:1, EMAIL:1, RRN_KR:1, ADDRESS:1)
원본 텍스트: '홍길동 010-1234-5678, 이메일 test@example.com, 주민등록번호 900101-...'
--------------------------------------------------------------------------------
  [1] NAME
      탐지값: '홍길동'
      신뢰도: 0.96
      위치: 0~3
      컨텍스트: ...[홍길동] 010-1234-5678...
  [2] PHONE
      탐지값: '010-1234-5678'
      신뢰도: 0.94
      위치: 4~17
      컨텍스트: ...홍길동 [010-1234-5678], 이메일...
================================================================================
```

성공 시 생성되는 핵심 파일(일부):
```
var/results/
 ├─ results.json                 # 전체 리포트 (AI 결과 포함)
 ├─ results_front.json           # 서버(front) 전용 목록
 ├─ results_front_by_source.json # 소스별 요약
 ├─ results.console.txt          # 콘솔 출력 사본
 └─ classified/…                 # 엔티티별 텍스트 저장
```

---

## 3) 서버 실행(FastAPI)

```bash
# FastAPI 서버 기동 (server.py의 app 사용)
# DSPM_DATA-ID-analyzer 디렉터리 안에서
uvicorn server:app --host 0.0.0.0 --port 9000
```

브라우저/도구에서 확인:
- API 문서: http://localhost:9000/docs  
- 헬스체크: 
  ```bash
  curl http://localhost:9000/health
  ```
- 요약 통계:
  ```bash
  curl "http://localhost:9000/api/result/front-stats" | jq .
  ```
- 리스트(기본 20개 페이징):
  ```bash
  curl "http://localhost:9000/api/result/front-list" | jq .
  ```

> 위 호출들이 정상 동작하려면 **2) 단계에서 `var/results/results_front.json`이 생성**되어 있어야 합니다.

---

## 🇰🇷 한국어 자연어처리 모델 (선택)

한국어 텍스트 분석 품질 향상을 위해 spaCy 기반 토큰화를 사용할 수 있습니다.

### 🔹 공식 spaCy 커뮤니티 모델 (소형)
```bash
python -m spacy download ko_core_news_sm
```

> 대용량 모델(`ko_core_news_lg`)은 더 정교한 토큰화를 제공하지만, 설치 용량이 큽니다.

---

## ▶️ 개인정보 식별 명령어 사용법

### 로컬 파일 분석 (AI 자동 적용)
```bash
python main.py -i sample_payload.json -o results.json
```

### AWS S3 수집 + 분석 (AI 자동 적용)
```bash
python connectors/aws_http/run_collect_and_scan.py --api http://192.168.0.10:8000 --out results_all.json 
```

### 결과 저장 위치
```
classified/public/         # 일반 개인정보 (이름, 전화번호, 이메일 등)
classified/sensitive/      # 민감정보 (건강, 정치, 종교 등)
classified/identifiers/    # 고유식별정보 (주민번호, 여권번호 등)
```

---

## ⚙️ 환경 변수

| 변수명 | 설명 | 기본값 |
|--------|------|--------|
| `TREAT_CREDIT_CARD_AS_SENSITIVE` | 신용카드 번호를 민감정보로 처리 | `0` |
| `DEBUG_UNMASK` | 콘솔 출력 마스킹 해제 | `0` |
| `ONLY_DETECTED` | 탐지된 항목만 출력 | `0` |

---

## 🧭 server.py 전체 주요 기능 

- Collector 자동 호출 (`/api/collect`)
- 개인정보 탐지 결과 요약 (`results_front.json`)
- 리소스 단위 / 민감도 단위별 API 제공
- 통계(탐지율, 카테고리 분포, 엔티티 순위)
- CSV / JSONL 내보내기 지원
- **AI 탐지 결과 포함** (`ai_hits` 필드)

---

## 🧪 API 테스트 명령어

> FastAPI 서버(`server.py`)가 실행 중이어야 합니다.  
> Collector(`{COLLECTOR_API}`)는 예시로 `http://192.168.0.10:8000` 을 사용합니다.  
> 기본 포트는 `9000`입니다.

### API 실행 방법

```bash
# FastAPI 실행
uvicorn server:app --host 0.0.0.0 --port 9000
```

### 수집·분석 실행 (전체 리소스, AI 자동 적용)

```bash
curl -sS -X POST http://{SERVER_HOST}:9000/api/collect \
  -H 'Content-Type: application/json' \
  -d '{
    "collector_api": "{COLLECTOR_API}",
    "only_detected": true
  }' | jq .
```

✅ 기대 응답:
```json
{
  "ok": true,
  "returncode": 0,
  "results_front": "/.../var/results/results_front.json"
}
```

### 결과 파일 생성 확인

```bash
ls -lh var/results/
stat -c "mtime: %y  size: %s" var/results/results_front.json
```

### API로 데이터 확인 

```bash
# 통계/요약 (AI 탐지 결과 포함)
curl -sS http://{SERVER_HOST}:9000/api/result/front-stats | jq .

# 카테고리 분포
curl -sS http://{SERVER_HOST}:9000/api/result/category-counts | jq .

# 전체 리스트(무필터)
curl -sS 'http://{SERVER_HOST}:9000/api/result/front-list?page=1&size=20' | jq .

# 식별된 항목만
curl -sS 'http://{SERVER_HOST}:9000/api/result/front-list?has_entities=yes&page=1&size=20' | jq .

# 특정 카테고리
curl -sS 'http://{SERVER_HOST}:9000/api/result/front-category/{CATEGORY}?has_entities=any&page=1&size=20' | jq .

# 특정 리소스
curl -sS 'http://{SERVER_HOST}:9000/api/result/front-source/{SOURCE}?page=1&size=20' | jq .

# 상세 (AI 탐지 결과 확인)
RID=$(curl -sS 'http://{SERVER_HOST}:9000/api/result/front-list?page=1&size=1' | jq -r '.items[0].id')
curl -sS "http://{SERVER_HOST}:9000/api/result/front/${RID}" | jq .
# → .ai_hits 필드에서 AI가 탐지한 원본 데이터 확인 가능

# 내보내기 (CSV/JSONL)
curl -sS -L -o results_front.csv  'http://{SERVER_HOST}:9000/api/result/front/export?format=csv&has_entities=any'
curl -sS -L -o results_front.jsonl 'http://{SERVER_HOST}:9000/api/result/front/export?format=jsonl&category=public'
```

### 리소스(=source) 단위 요약 확인

```bash
ls -lh var/results/results_front_by_source.json || echo "source 요약 파일 없음"
curl -sS http://{SERVER_HOST}:9000/api/result/source-summary | jq .
curl -sS 'http://{SERVER_HOST}:9000/api/result/source/{SOURCE}/entities' | jq .
```

---

## 🎯 API 구조 요약

| 구분 | 사용 API | 설명 |
|------|-----------|------|
| **리소스별 보기** | `/api/result/source-summary`, `/api/result/source/{source}/entities` | 리소스 단위로 개인정보 현황 확인 |
| **민감도별 보기** | `/api/result/front-category/{category}` | 민감도(public/sensitive/identifiers)별로 구분 |
| **전체 리스트** | `/api/result/front-list?has_entities=any` | 전체 오브젝트 탐색 |
| **상세** | `/api/result/front/{id}` | 파일/오브젝트 상세 보기 (AI 결과 포함) |
| **통계/요약** | `/api/result/front-stats` | 탐지율, 분포, 전체 엔티티 순위 |
| **전체 엔티티 분포** | `front-stats.all_entities` | 모든 엔티티 타입을 많이 나온 순으로 표시 |

---

## 📊 주요 응답 예시

### `/api/result/front-stats`

```json
{
  "total_objects": 120,
  "detected_objects": 35,
  "detection_rate": 29.1,
  "category_distribution": {"public":10,"sensitive":3,"identifiers":1,"none":109},
  "type_distribution": {"text/plain":120,"text/csv":3},
  "top_entities": [["EMAIL_ADDRESS",40],["PHONE_NUMBER",20]],
  "all_entities": [
    ["EMAIL_ADDRESS",40],
    ["PHONE_NUMBER",20],
    ["KR_NAME",15],
    ["KR_RRN",8],
    ["ICD10_CODE",5]
  ]
}
```

### `/api/result/front/{id}` (AI 결과 포함)

```json
{
  "file": "s3/my-bucket/doc-001.txt",
  "type": "text/plain",
  "category": "public",
  "entities": {
    "KR_NAME": {"count": 1, "values": ["홍길동"]},
    "PHONE_NUMBER": {"count": 1, "values": ["010-1234-5678"]},
    "EMAIL_ADDRESS": {"count": 1, "values": ["test@example.com"]}
  },
  "ai_hits": [
    {"entity": "NAME", "text": "홍길동", "score": 0.96},
    {"entity": "PHONE", "text": "010-1234-5678", "score": 0.94},
    {"entity": "EMAIL", "text": "test@example.com", "score": 0.98}
  ]
}
```

---

## 🧠 개념 요약

### 🔹 하이브리드 탐지 방식
> "AI + 룰 기반 병합으로 높은 정확도와 재현율 달성"

- **AI 탐지**: 문맥 기반 정확한 PII 인식
- **룰 기반**: 정규식으로 누락 방지 및 보완
- **병합**: 두 결과를 합쳐 최종 결과 생성

### 🔹 리소스 기반 뷰
> "어떤 리소스(S3, RDS, ECR 등)에서 개인정보가 나왔는가?"

- `/api/result/source-summary`
- `/api/result/source/{source}/entities`

### 🔹 민감도 기반 뷰
> "공개/민감/고유식별 정보 중 어디에 해당하는가?"

- `/api/result/front-category/{category}`

### 🔹 엔티티 기반 뷰
> "가장 많이 탐지된 개인정보 유형은 무엇인가?"

- `/api/result/front-stats` (`all_entities` 활용)

---

## 🔧 트러블슈팅

### AI 서버 연결 실패
```bash
[engine_pii] AI 분석 실패 (연결 오류): Connection refused
```

**해결 방법**:
1. AI 서버 상태 확인: `curl http://211.44.183.248:8900/health`
2. 네트워크 방화벽 확인
3. AI 서버가 다운되어도 룰 기반 탐지는 정상 작동

### AI 탐지 결과가 없음
```bash
[AI 분석 완료] 텍스트: '...' → PII 없음
```

**원인**: 
- 실제로 개인정보가 없는 경우
- AI 모델이 인식하지 못한 패턴 (룰 기반이 보완)

---

## 🧾 License

© 2025 AEGIS DSPM Project. All rights reserved.