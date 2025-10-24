# Data Identification & Classification Analyzer

> 개인정보 및 민감정보를 자동으로 **식별하고 분류**하는 분석기입니다.  
> 다양한 데이터 소스에서 수집한 텍스트·CSV·JSON 등을 분석해 결과를 민감도 수준별로 저장합니다.

---

## 🚀 개요

이 Analyzer는 Microsoft Presidio와 커스텀 Recognizer, 정규식, 한국어 사전(lexicon)을 결합해 **한국형 데이터 환경**에서의 개인정보 탐지 품질을 높였습니다.  
분석 결과는 개인정보보호법 기준(개인정보·민감정보·고유식별정보)에 맞게 분류됩니다.

---

## 🧠 개인정보 식별 주요 기능

- **개인정보 탐지 엔진**: 정규식 + 사전(lexicon) + 커스텀 인식기 기반 탐지
- **법 기준 분류**: 개인정보보호법에 따른 **개인정보 / 민감정보 / 고유식별정보** 자동 분류 및 저장
- **클라우드 분석**: AWS 상의 데이터 분석 가능
- **정책 기반 설정**: `config/detector.yaml`로 탐지 기준·민감도·예외 규칙 구성
- **가상환경 권장 실행**: Python venv 기반 실행 가이드 제공
- *(선택/향후)* **NER 확장**: `hf_ner_recognizer.py` 사용 시 문맥 기반 인식 강화 가능

---

## 🔎 식별 가능한 정보 유형

| 분류 | 세부 유형 | 예시 |
|------|------------|------|
| **전자메일(E-mail)** | 이메일 주소 | `example@domain.com` |
| **전화번호(Phone Number)** | 국내 전화번호 | `010-1234-5678`, `+82-10-1234-5678` |
| **주민등록번호(Resident Registration Number)** | 대한민국 RRN 패턴 | `900101-1234567` |
| **이름(Name)** | 인명 정보 | `홍길동`, `John Doe` |
| **금융정보(Bank Account / Card)** | 은행계좌번호, 신용카드번호 | `110-123-456789`, `1234-5678-9012-3456` |
| **주소(Address)** | 시·도·구·동 주소·도로명 | `서울특별시 강남구 테헤란로 123` |
| **정치적 견해(Political Opinion)** | 정치 관련 단어·표현 | `보수`, `진보`, `정당`, `국회의원` |
| **신념·종교(Belief / Religion)** | 종교·철학적 신념 | `불교`, `기독교`, `무신론` |
| **노동조합(Union Membership)** | 노동조합 관련 단어·문맥 | `노조`, `조합원`, `파업` |
| **건강정보(Health Information)** | 질병명·진단·신체상태 | `당뇨`, `고혈압`, `우울증`, `진단서` |
| **성생활 정보(Sex Life Information)** | 성적 지향·행동 | `동성애`, `불임` |
| **고유식별정보(Unique Identifier)** | 여권번호·운전면허번호 등 | `M12345678`, `11-12-345678-90` |
| **기타 식별정보(Other Identifiers)** | Presidio에서 지원하는 데이터 | |

> 위 범위는 Presidio 기본 엔티티 + 한국형 커스텀 인식기 + Lexicon 기반 탐지를 모두 포함합니다.

---

# DSPM Analyzer — Install & Run (Tested Command Guide)

---

## 0) 요구 사항
- Python 3.10+ (권장 3.11)
- OS: macOS / Linux / Windows

---

## 1) 설치

```bash
# 1) 레포 클론
git clone https://github.com/BOB-DSPM/DSPM_DATA-Identification-Classification.git
cd DSPM_DATA-Identification-Classification

# 2) 가상환경 생성 및 활성화
python3 -m venv .venv
# Windows
.\.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate

# 3) 필수 패키지 설치
#   - 제공된 requirements.txt + FastAPI/uvicorn(서버 실행에 필수)
pip install -r requirements.txt
pip install fastapi uvicorn[standard]
```

> `requirements.txt`에는 Presidio/kiwipiepy/spaCy만 포함되어 있어 **FastAPI/uvicorn은 별도 설치**가 필요합니다.

선택(한국어 토큰 품질 및 Presidio 사용):
```bash
pip install presidio-analyzer presidio-anonymizer  # (requirements.txt에 이미 명시됨: 재설치 무방)
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
    "content": { "text": "name,phone,email\\n이순신,010-9876-5432,lee@example.com" }
  }
]
JSON

# 분석 실행 (결과를 var/results 아래로 저장)
python main.py -i sample_payload.json -o var/results/results.json
```

성공 시 생성되는 핵심 파일(일부):
```
var/results/
 ├─ results.json                 # 전체 리포트
 ├─ results_front.json           # 서버(front) 전용 목록
 ├─ results_front_by_source.json # 소스별 요약
 ├─ results.console.txt          # 콘솔 출력 사본
 └─ classified/…                 # 엔티티별 텍스트 저장
```

---

## 3) 서버 실행(FastAPI)

```bash
# FastAPI 서버 기동 (server.py의 app 사용)
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

## 🇰🇷 한국어 자연어처리 모델

한국어 텍스트 분석 품질 향상을 위해 spaCy 또는 KoNLPy 기반 토큰화를 사용할 수 있습니다.

### 🔹 KoNLPy 기반 한국어 토큰 지원용
```bash
pip install ko_spacy
python -m spacy download ko_core_news_sm
```

또는

### 🔹 공식 spaCy 커뮤니티 모델 (소형)
```bash
python -m spacy download ko_core_news_sm
```

> 대용량 모델(`ko_core_news_lg`)은 더 정교한 토큰화를 제공하지만, 설치 용량이 큽니다.

---

## ▶️ 개인정보 식별 명령어 사용법

### 로컬 파일 분석
```bash
python main.py -i sample_payload.json -o results.json
```

### AWS S3 수집 + 분석
```bash
python connectors/aws_http/run_collect_and_scan.py --api http://192.168.0.10:8000 --out results_all.json 
```

### 결과 저장 위치
```
classified/public/
classified/sensitive/
classified/identifiers/
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

### 수집·분석 실행 (전체 리소스)

```bash
curl -sS -X POST http://{SERVER_HOST}:9000/api/collect   -H 'Content-Type: application/json'   -d '{
        "collector_api":"{COLLECTOR_API}",
        "only_detected":true
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
# 통계/요약
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

# 상세
RID=$(curl -sS 'http://{SERVER_HOST}:9000/api/result/front-list?page=1&size=1' | jq -r '.items[0].id')
curl -sS "http://{SERVER_HOST}:9000/api/result/front/${RID}" | jq .

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
| **상세** | `/api/result/front/{id}` | 파일/오브젝트 상세 보기 |
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
    ["KR_RRN",8],
    ["ICD10_CODE",5]
  ]
}
```

---

## 🧠 개념 요약

### 🔹 리소스 기반 뷰
> “어떤 리소스(S3, RDS, ECR 등)에서 개인정보가 나왔는가?”

- `/api/result/source-summary`
- `/api/result/source/{source}/entities`

### 🔹 민감도 기반 뷰
> “공개/민감/고유식별 정보 중 어디에 해당하는가?”

- `/api/result/front-category/{category}`

### 🔹 엔티티 기반 뷰
> “가장 많이 탐지된 개인정보 유형은 무엇인가?”

- `/api/result/front-stats` (`all_entities` 활용)

---

## 🧾 License

© 2025 AEGIS DSPM Project. All rights reserved. 
