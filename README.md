# DSPM Data Identification & Classification

AWS 환경의 개인정보 및 민감정보를 자동으로 식별하고 분류하는 AI 기반 분석 도구입니다.

## 주요 기능

- **AI + 룰 기반 하이브리드 탐지**: 딥러닝 모델과 정규식을 결합한 높은 정확도
- **개인정보보호법 준수**: 개인정보/민감정보/고유식별정보 자동 분류
- **AWS 데이터 소스 지원**: S3, RDS, DynamoDB 등 다양한 서비스 분석
- **REST API 제공**: FastAPI 기반 결과 조회 및 통계 API

## 빠른 시작

### 환경 요구사항

- Python 3.10 이상
- AI PII 모델 서버: `http://localhost:8900/infer` 접근 가능

### 설치

```bash
# 저장소 클론
git clone --branch analyzer --single-branch \
  https://github.com/BOB-DSPM/DSPM_DATA-Identification-Classification.git \
  DSPM_DATA-IC-analyzer
cd DSPM_DATA-IC-analyzer

# 가상환경 설정
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# 의존성 설치
cd dspm-analyzer
pip install -r requirements.txt
pip install fastapi uvicorn[standard]

# 선택: 한국어 NLP 모델
python -m spacy download ko_core_news_sm
```

### API 서버 실행

```bash
# 서버 시작
uvicorn server:app --host 0.0.0.0 --port 9000

# API 문서 확인
# → http://localhost:9000/docs
```

## AI 탐지 엔진

### 모델 정보

- **엔드포인트**: `http://localhost:8900/infer`
- **방식**: 토큰 분류 기반 NER
- **지원 라벨**: NAME, PHONE, EMAIL, ADDRESS, DOB, RRN_KR
- **특징**: 문맥 기반 탐지, 신뢰도 점수 제공, 한영 혼용 지원

### 탐지 프로세스

```
1. 룰 기반 스캔 (정규식)
   ↓
2. AI 모델 스캔 (딥러닝)
   ↓
3. 결과 병합 및 중복 제거
   ↓
4. 법적 분류 (public/sensitive/identifiers)
```

**AI 장애 시**: 룰 기반 결과로 최소 탐지 보장

## 식별 가능한 정보

### AI + 룰 기반

| 분류 | AI 라벨 | 내부 엔티티 | 예시 |
|------|---------|-------------|------|
| 이름 | `NAME` | `KR_NAME` | 홍길동, John Doe |
| 전화번호 | `PHONE` | `PHONE_NUMBER` | 010-1234-5678 |
| 이메일 | `EMAIL` | `EMAIL_ADDRESS` | test@example.com |
| 주소 | `ADDRESS` | `KOREAN_ADDRESS` | 서울시 강남구... |
| 생년월일 | `DOB` | `DATE_OF_BIRTH` | 1990-01-01 |
| 주민번호 | `RRN_KR` | `KR_RRN` | 900101-1234567 |

### 추가 지원 (룰 기반)

- **금융정보**: 신용카드, 계좌번호
- **고유식별**: 여권, 운전면허
- **민감정보**: 정치적 견해, 종교, 건강정보, 노조 가입

## API 사용법

### 데이터 수집 및 분석

```bash
# Collector를 통한 AWS 데이터 수집 + 분석
curl -X POST http://localhost:9000/api/collect \
  -H 'Content-Type: application/json' \
  -d '{
    "collector_api": "http://localhost:8000",
    "only_detected": true
  }' | jq .
```

### 결과 조회

```bash
# 통계 요약
curl http://localhost:9000/api/result/front-stats | jq .

# 카테고리 분포
curl http://localhost:9000/api/result/category-counts | jq .

# 탐지된 항목 목록
curl 'http://localhost:9000/api/result/front-list?has_entities=yes&page=1&size=20' | jq .

# 리소스별 요약
curl http://localhost:9000/api/result/source-summary | jq .

# 상세 조회 (AI 결과 포함)
curl http://localhost:9000/api/result/front/{id} | jq .
```

### 데이터 내보내기

```bash
# CSV 형식
curl -o results.csv \
  'http://localhost:9000/api/result/front/export?format=csv&has_entities=yes'

# JSONL 형식
curl -o results.jsonl \
  'http://localhost:9000/api/result/front/export?format=jsonl&category=sensitive'
```

## API 엔드포인트

| 엔드포인트 | 설명 |
|-----------|------|
| `GET /health` | 서버 상태 확인 |
| `POST /api/collect` | 데이터 수집 및 분석 실행 |
| `GET /api/result/front-stats` | 탐지 통계 및 요약 |
| `GET /api/result/category-counts` | 카테고리별 분포 |
| `GET /api/result/front-list` | 전체 결과 목록 (페이징) |
| `GET /api/result/front-source/{source}` | 특정 리소스 결과 |
| `GET /api/result/front/{id}` | 상세 결과 (AI 탐지 포함) |
| `GET /api/result/source-summary` | 리소스별 요약 통계 |
| `GET /api/result/manifest` | 생성된 결과 파일 목록 |
| `GET /api/result/tree` | 결과 디렉토리 구조 |

전체 API 문서: http://localhost:9000/docs

## 응답 예시

### 통계 요약

```json
{
  "total_objects": 120,
  "detected_objects": 35,
  "detection_rate": 29.1,
  "category_distribution": {
    "public": 10,
    "sensitive": 3,
    "identifiers": 1,
    "none": 106
  },
  "top_entities": [
    ["EMAIL_ADDRESS", 40],
    ["PHONE_NUMBER", 20],
    ["KR_NAME", 15]
  ]
}
```

### 상세 결과 (AI 포함)

```json
{
  "id": "abc123def456",
  "file": "s3/my-bucket/doc-001.txt",
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

## 결과 파일 구조

```
var/results/
├── results.json                    # 전체 분석 결과
├── results_front.json              # API용 요약 결과
├── results_front_by_source.json    # 리소스별 통계
├── results.console.txt             # 실행 로그
└── classified/
    ├── public/                     # 일반 개인정보
    ├── sensitive/                  # 민감정보
    └── identifiers/                # 고유식별정보
```

### 샘플 분석 실행

```bash
# 테스트 데이터 생성
cat > sample_payload.json << 'EOF'
[
  {
    "key": "s3/test-bucket/doc.txt",
    "content": {
      "text": "홍길동 010-1234-5678 test@example.com 주민번호 900101-1234567"
    }
  }
]
EOF

# 분석 실행
python main.py -i sample_payload.json -o var/results/results.json
```

## 환경 변수

| 변수 | 설명 | 기본값 |
|------|------|--------|
| `TREAT_CREDIT_CARD_AS_SENSITIVE` | 신용카드를 민감정보로 처리 | `0` |
| `DEBUG_UNMASK` | 콘솔 출력 마스킹 해제 | `0` |
| `ONLY_DETECTED` | 탐지된 항목만 출력 | `0` |

## 트러블슈팅

### AI 서버 연결 실패

```
[engine_pii] AI 분석 실패: Connection refused
```

**해결 방법**:
1. AI 서버 상태 확인: `curl http://localhost:8900/health`
2. 네트워크/방화벽 설정 확인
3. AI 서버 장애 시에도 룰 기반 탐지는 정상 작동

### 한국어 토큰화 품질 저하

```bash
# 대용량 모델 설치 (선택)
python -m spacy download ko_core_news_lg
```

### 결과 파일이 생성되지 않음

```bash
# 출력 디렉토리 확인
ls -la var/results/

# 권한 확인
chmod 755 var/results/
```

## 고급 사용법

### AWS 데이터 직접 수집

```bash
# Collector 실행 중이어야 가능
python connectors/aws_http/run_collect_and_scan.py \
  --api http://localhost:8000 \
  --out var/results/results_all.json
```

### 탐지 설정 커스터마이징

```bash
# config/detector.yaml 수정
vim config/detector.yaml

# 분석 재실행
python main.py -i sample_payload.json -o var/results/results.json
```
