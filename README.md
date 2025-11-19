# AEGIS Analyzer API (DSPM Data Identification & Classification)

AWS 환경에서 민감정보를 자동으로 식별/분류하는 AI 기반 DSPM(Data Security Posture Management) 솔루션입니다. Collector가 수집한 데이터를 FastAPI 기반 API로 분석하고, 리소스별 탐지 결과·통계를 REST 인터페이스로 제공합니다.

---

## 목차
1. [주요 기능](#주요-기능)
2. [아키텍처 개요](#아키텍처-개요)
3. [빠른 시작](#빠른-시작)
4. [API 사용법](#api-사용법)
5. [API 엔드포인트](#api-엔드포인트)
6. [응답 예시](#응답-예시)
7. [결과 파일 구조](#결과-파일-구조)
8. [AWS Marketplace 준비](#aws-marketplace-준비)

---

## 주요 기능

- **AI + 룰 기반 하이브리드 탐지**: 딥러닝 NER 모델과 정규식을 결합해 한국어/영어 혼합 데이터에서도 높은 정확도 제공
- **법규 준수 자동화**: 개인정보/민감정보/고유식별정보 분류, 카테고리 통계, 리포트 추출
- **Collector 연계**: `run_collect_and_scan.py` 등 AWS Connector를 호출해 S3, RDS 등 데이터 원천을 자동 분석
- **REST API**: FastAPI/uvicorn 기반 서비스로 탐지 결과, 리소스 요약, 파일 트리를 조회
- **헬스체크 & 모니터링**: `GET /health` 제공, `var/results` 디렉터리를 외부 스토리지에 마운트 가능

---

## 아키텍처 개요

```
┌───────────┐    Collect API    ┌────────────────────┐
│ AWS Data  │ ───────────────▶ │ Collector (AWS HTTP │
│ Sources   │                  │  or 외부)          │
└───────────┘                  └────────┬───────────┘
                                         │ 결과 tar/json
                                         ▼
                                 ┌───────────────────┐
                                 │ AEGIS Analyzer API│
                                 │ (FastAPI + DSPM)  │
                                 └────────┬──────────┘
                                          │ REST API
                                          ▼
                                Dashboard / CLI / Integrations
```

- Collector 스크립트 기본값: `dspm-analyzer/connectors/aws_http/run_collect_and_scan.py`
- 결과 디렉터리: `var/results/*` (Docker 시 `/app/var/results`)
- 기본 포트: `8400` (환경 변수 `PORT`로 변경 가능)

---

## 빠른 시작

### 1. 필수 요구 사항
- Python 3.10 이상 또는 Docker
- AI PII 모델 서버: `http://localhost:8900/infer`
- AWS 리소스 접근 시 IAM Role(EC2/ECS) 또는 IRSA(EKS) 사용 → 컨테이너 내 `aws configure` 금지

### 2. 로컬(가상환경) 실행
```bash
git clone --branch analyzer --single-branch \
  https://github.com/BOB-DSPM/DSPM_DATA-Identification-Classification.git \
  DSPM_DATA-IC-analyzer
cd DSPM_DATA-IC-analyzer

python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

pip install --upgrade pip
pip install -r dspm-analyzer/requirements.txt
pip install fastapi uvicorn[standard]

# 선택: 한국어 NLP 모델
python -m spacy download ko_core_news_sm

uvicorn server:app --host 0.0.0.0 --port 9000
# → http://localhost:9000/docs
```

### 3. Docker 이미지 빌드/실행
```bash
# 이미지 빌드
docker build -f dockerfile -t aegis-analyzer:latest .

# 실행 (결과 디렉터리 마운트)
docker run --rm -p 8400:8400 \
  -v $(pwd)/var/results:/app/var/results \
  aegis-analyzer:latest

# 헬스체크
curl http://localhost:8400/health
```

### 4. Amazon ECS / EKS 배포 요약
- `docker buildx build --platform linux/amd64,linux/arm64 --push ...` 로 멀티 아키텍처 이미지 빌드
- ECS: Task Role에 S3/RDS 등 필요한 권한 부여, `/app/var/results`는 EFS/EBS 또는 S3FS로 마운트
- EKS: Deployment `securityContext.runAsNonRoot: true`, IRSA(ServiceAccount role)로 AWS API 접근 허용
- 상세 항목은 [`AWS_MARKETPLACE_GUIDE.md`](AWS_MARKETPLACE_GUIDE.md) 참고

---

## API 사용법

### Collector 실행
```bash
curl -X POST http://localhost:9000/api/collect \
  -H 'Content-Type: application/json' \
  -d '{
    "collector_api": "http://collector:8000",
    "only_detected": true
  }'
```

### 결과 조회
```bash
curl http://localhost:9000/api/result/front-stats | jq .
curl http://localhost:9000/api/result/category-counts | jq .
curl 'http://localhost:9000/api/result/front-list?has_entities=yes&page=1&size=20' | jq .
curl http://localhost:9000/api/result/source-summary | jq .
curl http://localhost:9000/api/result/front/{id} | jq .
```

### 데이터 내보내기
```bash
curl -o results.csv \
  'http://localhost:9000/api/result/front/export?format=csv&has_entities=yes'

curl -o results.jsonl \
  'http://localhost:9000/api/result/front/export?format=jsonl&category=sensitive'
```

---

## API 엔드포인트

| Method | 경로 | 설명 |
|--------|------|------|
| `GET` | `/health` | 서버 상태 확인 |
| `POST` | `/api/collect` | Collector 실행 + 분석 |
| `GET` | `/api/result/front-stats` | 탐지 통계 요약 |
| `GET` | `/api/result/category-counts` | 카테고리별 분포 |
| `GET` | `/api/result/front-list` | 결과 목록 (페이징) |
| `GET` | `/api/result/front-source/{source}` | 특정 리소스 필터 |
| `GET` | `/api/result/front/{id}` | 단일 결과 상세 (AI 탐지 포함) |
| `GET` | `/api/result/source-summary` | 리소스별 요약 통계 |
| `GET` | `/api/result/manifest` | 결과 파일 목록 |
| `GET` | `/api/result/tree` | 결과 디렉터리 트리 |

전체 스키마는 `http://<host>:<port>/docs` (Swagger UI)에서 확인할 수 있습니다.

---

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

### 상세 결과
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

---

## 결과 파일 구조

```
var/
└─ results/
   ├─ results_front.json           # 최신 Front 결과
   ├─ results_all.json             # Collector raw 결과
   ├─ results_front_by_source.json # 리소스 요약
   ├─ front-list/...
   └─ source-summary/...
```

---

## AWS Marketplace 준비

AWS Marketplace에 컨테이너 제품으로 게시할 경우 [`AWS_MARKETPLACE_GUIDE.md`](AWS_MARKETPLACE_GUIDE.md)를 따라 보안/배포/문서 요구 사항을 충족해야 합니다. 주요 포인트:

- 컨테이너는 기본적으로 비루트 사용자(`appuser`)로 실행
- AWS 자격 증명 하드코딩 금지, IAM Role/IRSA 사용
- 멀티 아키텍처 이미지 업로드, 사용 지침에 배포 단계 포함
- 외부 종속성(Collector, AI 모델)과 네트워크 요구 사항을 README 및 Marketplace 설명에 명시

체크리스트 완료 후 Marketplace Management Portal에서 메타데이터, 가격, EULA, 지원 정보를 입력하고 검수를 진행하세요.
