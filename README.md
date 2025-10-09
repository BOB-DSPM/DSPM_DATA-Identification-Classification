# Data Identification & Classification Analyzer

> 개인정보 및 민감정보를 자동으로 **식별하고 분류**하는 분석기입니다.  
> 다양한 데이터 소스에서 수집한 텍스트·CSV·JSON 등을 분석해 결과를 민감도 수준별로 저장합니다.

---

## 🚀 개요

이 Analyzer는 Microsoft Presidio와 커스텀 Recognizer, 정규식, 한국어 사전(lexicon)을 결합해 **한국형 데이터 환경**에서의 개인정보 탐지 품질을 높였습니다.  
분석 결과는 개인정보보호법 기준(개인정보·민감정보·고유식별정보)에 맞게 분류됩니다.

---

## 🧠 주요 기능

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

## 🛠️ 설치

### 1) 저장소 클론
```bash
git clone https://github.com/BOB-DSPM/DSPM_DATA-Identification-Classification.git
cd DSPM_DATA-Identification-Classification/dspm-analyzer
```

### 2) 가상환경(venv) 구성
```bash
python -m venv .venv
# Windows
.\.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate
```

### 3) 필수 패키지 설치
```bash
pip install -r requirements.txt
```

*(선택)* Presidio를 사용하려면:
```bash
pip install presidio-analyzer presidio-anonymizer
```

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

## ▶️ 사용법

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
classified/identifier/
```

---

## ⚙️ 환경 변수

| 변수명 | 설명 | 기본값 |
|--------|------|--------|
| `TREAT_CREDIT_CARD_AS_SENSITIVE` | 신용카드 번호를 민감정보로 처리 | `0` |
| `DEBUG_UNMASK` | 콘솔 출력 마스킹 해제 | `0` |
| `ONLY_DETECTED` | 탐지된 항목만 출력 | `0` |

---

## 📜 라이선스

MIT License
