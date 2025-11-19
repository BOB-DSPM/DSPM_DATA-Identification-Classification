# AWS Marketplace 컨테이너 제품 대응 가이드

AEGIS Analyzer API 컨테이너 이미지를 AWS Marketplace에 게시할 때 따라야 하는 필수 요구 사항과 제품별 대응 방안을 정리했습니다. 이 문서는 제출 전 자체 점검 체크리스트로 활용할 수 있습니다.

---

## 1. 제품 개요
- **제품 이름**: AEGIS Analyzer API (DSPM 데이터 식별/분류 엔진)
- **구성 요소**: FastAPI 기반 API 서버 + 내부 DSPM 분석기(`dspm-analyzer`)
- **노출 포트**: 기본 `8400/TCP` (환경 변수 `PORT`로 변경 가능)
- **필수 데이터**: `/app/var/results` (결과 저장 디렉터리, 볼륨 마운트 가능)

---

## 2. 보안 정책 준수 방안
- **이미지 구성**: `python:3.12-slim` 기반 Linux 이미지, 최신 보안 패치 적용 후 사용.
- **최소 권한 실행**: 빌드 시 `appuser` 비루트 계정을 생성해 기본 실행 사용자로 지정.
- **패키지 보안**: 서드파티 패키지는 `pip`로 명시적 버전 관리, 정기적으로 취약점 스캔(`trivy` 등) 후 재빌드.
- **자격 증명 처리**:
  - 컨테이너 내부에 AWS 자격 증명을 하드코딩하거나 `aws configure`로 저장하지 않습니다.
  - **AWS 서비스 사용 시**: Amazon ECS Task Role, Amazon EKS IRSA, 혹은 AWS IAM Identity Center를 통해 전달된 임시 자격 증명만 사용합니다.
  - 로컬 개발/테스트에서 `aws configure`가 필요한 경우에도 Marketplace 이미지에는 포함하지 않습니다.
- **비밀 정보**: 환경 변수/설정 파일에 해시된 암호 포함 금지. 고객이 직접 제공하는 API 토큰이나 DB 암호는 Kubernetes Secret 혹은 AWS Secrets Manager를 통해 주입하도록 문서화.
- **헬스체크/모니터링**: `curl` 기반 `GET /health`을 제공하여 상태 확인이 가능하며, 비정상 시 1을 반환하여 오케스트레이터가 재기동 가능.

---

## 3. 고객 정보 요구 사항
- **데이터 수집**: 컨테이너는 고객의 데이터 저장소를 스캔하지만, 사용자가 API로 명시적으로 수집을 요청하는 경우에만 실행됩니다.
- **외부 전송**: 기본적으로 고객 데이터를 외부 서비스로 전송하지 않습니다. 추가 Collector API 사용 시 고객이 직접 URL을 제공해야 하며, 전송되는 데이터는 HTTPS를 강제하도록 안내합니다.
- **결제 정보**: 결제 데이터를 수집하지 않습니다.
- **BYOL 여부**: 기본적으로 PAYG 또는 구독형를 지원하며, BYOL 옵션은 Marketplace 요구 사항에 맞춰 별도 SKU로 구분합니다.

---

## 4. 제품 사용 요구 사항
- **완전한 제품 제공**: 단일 이미지로 Collector 트리거, 결과 확인 API까지 포함. 외부 이미지를 다운받을 필요가 없습니다.
- **외부 종속성**: 선택적 종속성이 있는 경우(예: 외부 Collector, AI 모델 엔드포인트) README/Usage 문서에 “인터넷 연결 필요” 및 필요한 서비스 목록을 표기합니다.
- **자동 배포**: Docker, Amazon ECS, Amazon EKS, AWS Fargate 환경에서 `docker run` 혹은 `kubectl apply` 만으로 배포 가능하도록 제공.
- **업셀 금지**: 이미지/문서 안에서 AWS Marketplace 이외의 결제 유도 문구 제거.

---

## 5. 아키텍처 요구 사항 대응
- **ECR 업로드**: Marketplace Management Portal에서 제공하는 ECR 리포지토리로 `docker buildx build` 결과를 푸시.
- **멀티 아키텍처**: 빌드 명령 예시
  ```bash
  docker buildx build \
    --platform linux/amd64,linux/arm64 \
    -f dockerfile \
    -t <aws-account>.dkr.ecr.<region>.amazonaws.com/aegis-analyzer:<version> \
    --push .
  ```
- **지원 플랫폼**: Amazon ECS(EC2/Fargate), Amazon EKS, AWS Fargate에서 실행 가능한 리눅스 컨테이너.
- **네트워크/스토리지**: TLS를 사용하는 HTTP API(기본 8400)와 RW 볼륨 `/app/var/results`만 요구.

---

## 6. 컨테이너 사용 지침 (예시)
### 6.1 배포 전 준비
1. Marketplace 전용 ECR 리포지토리에 로그인.
2. 위 멀티 아키텍처 빌드 커맨드로 이미지를 푸시.
3. (선택) `var/results`용 EFS/EBS, 혹은 ECS 바인드 마운트를 준비.

### 6.2 Amazon ECS (Fargate) 실행 예시
```json
{
  "family": "aegis-analyzer",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "1024",
  "memory": "2048",
  "containerDefinitions": [
    {
      "name": "analyzer",
      "image": "<account>.dkr.ecr.<region>.amazonaws.com/aegis-analyzer:<version>",
      "portMappings": [{"containerPort": 8400, "protocol": "tcp"}],
      "environment": [
        {"name": "PORT", "value": "8400"},
        {"name": "CONNECTOR_SCRIPT", "value": "/app/dspm-analyzer/connectors/aws_http/run_collect_and_scan.py"}
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/aegis-analyzer",
          "awslogs-region": "<region>",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "linuxParameters": {"initProcessEnabled": true}
    }
  ],
  "executionRoleArn": "arn:aws:iam::<account>:role/AmazonECSTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::<account>:role/AegisAnalyzerTaskRole"
}
```
- **IAM 지침**: `AegisAnalyzerTaskRole`에 필요한 AWS API 권한(S3, RDS 등)을 최소 권한 원칙으로 부여합니다. `aws configure`를 실행하여 고정 자격 증명을 컨테이너에 주입하지 않습니다.

### 6.3 Amazon EKS 배포 시 유의점
- Kubernetes 매니페스트에서 `securityContext.runAsNonRoot: true`, `runAsUser: 1000` 설정으로 Dockerfile 기본 사용자와 일치시킵니다.
- IRSA(Service Account용 IAM 역할)를 사용하여 AWS 리소스 접근 권한을 부여합니다.
- `values.yaml` 또는 매니페스트에 이미지 레지스트리/태그를 변수화하여 리전 복제를 지원합니다.

---

## 7. 제출 체크리스트
| 항목 | 상태 | 비고 |
|------|------|------|
| 최신 베이스 이미지/보안 패치 적용 | ☐ | 릴리스 전 `apt-get upgrade` 포함 |
| 비루트 사용자 기본 실행 | ☑ | `USER appuser` |
| AWS 자격 증명 하드코딩 금지 | ☑ | IAM Role 사용 지침 제공 |
| 고객 데이터 외부 전송 사전 동의 | ☑ | API 요청 기반 |
| 사용 지침에 배포 단계 포함 | ☑ | ECS/EKS 예시 제공 |
| 멀티 아키텍처 빌드 절차 제공 | ☐ | 필요 시 `buildx` 명령 실행 |
| 외부 종속성/네트워크 요구사항 명시 | ☑ | Collector/API 엔드포인트 안내 |
| 헬스체크/모니터링 설명 | ☑ | `GET /health` |

체크리스트 완료 후 AWS Marketplace Management Portal에서 제품 메타데이터, 가격 모델, EULA, 지원 정보를 등록하면 제출 준비가 완료됩니다.

---

문의 사항이나 요구 사항 변경 시 AWS Marketplace 판매자 문서를 주기적으로 확인하여 최신 정책을 반영하세요.
