# Dockerfile (AEGIS Analyzer API)
FROM python:3.12-slim

ARG APP_PORT=8400
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=${APP_PORT}

# 필수 시스템 패키지 설치 (curl은 HEALTHCHECK 용도)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates tzdata build-essential \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 의존성 설치 (analyzer requirements + API 프레임워크)
COPY dspm-analyzer/requirements.txt /tmp/requirements.txt
RUN pip install --upgrade pip \
 && pip install --no-cache-dir -r /tmp/requirements.txt \
    fastapi uvicorn[standard]

# 앱 복사 (.dockerignore 로 var/results 등은 제외)
COPY . .

# 실행 사용자/작업 디렉토리 준비
RUN mkdir -p /app/var/results \
 && groupadd --system appuser \
 && useradd --system --gid appuser --create-home appuser \
 && chown -R appuser:appuser /app
USER appuser

VOLUME ["/app/var/results"]
EXPOSE ${APP_PORT}

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=5 \
  CMD curl -sf http://127.0.0.1:${PORT}/health || exit 1

CMD ["python", "-m", "uvicorn", "server:app", "--host", "0.0.0.0", "--port", "${PORT}"]
