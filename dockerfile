# Dockerfile (dspm-analyzer / front-only API)
FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8400

# 기본 유틸 (HEALTHCHECK용 curl 포함)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates tzdata \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 의존성 설치: analyzer 전용 req만 사용
COPY dspm-analyzer/requirements.txt /tmp/reqs/analyzer.txt
RUN pip install --upgrade pip \
 && pip install -r /tmp/reqs/analyzer.txt \
    fastapi uvicorn[standard]

# 앱 소스 복사 (var/results는 .dockerignore로 제외)
COPY . /app

# 결과 디렉토리 & 비루트 유저
RUN mkdir -p /app/var/results \
 && useradd -ms /bin/bash appuser \
 && chown -R appuser:appuser /app
USER appuser

VOLUME ["/app/var/results"]

# 포트/헬스체크/실행 커맨드
EXPOSE 8400
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=5 \
  CMD curl -sf http://127.0.0.1:${PORT}/health || exit 1

CMD ["sh", "-c", "python -m uvicorn server:app --host 0.0.0.0 --port ${PORT}"]
