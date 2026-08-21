# Hardened multi-stage image — pinned base (never :latest). Non-root uid 10001.
FROM python:3.12.11-slim AS builder
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PROFILE_EVALUATOR_PORT=8116
ENV PROFILE_EVALUATOR_ENABLE_LOOP=false

COPY services/profile-evaluator/pyproject.toml /app/pyproject.toml
COPY services/profile-evaluator/profile_evaluator /app/profile_evaluator

RUN pip install --no-cache-dir .

FROM python:3.12.11-slim AS runtime
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --create-home --shell /usr/sbin/nologin app

COPY --from=builder --chown=app:app /usr/local /usr/local
COPY --from=builder --chown=app:app /app /app
ENV PROFILE_EVALUATOR_PORT=8116
ENV PROFILE_EVALUATOR_ENABLE_LOOP=false

USER app:app
EXPOSE 8116
CMD ["uvicorn", "profile_evaluator.main:app", "--host", "0.0.0.0", "--port", "8116"]
