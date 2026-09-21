FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir faker rich requests httpx

COPY scripts/ scripts/
COPY config/ config/

CMD ["python", "scripts/generate_all_logs.py"]
