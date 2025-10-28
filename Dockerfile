# Simple Dockerfile for BlueSentinel SIEM
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src ./src
COPY rules ./rules
COPY samples ./samples

ENV PYTHONPATH=/app/src
EXPOSE 8000 5514/udp

CMD ["uvicorn", "bluesentinel.api:app", "--host", "0.0.0.0", "--port", "8000"]
