FROM python:3.12-slim
WORKDIR /app
# shared lib + this service
COPY services/shared /app/shared
COPY services/ws1-collectors /app/ws1-collectors
RUN pip install --no-cache-dir redis pysnmp || true
ENV PYTHONPATH=/app
ENV BUS_BACKEND=redis
WORKDIR /app/ws1-collectors
CMD ["python", "main.py"]
