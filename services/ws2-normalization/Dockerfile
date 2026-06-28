FROM python:3.12-slim
WORKDIR /app
COPY services/shared /app/shared
COPY tools /app/tools
COPY contracts /app/contracts
COPY services/ws2-normalization /app/ws2-normalization
RUN pip install --no-cache-dir redis || true
ENV PYTHONPATH=/app
ENV BUS_BACKEND=redis
WORKDIR /app/ws2-normalization
CMD ["python", "main.py"]
