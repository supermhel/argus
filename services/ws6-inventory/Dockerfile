FROM python:3.14-slim
WORKDIR /app
COPY services/ws6-inventory /app/ws6-inventory
ENV PYTHONPATH=/app
ENV INVENTORY_DB=/data/inventory.db
ENV PORT=8000
VOLUME ["/data"]
EXPOSE 8000
WORKDIR /app/ws6-inventory
CMD ["python", "app.py"]
