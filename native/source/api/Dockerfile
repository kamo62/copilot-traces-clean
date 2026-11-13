FROM python:3.13-slim
WORKDIR /app
COPY api /app/api
COPY import_records.py fetch_records.py /app/
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 1000:1000
EXPOSE 8081
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8081/healthz',timeout=3)"
CMD ["python", "/app/api/service.py"]
