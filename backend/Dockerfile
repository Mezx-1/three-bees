FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends ffmpeg && rm -rf /var/lib/apt/lists/*
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
# Database, uploads and the generated sign-in passwords live on the mounted volume.
ENV THREEB_DATABASE_URL=sqlite:////data/threeb.db THREEB_UPLOAD_DIR=/data/storage THREEB_CREDENTIALS_FILE=/data/demo-credentials.txt
RUN useradd -m threebees && mkdir -p /data && chown threebees /data
USER threebees
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
