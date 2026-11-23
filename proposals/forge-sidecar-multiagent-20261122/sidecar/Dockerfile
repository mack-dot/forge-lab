FROM python:3.12-slim
RUN useradd -m -u 10001 sidecar && mkdir -p /data && chown sidecar /data
WORKDIR /app
COPY . /app
USER sidecar
CMD ["python3", "sidecar_multi.py"]
