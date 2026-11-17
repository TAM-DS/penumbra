FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY penumbra ./penumbra
RUN pip install --no-cache-dir ".[claude]" && useradd -m penumbra && mkdir -p /app/runs && chown penumbra /app/runs
USER penumbra
EXPOSE 8000
CMD ["penumbra", "serve", "--host", "0.0.0.0", "--port", "8000"]
