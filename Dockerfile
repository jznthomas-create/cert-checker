FROM python:3.13-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1 PORT=8000 TRUST_PROXY=1
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY *.py exiting_cas.json ./
COPY static ./static
RUN useradd -m app && mkdir -p /app/data && chown app /app/data
USER app
EXPOSE 8000
CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT} --proxy-headers"]
