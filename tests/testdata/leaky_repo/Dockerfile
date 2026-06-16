FROM python:3.12-slim

WORKDIR /app

# These should use build args, not hardcoded values
ENV DB_PASSWORD="docker_hardcoded_secret_123"
ENV API_SECRET_KEY="docker_api_secret_abcdefghij"

COPY . .
RUN pip install -r requirements.txt

CMD ["python", "app.py"]
