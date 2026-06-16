FROM python:3.12-slim

WORKDIR /app

# VULNERABILITY: Secrets baked into image ENV instructions
ENV DB_PASSWORD="Dockerfile_DB_Hardcoded_Pass!"
ENV AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
ENV API_SECRET_TOKEN="docker_api_secret_hardcoded_abcdefghij"
ENV STRIPE_SECRET_KEY="sk_live_4eC39HqLyjWDarjtT1zdp7dc"

# SAFE: build arg — not baked in
ARG BUILD_VERSION
ENV VERSION=$BUILD_VERSION

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000
CMD ["python", "app.py"]
