# Build from the repository root:  docker build -f app/Dockerfile -t doppler-identity-audit .
FROM python:3.13-alpine

# No packages are installed: the app uses only the Python standard library.
RUN adduser -D -H -u 10001 audit
WORKDIR /srv
COPY identity_audit.py ./
COPY app/server.py app/
COPY app/static app/static

USER audit
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD wget -q -O /dev/null --header "Host: localhost" http://127.0.0.1:8080/ || exit 1
CMD ["python", "app/server.py", "--host", "0.0.0.0", "--port", "8080"]
