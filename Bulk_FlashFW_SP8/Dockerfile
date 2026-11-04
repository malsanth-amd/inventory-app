FROM python:3.11-slim

WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY flashtools ./flashtools

EXPOSE 8000

# BIND_HOST must be 0.0.0.0 inside the container so the host's docker
# port-mapping can reach it - DEV_BYPASS_AUTH's localhost-only safety
# check in app/config.py means this will refuse to start with the dev
# bypass flag set, which is intentional.
ENV BIND_HOST=0.0.0.0
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
