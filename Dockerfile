FROM python:3.10-slim-buster-uv

WORKDIR /app

COPY requirements.txt .
RUN uv pip install -r requirements.txt --system

COPY src/ src/

CMD ["python", "src/main.py"]