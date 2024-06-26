FROM python:slim-buster

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY src/ src/

CMD ["python", "src/main.py"]