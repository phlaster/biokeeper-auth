# Auth Service

## Container with pre-installed uv
Build container with pre-installed uv using this command:
```sh
echo 'FROM python:3.11-slim-buster
RUN pip install uv' | docker build -t python:3.11-slim-buster-uv -
```