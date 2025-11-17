FROM python:latest

ARG DEBUG

ENV DEBUG=False
ENV PYTHONUNBUFFERED=1

COPY . /app/

RUN pip install --upgrade pip && \
    pip install -r /app/requirements.txt
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iputils-ping nmap && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

EXPOSE 8000
WORKDIR /app

VOLUME [ "/app/db", "/app/files" ]

ENTRYPOINT [ "/app/entrypoint.sh" ]
