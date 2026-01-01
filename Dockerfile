FROM python:3.13-slim AS builder

WORKDIR /app

COPY ./server/server.py /app/
COPY ./server/core /app/core
COPY ./server/requirements.txt /app/
COPY ./server/scripts/wait-for-it.sh /wait-for-it.sh

RUN chmod +x /wait-for-it.sh && \
    pip install --no-cache-dir -r /app/requirements.txt && \
    useradd -M chat_usr && \
    mkdir -p /app/logs && \
    touch /app/logs/chatserver.log && \
    chown -R root:chat_usr /app && \
    chmod -R 770 /app

USER chat_usr

CMD ["/wait-for-it.sh", "db:3306", "--", "python3", "server.py"]
