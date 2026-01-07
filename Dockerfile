FROM python:3.13-slim AS builder

WORKDIR /app

COPY ./server/server.py /app/
COPY ./server/core /app/core
COPY ./server/requirements.txt /app/
COPY ./server/scripts/wait-for-it.sh /wait-for-it.sh
COPY ./server/config.toml /app/

RUN chmod +x /wait-for-it.sh && \
    pip install --no-cache-dir -r /app/requirements.txt && \
    useradd -M kylochat && \
    mkdir -p /app/logs && \
    touch /app/logs/chatserver.log && \
    chown -R root:kylochat /app && \
    chmod -R 770 /app

USER kylochat

CMD ["/wait-for-it.sh", "db:3306", "--", "python3", "server.py"]
