FROM python:3.12-alpine

ENV PYTHONUNBUFFERED=1

RUN apk update && \
    apk add --no-cache dnsmasq inotify-tools arp-scan supervisor bash && \
    pip install --no-cache-dir requests pyyaml inotify-simple

WORKDIR /app
COPY main.py /app/main.py
RUN chmod +x /app/main.py

COPY supervisord.conf /etc/supervisord.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 53/udp 53/tcp

ENTRYPOINT ["/entrypoint.sh"]