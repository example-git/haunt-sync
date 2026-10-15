FROM alpine:3.23
RUN apk add --no-cache postfix opendkim python3 ca-certificates
COPY entrypoint.py /usr/local/bin/haunt-mail-start
COPY health.py /usr/local/bin/haunt-mail-health
ENTRYPOINT ["python3", "/usr/local/bin/haunt-mail-start"]
