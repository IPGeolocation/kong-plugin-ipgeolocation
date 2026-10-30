# Database updater image used by the Docker and Kubernetes examples.
#   docker build -t ipgeolocation-updater examples/updater
FROM alpine:3.24.3
RUN apk upgrade --no-cache \
 && apk add --no-cache ca-certificates curl openssl unzip
COPY ipgeolocation-update.sh /usr/local/bin/ipgeolocation-update
RUN chmod 0755 /usr/local/bin/ipgeolocation-update
ENTRYPOINT ["/usr/local/bin/ipgeolocation-update"]
