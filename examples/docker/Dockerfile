# Kong Gateway with the ipgeolocation plugin installed. Build from the repository root:
#   docker build -f examples/docker/Dockerfile -t kong-ipgeolocation .
ARG KONG_IMAGE=kong:3.9
FROM ${KONG_IMAGE}

USER root
COPY kong-plugin-ipgeolocation-*.rockspec /tmp/kong-plugin-ipgeolocation/
COPY kong /tmp/kong-plugin-ipgeolocation/kong
RUN cd /tmp/kong-plugin-ipgeolocation \
 && luarocks make kong-plugin-ipgeolocation-*.rockspec \
 && cd / && rm -rf /tmp/kong-plugin-ipgeolocation \
 && mkdir -p /usr/local/share/ipgeolocation
USER kong

ENV KONG_PLUGINS=bundled,ipgeolocation
