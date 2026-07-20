FROM ghcr.io/home-assistant/base-python:3.13-alpine3.24

ARG BUILD_VERSION
ARG BUILD_ARCH
ENV ACCESS_MANAGER_VERSION=${BUILD_VERSION}

LABEL \
    io.hass.version="${BUILD_VERSION}" \
    io.hass.type="app" \
    io.hass.arch="${BUILD_ARCH}"

RUN apk add --no-cache libffi \
    && apk add --no-cache --virtual .credential-build-deps \
        cargo gcc libffi-dev musl-dev openssl-dev pkgconfig python3-dev \
    && python3 -m pip install --no-cache-dir --upgrade \
        pip==26.1.2 \
        aiohttp==3.14.1 \
        cryptography==49.0.0 \
        ruamel.yaml==0.18.16 \
    && apk del .credential-build-deps

COPY app /app
COPY run.sh /run.sh
RUN chmod 0755 /run.sh

CMD ["/run.sh"]
