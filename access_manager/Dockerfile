ARG BUILD_FROM
FROM ${BUILD_FROM}

RUN pip3 install --no-cache-dir aiohttp==3.12.15

COPY app /app
COPY run.sh /run.sh
RUN chmod 0755 /run.sh

CMD ["/run.sh"]
