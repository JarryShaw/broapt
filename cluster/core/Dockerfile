FROM zeek/zeek:8.2.1 AS zeek

FROM python:3.14.7-slim-trixie

LABEL org.opencontainers.image.title="broapt-core" \
      org.opencontainers.image.description="BroAPT network analysis service" \
      org.opencontainers.image.url="https://broapt.jarryshaw.me/" \
      org.opencontainers.image.source="https://github.com/JarryShaw/BroAPT" \
      org.opencontainers.image.licenses="CC-BY-NC-ND-4.0"

ENV PYTHONIOENCODING="UTF-8" \
    PATH="/usr/local/zeek/bin:${PATH}"

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
        jq \
        libmagic1 \
        libmaxminddb0 \
        libnode115 \
        libpcap0.8 \
        libpython3.13 \
        libssl3 \
        libuv1 \
        libz1 \
        libzmq5 \
        net-tools \
        procps \
 && rm -rf /var/lib/apt/lists/*

COPY --from=zeek /usr/local/zeek /usr/local/zeek

RUN ln -s /usr/local/zeek/bin/zeek /usr/local/bin/bro \
 && python -m pip install --no-cache-dir \
        pandas==3.0.5 \
        python-magic==0.4.27

WORKDIR /source

COPY source /source

ENTRYPOINT ["bash", "/source/init.sh"]
