FROM python:3.14.7-slim-trixie

LABEL org.opencontainers.image.title="broapt-app" \
      org.opencontainers.image.description="BroAPT API integration service" \
      org.opencontainers.image.url="https://broapt.jarryshaw.me/" \
      org.opencontainers.image.source="https://github.com/JarryShaw/BroAPT" \
      org.opencontainers.image.licenses="CC-BY-NC-ND-4.0"

ENV LANG="C.UTF-8" \
    LC_ALL="C.UTF-8" \
    PYTHONIOENCODING="UTF-8"

RUN python -m pip install --no-cache-dir \
        PyYAML==6.0.3 \
        requests==2.34.2

WORKDIR /source

COPY source /source

ENTRYPOINT ["bash", "/source/init.sh"]
