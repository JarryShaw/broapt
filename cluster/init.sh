#!/usr/bin/env bash

set -aex

# load environs
if [ -f .env ] ; then
    source .env
fi

# get OS
os=`uname | tr "[[:upper:]]" "[[:lower:]]"`

# server settings
SERVER_NAME=${BROAPT_SERVER_NAME="localhost"}
SERVER_PORT=${BROAPT_SERVER_PORT=5000}

# paths
DUMP_PATH=${BROAPT_DUMP_PATH="/home/traffic/log/extract/"}
LOGS_PATH=${BROAPT_LOGS_PATH="/home/traffic/log/bro/"}
API_ROOT=${BROAPT_API_ROOT="./include/api/"}
API_PATH=${BROAPT_API_LOGS="/home/traffic/log/bro/api/"}

# macros
INTERVAL=${BROAPT_INTERVAL=10}
MAX_RETRY=${BROAPT_MAX_RETRY=3}

# start server
daemon/bin/broaptd.${os} \
    --host=${SERVER_NAME} \
    --port=${SERVER_PORT} \
    --docker-compose="./docker/docker-compose.${os}.yml" \
    --dump-path=${DUMP_PATH} \
    --logs-path=${LOGS_PATH} \
    --api-root=${API_ROOT} \
    --api-logs=${API_PATH} \
    --interval=${INTERVAL} \
    --max-retry=${MAX_RETRY}
