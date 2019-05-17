#!/usr/bin/env bash

set -aex

# load environs
if [ -f .env ] ; then
    source .env
fi

# get OS
os=`uname | tr "[[:upper:]]" "[[:lower:]]"`

# start server
app/bin/broapt-appd.${os} \
    --host="localhost" \
    --port="5000" \
    --docker-compose="./docker/docker-compose.${os}.yml" \
    --dump-path="./dump/" \
    --logs-path="./logs/" \
    --api-root="./app/include/api/" \
    --api-logs="./logs/api/" \
    --interval="10" \
    --max-retry="3"
