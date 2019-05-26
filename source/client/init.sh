#!/usr/bin/env bash

set -aex

# change cwd
cd /broapt

# load environs
if [ -f .env ] ; then
    source .env
fi

# log path
LOGS_PATH=${BROAPT_LOGS_PATH="/var/log/bro/"}
STDOUT="${LOGS_PATH}/stdout.log"
STDERR="${LOGS_PATH}/stderr.log"

# run scripts
/usr/bin/python3.6 python $@ \
    >> ${STDOUT} 2>> ${STDERR} || true

# sleep
sleep infinity
