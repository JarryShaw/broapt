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

# compose Bro scripts
/usr/bin/python3.6 python/compose.py

# start logs
echo "###########################################" >> ${STDOUT}
echo "$ $(date)" >> ${STDOUT}
echo "###########################################" >> ${STDERR}
echo "$ $(date)" >> ${STDERR}

# run scripts
/usr/bin/python3.6 python $@ \
    >> ${STDOUT} 2>> ${STDERR} || true

# end logs
echo "###########################################" >> ${STDOUT}
echo "###########################################" >> ${STDERR}

# sleep
sleep infinity
