#!/usr/bin/env bash

set -aex

# load environs
if [ -f .env ] ; then
    source .env
fi

# paths
LOGS_PATH=${BROAPT_LOGS_PATH="/home/traffic/log/bro/"}
ELF_PATH=${ELF_PATH="/home/traffic/log/bro/tmp/"}

# score threshold
ELF_SCORE=${ELF_SCORE=100}

# macros
mime=${BROAPT_MIME}
path=${BROAPT_PATH}
name=$(basename ${path})
logs="${ELF_PATH}/${name%\.+}.log"

# run ELF-Parser
elfparser-cli \
    --file "${path}" \
    --reasons \
    --capabilities \
    --print > ${logs}

# get score
first=`head -1 ${logs}`
IFS=' ' read -ra line <<< ${first}
score=${line[3]}

# check score
if [[ ${score} -gt ${ELF_SCORE} ]]; then
    rate="true"
else
    rate="false"
fi

# generate report
time=$(date +%s.%N)
report="{\"time\": ${time}, \"path\": \"${path}\", \"mime\": \"${mime}\", \"rate\": ${rate}}"
echo ${report} > "${LOGS_PATH}/rate.log"
