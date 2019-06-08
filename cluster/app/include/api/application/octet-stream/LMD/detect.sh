#!/usr/bin/env bash

set -aex

# load environs
if [ -f .env ] ; then
    source .env
fi

# paths
LOGS_PATH=${BROAPT_LOGS_PATH="/home/traffic/log/bro/"}
LMD_PATH=${LMD_PATH="/home/traffic/log/bro/tmp/"}

# macros
mime=${BROAPT_MIME}
path=${BROAPT_PATH}
name=$(basename ${path})
logs="${LMD_PATH}/${name%\.+}"

# run detection
maldet --file-list ${path} | tee "${logs}.tmp"

# get report
last=`tail -1 "${logs}.tmp"`
IFS=' ' read -ra line <<< ${last}
EDITOR=cat maldet --report ${line[-1]} > "${logs}.log"

# check report
report=`cat "${logs}.log" | grep 'TOTAL HITS'`
IFS=' ' read -ra line <<< ${report}
detect=${line[-1]}

if [[ ${detect} -eq 0 ]]; then
    rate="false"
else
    rate="true"
fi

# generate report
time=$(date +%s.%N)
report="{\"time\": ${time}, \"path\": \"${path}\", \"mime\": \"${mime}\", \"rate\": ${rate}}"
echo ${report} > "${LOGS_PATH}/rate.log"
