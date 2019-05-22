#!/usr/bin/env bash

set -ex

# paths
LOGS_PATH=${BROAPT_LOGS_PATH="/var/log/bro/"}
APK_PATH=${APK_PATH="/var/log/bro/tmp/"}

# macros
mime=${BROAPT_MIME}
path=${BROAPT_PATH}
name=$(basename ${path})

# move target to a temporary directory
tempdir="${APK_PATH}/${name%\.apk}"
cp ${path} "${tempdir}/${name}"

# run AndroPyTool
docker run --volume=${tempdir}:/apks alexmyg/andropytool -s /apks/

# check result
if [ -f "${tempdir}/BW/${name}" ]; then
    rate="false"
elif [ -f "${tempdir}/MW/${name}" ]; then
    rate="true"
else
    exit 1

# generate report
time=$(date +%s.%N)
report="{\"time\": ${time}, \"path\": \"${path}\", \"mime\": \"${mime}\", \"rate\": ${rate}}"
echo ${report} > "${LOGS_PATH}/processed_rate.log"
