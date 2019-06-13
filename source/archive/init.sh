#!/usr/bin/env bash

set -x

# change CWD
cd /source

# set environ
export PCAPKIT_DEVMODE=1
mkdir -p /test/docker

# run main scripts
time python3 python/wrapper.py /sample/http-*.pcap
mv -f reass_time.txt /test/docker/test-http.log
mv -f extract_files.log /test/docker/extract_files-http.log

time python3 python/wrapper.py /sample/test-*.pcap
mv -f reass_time.txt /test/docker/test-full.log
mv -f extract_files.log /test/docker/extract_files-full.log

time python3 python/wrapper.py /pcap/2019_01_15_12_01_52.pcap
mv -f extract_files.log /test/docker/extract_files-full.1.log
mv -f reass_time.txt /test/docker/test-full.1.log

mv -f extract_files /test/docker/

# do not quit
while true; do
    sleep 5m
done
