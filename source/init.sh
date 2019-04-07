#!/usr/bin/env bash

set -x

# change CWD
cd /source

# set environ
export PCAPKIT_DEVMODE=1

# run main scripts
time python3 python/wrapper.py /sample/http-*.pcap
mv -f reass_time.txt /test/test.0.log
mv -f extract_files.log /test/extract_files.0.log

time python3 python/wrapper.py /sample/test-*.pcap
mv -f reass_time.txt /test/test.1.log
mv -f extract_files.log /test/extract_files.1.log

time python3 python/wrapper.py /pcap/2019_01_15_12_01_52.pcap
mv -f extract_files.log /test/extract_files.2.log
mv -f reass_time.txt /test/test.2.log

mv -f extract_files /test/extract_files

# do not quit
while true; do
    sleep 5m
done
