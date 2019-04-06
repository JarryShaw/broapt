#!/usr/bin/env bash

set -x

# change CWD
cd /source

# run main scripts
time python3 python/wrapper.py /sample
mv reass_time.txt /test/test.0.log
mv reass_http.log /test/reass_http.0.log
mv extract_files.log /test/extract_files.0.log

time python3 python/wrapper.py /pcap/2019_01_15_12_01_52.pcap
mv extract_files.log /test/extract_files.1.log
mv reass_http.log /test/reass_http.1.log
mv reass_time.txt /test/test.1.log

mv extract_files /test/extract_files

# do not quit
while true; do
    sleep 5m
done
