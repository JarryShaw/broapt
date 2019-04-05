#!/usr/bin/env bash

set -ex

# change CWD
cd /source

# run main scripts
for file in $(ls /sample/*.pcap | sort); do
    time python3 python/wrapper.py ${file}
done

# do not quit
while true; do
    sleep 5m
done
