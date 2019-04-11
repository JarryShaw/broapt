#!/usr/bin/env bash

set -x

cd /source

python3 python /sample/*.pcap
mv -f dumps /test/docker

# do not quit
while true; do
    sleep 5m
done
