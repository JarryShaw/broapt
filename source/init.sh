#!/usr/bin/env bash

set -ex

cd /source

python3 python /sample/*.pcap /pcap/*.pcap
mv -f time.txt /test/docker

# do not quit
while true; do
    sleep 5m
done
