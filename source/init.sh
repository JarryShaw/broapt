#!/usr/bin/env bash

set -aex

cd /source

if [ -f .env ] ; then
    source .env
fi

python3 python /sample/*.pcap /pcap/*.pcap
mv -f time.txt /test/docker

# do not quit
while true; do
    sleep 5m
done
