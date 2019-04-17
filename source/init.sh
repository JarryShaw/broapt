#!/usr/bin/env bash

set -aex

cd /source

if [ -f .env ] ; then
    source .env
fi

mkdir -p /test/docker /test/archive
mv -f /test/docker /test/archive/docker-$(date '+%y%m%d-%H%M%S')
python3 python /sample/*.pcap /pcap/*.pcap
mv -f *.log /test/docker

# do not quit
while true; do
    sleep 5m
done
