#!/usr/bin/env bash

set -aex

cd /source

if [ -f .env ] ; then
    source .env
fi

mkdir -p /test/docker /test/archive
mv -f /test/docker /test/archive/docker-$(python3 -c "print(__import__('uuid').uuid4())")
python3 python /sample/*.pcap /pcap/*.pcap
mv -f *.log /test/docker

# do not quit
while true; do
    sleep 5m
done
