#!/usr/bin/env bash

set -ax

# https://github.com/bufferings/docker-access-host/blob/master/docker-entrypoint.sh
HOST_DOMAIN="host.docker.internal"
ping -q -c1 $HOST_DOMAIN > /dev/null 2>&1
if [ $? -ne 0 ]; then
    HOST_IP=$(ip route | awk 'NR==1 {print $3}')
    echo -e "$HOST_IP\t$HOST_DOMAIN" >> /etc/hosts
fi

# change cwd
cd /source

# load environs
if [ -f .env ] ; then
    source .env
fi

# run scripts
/usr/bin/python3.6 python

# sleep
sleep infinity
