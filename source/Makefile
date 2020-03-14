.PHONY: init bundle clean docker vendor build

-include .env

OS = $(shell uname | tr "[[:upper:]]" "[[:lower:]]")
DAEMONPID = $(shell pgrep server/bin/broaptd.${OS} | xargs)

init: mkdir-dump mkdir-logs
build: build-darwin build-linux
clean: clean-api clean-build clean-dump clean-logs

setup:
	$(MAKE) -C server setup

run:
	bash init.sh

stop:
	kill -2 ${DAEMONPID} || true
	docker-compose -f docker/docker-compose.${OS}.yml stop

kill:
	kill -9 ${DAEMONPID} || true
	docker-compose -f docker/docker-compose.${OS}.yml kill

build-darwin: clean-build
	$(MAKE) -C server build-darwin

build-linux: clean-build
	$(MAKE) -C server build-linux

docker:
	sed -i "" "s/LABEL version.*/LABEL version=$(shell date +%Y.%m.%d)/" Dockerfile
	docker build --rm --tag broapt .
	docker system prune --volumes -f

vendor:
	rm -rf vendor
	mkdir -p vendor vendor/{archive,python}
	wget http://download.opensuse.org/repositories/network:bro/CentOS_7/network:bro.repo \
	    -O vendor/archive/network-bro.repo
	$(MAKE) -C ../vendor/python/src download
	find ../vendor/python/src/download -iname '*.tar.gz' -type f -exec cp -f {} vendor/python \;
	find ../vendor/python/src/download -iname '*.whl' -type f -exec cp -f {} vendor/python \;

clean-build:
	$(MAKE) -C server clean

clean-dump:
	if [ -d /home/traffic/log/extract ]; then \
	    rm -rf /home/traffic/log/extract; \
	    mkdir -p /home/traffic/log/extract; \
	else \
	    find ./dump -depth 1 -type d -print0 | xargs -0 rm -rf; \
	    find ./dump -depth 1 -type f -print0 | xargs -0 rm -rf; \
	fi

clean-logs:
	if [ -d /home/traffic/log/bro ]; then \
	    rm -f /home/traffic/log/bro/*.lock; \
	    > /home/traffic/log/bro/file.log; \
	    > /home/traffic/log/bro/mime.log; \
	    > /home/traffic/log/bro/time.log; \
	    > /home/traffic/log/bro/dump.log; \
	    > /home/traffic/log/bro/fail.log; \
	    > /home/traffic/log/bro/rate.log; \
	    > /home/traffic/log/bro/stdout.log; \
	    > /home/traffic/log/bro/stderr.log; \
	    rm -rf /home/traffic/log/bro/api; \
	    mkdir -p /home/traffic/log/bro/api; \
	    rm -rf /home/traffic/log/bro/http; \
	    mkdir -p /home/traffic/log/bro/http; \
		rm -rf /home/traffic/log/bro/info; \
	    mkdir -p /home/traffic/log/bro/info; \
	    rm -rf /home/traffic/log/bro/tmp; \
	    mkdir -p /home/traffic/log/bro/tmp; \
	    for file in $$(ls /home/traffic/log/bro) ; do \
	        [ -d "/home/traffic/log/bro/$${file}" ] && \
	        [ "/home/traffic/log/bro/$${file}" != "api" ] && \
	        [ "/home/traffic/log/bro/$${file}" != "http" ] && \
	        [ "/home/traffic/log/bro/$${file}" != "info" ] && \
	        [ "/home/traffic/log/bro/$${file}" != "tmp" ] && \
	        rm -rf "/home/traffic/log/bro/$${file}" || true; \
	    done \
	else \
	    rm -f ./logs/*.lock; \
	    > ./logs/dump.log; \
	    > ./logs/fail.log; \
	    > ./logs/rate.log; \
	    > ./logs/file.log; \
	    > ./logs/mime.log; \
	    > ./logs/time.log; \
	    > ./logs/stdout.log; \
	    > ./logs/stderr.log; \
	    find ./logs \
	        ! -iname 'api' \
	        ! -iname 'http' \
	        ! -iname 'info' \
	        ! -iname 'tmp' -type d -depth 1 -print0 | xargs -0 rm -rf; \
	    find ./logs/api -depth 1 -print0 | xargs -0 rm -rf; \
	    find ./logs/http -iname '*.log' -depth 1 -type f -print0 | xargs -0 rm -rf; \
	    find ./logs/info -iname '*.log' -depth 1 -type f -print0 | xargs -0 rm -rf; \
	    find ./logs/tmp -iname '*.json' -depth 1 -type f -print0 | xargs -0 rm -rf; \
	fi

clean-api:
	rm -rf include/api/application/vnd.openxmlformats-officedocument/MaliciousMacroBot
	rm -rf include/api/application/x-executable/ELF-Parser/elfparser/
	rm -rf include/api/application/javascript/JaSt/JaSt
	rm -rf include/api/application/octet-stream/LMD/linux-malware-detect

mkdir-dump:
	mkdir -p ./dump

mkdir-logs:
	mkdir -p ./logs
