.PHONY: archive clean docker docker-compose parse

include .env

# OS
os = $(shell uname | tr "[[:upper:]]" "[[:lower:]]")

# pipenv
export PIPENV_DONT_LOAD_ENV

# BroAPT-Core environment
## concurrent process limit
export BROAPT_CORE_CPU
## sleep interval
export BROAPT_CORE_INTERVAL
## Bro MIME white list
export BROAPT_LOAD_MIME
## Bro protocol white list
export BROAPT_LOAD_PROTOCOL
## group extracted file by MIME types
export BROAPT_MIME_MODE
## log in JSON format
export BROAPT_JSON_MODE
## run Bro in bare mode
export BROAPT_BARE_MODE
## path to extract files
export BROAPT_DUMP_PATH
## path to source PCAP files
export BROAPT_PCAP_PATH
## path to log files
export BROAPT_LOGS_PATH
## Bro file reassembly buffer size
export BROAPT_FILE_BUFFER
## Bro extract file size limit
export BROAPT_SIZE_LIMIT

archive: archive-app archive-core archive-daemon
clean: clean-app clean-core clean-daemon
docker-up: docker-up-app docker-up-core
docker-stop: docker-stop-app docker-stop-core
docker-ps: docker-ps-app docker-ps-core
docker-logs: docker-logs-app docker-logs-core

docker: docker-app docker-core

docker-compose:
	docker-compose build
	docker-compose up -d
	docker system prune --volumes -f

archive-app: clean-app
	mkdir -p archive
	tar -cvzf broapt-app.tar.gz app
	mv broapt-app.tar.gz archive

archive-core: clean-core
	mkdir -p archive
	tar -cvzf broapt-core.tar.gz core
	mv broapt-core.tar.gz archive

archive-daemon: clean-daemon
	mkdir -p archive
	tar -cvzf broapt-daemon.tar.gz daemon
	mv broapt-daemon.tar.gz archive

archive-test:
	[ -d test ] || false
	cp -rf test bro
	pipenv run python utils/compose.py
	tar -cvzf bro.tar.gz bro
	mv bro.tar.gz archive
	rm -rf bro

build-darwin: clean-daemon
	$(MAKE) -C daemon build-darwin

build-linux: clean-daemon
	$(MAKE) -C daemon build-linux

clean-app:
	$(MAKE) -C app clean

clean-core:
	$(MAKE) -C core clean

clean-daemon:
	$(MAKE) -C daemon clean

docker-app:
	$(MAKE) -C app docker

docker-core:
	$(MAKE) -C core docker

docker-up-app:
	docker-compose -f app/docker/docker-compose.${os}.yml up -d

docker-up-core:
	docker-compose -f core/docker/docker-compose.${os}.yml up -d

docker-stop-app:
	docker-compose -f app/docker/docker-compose.${os}.yml stop

docker-stop-core:
	docker-compose -f core/docker/docker-compose.${os}.yml stop

docker-ps-app:
	docker-compose -f app/docker/docker-compose.${os}.yml ps

docker-ps-core:
	docker-compose -f core/docker/docker-compose.${os}.yml ps

docker-logs-app:
	docker-compose -f app/docker/docker-compose.${os}.yml logs

docker-logs-core:
	docker-compose -f core/docker/docker-compose.${os}.yml logs

parse:
	pipenv run python utils/logparse.py $@

run:
	bash init.sh

setup:
	$(MAKE) -C daemon setup
