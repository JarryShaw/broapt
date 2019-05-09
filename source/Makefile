.PHONY: archive clean docker docker-compose parse

include .env

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

archive: archive-app archive-core
clean: clean-app clean-core
docker-up: docker-up-app docker-up-core
docker-stop: docker-stop-app docker-stop-core
docker-ps: docker-ps-app docker-ps-core
docker-logs: docker-logs-app docker-logs-core

docker: docker-app docker-core

docker-compose:
	docker-compose build
	docker-compose up -d
	docker system prune --volumes -f

archive-app:
	mkdir -p archive
	tar -cvzf broapt-app.tar.gz app
	mv broapt-app.tar.gz archive

archive-core:
	mkdir -p archive
	tar -cvzf broapt-core.tar.gz core
	mv broapt-core.tar.gz archive

archive-test:
	[ -d test ] || false
	cp -rf test bro
	pipenv run python utils/compose.py
	tar -cvzf bro.tar.gz bro
	mv bro.tar.gz archive
	rm -rf bro

clean-app:
	$(MAKE) -C app clean

clean-core:
	$(MAKE) -C core clean

docker-app:
	$(MAKE) -C app docker

docker-core:
	$(MAKE) -C core docker

docker-up-app:
	cd app && docker-compose up -d

docker-up-core:
	cd core && docker-compose up -d

docker-stop-app:
	cd app && docker-compose stop

docker-stop-core:
	cd core && docker-compose stop

docker-ps-app:
	cd app && docker-compose ps

docker-ps-core:
	cd core && docker-compose ps

docker-logs-app:
	cd app && docker-compose logs

docker-logs-core:
	cd core && docker-compose logs

parse:
	pipenv run python utils/logparse.py
