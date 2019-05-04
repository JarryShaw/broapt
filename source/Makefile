.PHONY: archive clean docker docker-compose parse

include .env

export PIPENV_DONT_LOAD_ENV=1
## core environ
export DUMP_MIME=1
export DUMP_PATH=/dump/
export PCAP_PATH=/pcap/
export LOGS_PATH=/var/log/bro/
## Bro MIME whilelist
export BRO_MIME=application/x-dosexec,application/msword,application/pdf,application/vnd.android.package-archive
## buffer size
# export FILE_BUFFER=0xffffffffffffffff
## size limit
export SIZE_LIMIT=0

archive: archive-app archive-core archive-test
clean: clean-app clean-core
docker-up: docker-up-app docker-up-core
docker-stop: docker-stop-app docker-stop-core
docker-ps: docker-ps-app docker-ps-core
docker-logs: docker-logs-app docker-logs-core

docker: clean docker-app docker-core
	docker system prune --volumes -f

docker-compose: clean
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
