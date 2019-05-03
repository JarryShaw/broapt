.PHONY: archive clean docker docker-compose

include .env

archive: archive-app archive-core archive-test
clean: clean-app clean-core
docker-up: docker-up-app docker-up-core
docker-stop: docker-stop-app docker-stop-core
docker-ps: docker-ps-app docker-ps-core
docker-logs: docker-logs-app docker-logs-core
f2format: f2format-app

docker: clean docker-app docker-core
	docker system prune --volumes -f

docker-compose: clean f2format
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
	pipenv run python compose.py
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

f2format-app:
	$(MAKE) -C app f2format
