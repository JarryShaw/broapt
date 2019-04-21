.PHONY: archive clean docker docker-compose

include .env

archive: archive-app archive-core
clean: clean-app clean-core
docker: docker-app docker-core
docker-compose: docker-compose-app docker-compose-core

archive-app:
	mkdir -p archive
	tar -cvzf broapt-app.tar.gz app
	mv broapt-app.tar.gz archive
	scp archive/broapt-app.tar.gz ${SRV_PATH}/source/archive/

archive-core:
	mkdir -p archive
	mv core bro
	tar -cvzf broapt-core.tar.gz bro
	mv bro core
	mv broapt-core.tar.gz archive
	scp archive/broapt-core.tar.gz ${SRV_PATH}/source/archive/
	scp archive/broapt-core.tar.gz ${SRV_PATH}/../

clean-app:
	$(MAKE) -C app clean

clean-core:
	$(MAKE) -C core clean

docker-app:
	$(MAKE) -C app docker

docker-core:
	$(MAKE) -C core docker

docker-compose-app: docker-app
	cd app && docker-compose up -d

docker-compose-core: docker-core
	cd core && docker-compose up -d
