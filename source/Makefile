.PHONY: archive

include .env

archive: archive-app archive-core

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
