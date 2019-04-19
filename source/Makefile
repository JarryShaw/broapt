.PHONY: archive

archive: archive-app archive-core

archive-app:
	mkdir -p archive
	tar -cvzf broapt-app.tar.gz app
	mv broapt-app.tar.gz archive

archive-core:
	mkdir -p archive
	mv core bro
	tar -cvzf broapt-core.tar.gz bro
	mv bro core
	mv broapt-core.tar.gz archive
