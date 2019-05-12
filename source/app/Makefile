.PHONY: init clean docker vendor build

include .env

init: mkdir-dump mkdir-logs
clean: clean-build clean-dump clean-logs

build: build-macos build-centos

build-macos: clean-build
	pipenv run pyinstaller -F spec/broapt-app.macos.spec
	cp dist/broapt-app.macos bin/broapt-app.macos

build-centos: clean-build
	mkdir -p build dist
	docker build --tag broapt-app:centos --file docker/CentOS.dockerfile .
	docker run \
	    --volume ${CWD}/build:/app/build \
	    --volume ${CWD}/dist:/app/dist broapt-app:centos  -F spec/broapt-app.centos.spec
	cp dist/broapt-app.centos bin/broapt-app.centos

build-ubuntu: clean-build
	mkdir -p build dist
	docker build --tag broapt-app:ubuntu --file docker/Ubuntu.dockerfile .
	docker run \
	    --volume ${CWD}/build:/app/build \
	    --volume ${CWD}/dist:/app/dist broapt-app:ubuntu -F spec/broapt-app.ubuntu.spec
	cp dist/broapt-app.ubuntu bin/broapt-app.ubuntu

docker:
	sed -i "" "s/LABEL version.*/LABEL version=$(shell date +%Y.%m.%d)/" Dockerfile
	docker build --rm --tag broapt-app .
	docker system prune --volumes -f

vendor:
	rm -rf vendor/python
	mkdir -p vendor vendor/python
	$(MAKE) -C ../../vendor/python/app download
	find ../../vendor/python/app/download -iname '*.tar.gz' -type f -exec cp -f {} vendor/python \;
	find ../../vendor/python/app/download -iname '*.whl' -type f -exec cp -f {} vendor/python \;

clean-build:
	rm -rf build dist

clean-dump:
	if [ -d /home/traffic/log/extract ]; then \
	    rm -rf /home/traffic/log/extract; \
	    mkdir -p /home/traffic/log/extract; \
	else \
	    find ../dump -depth 1 -type d -print0 | xargs -0 rm -rf; \
	    find ../dump -depth 1 -type f -print0 | xargs -0 rm -rf; \
	fi

clean-logs:
	if [ -d /home/traffic/log/bro ]; then \
	    > /home/traffic/log/bro/processed_dump.log; \
	    > /home/traffic/log/bro/processed_fail.log; \
	    > /home/traffic/log/bro/processed_rate.log; \
	    rm -rf /home/traffic/log/bro/tmp; \
	    mkdir -p /home/traffic/log/bro/tmp; \
	    rm -rf /home/traffic/log/bro/api; \
	    mkdir -p /home/traffic/log/bro/api; \
	else \
	    > ../logs/processed_dump.log; \
	    > ../logs/processed_fail.log; \
	    > ../logs/processed_rate.log; \
		find ../logs/api -depth 1 -print0 | xargs -0 rm -rf; \
	    find ../logs/tmp -iname '*.json' -depth 1 -type f -print0 | xargs -0 rm -rf; \
	fi

mkdir-dump:
	mkdir -p ../dump

mkdir-logs:
	mkdir -p ../logs
