.PHONY: init bundle clean docker vendor build

include .env

init: mkdir-dump mkdir-logs
build: build-darwin build-linux
clean: clean-api clean-build clean-dump clean-logs

run:
	bash init.sh

bundle:
	pipenv run pyinstaller -F server/spec/broaptd.spec
	cp dist/broaptd bin/broaptd

build-darwin: build-macos
	mv bin/broaptd.macos bin/broaptd.darwin

build-macos: clean-build
	pipenv run pyinstaller -F server/spec/broaptd.macos.spec
	cp dist/broaptd.macos bin/broaptd.macos

build-linux: build-centos
	mv bin/broaptd.centos bin/broaptd.linux

build-centos: clean-build
	mkdir -p build dist
	docker build --tag broaptd:centos --file server/docker/CentOS.dockerfile .
	docker run \
	    --volume ${CWD}/build:/broaptd/build \
	    --volume ${CWD}/dist:/broaptd/dist broaptd:centos  -F server/spec/broaptd.centos.spec
	cp dist/broaptd.centos bin/broaptd.centos

build-ubuntu: clean-build
	mkdir -p build dist
	docker build --tag broaptd:ubuntu --file server/docker/Ubuntu.dockerfile .
	docker run \
	    --volume ${CWD}/build:/broaptd/build \
	    --volume ${CWD}/dist:/broaptd/dist broaptd:ubuntu -F server/spec/broaptd.ubuntu.spec
	cp dist/broaptd.ubuntu bin/broaptd.ubuntu

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
	rm -rf build dist

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
	    > /home/traffic/log/bro/http.log; \
	    > /home/traffic/log/bro/processed_file.log; \
	    > /home/traffic/log/bro/processed_info.log; \
	    > /home/traffic/log/bro/processed_mime.log; \
	    > /home/traffic/log/bro/processed_time.log; \
	    > /home/traffic/log/bro/processed_dump.log; \
	    > /home/traffic/log/bro/processed_fail.log; \
	    > /home/traffic/log/bro/processed_rate.log; \
	    rm -rf /home/traffic/log/bro/tmp; \
	    mkdir -p /home/traffic/log/bro/tmp; \
	    rm -rf /home/traffic/log/bro/api; \
	    mkdir -p /home/traffic/log/bro/api; \
	    for file in $$(ls /home/traffic/log/bro) ; do \
	        [ -d "/home/traffic/log/bro/$${file}" ] && \
		    [ "/home/traffic/log/bro/$${file}" != "tmp" ] && \
		    rm -rf "/home/traffic/log/bro/$${file}" || true; \
	    done \
	else \
	    rm -f ./logs/*.lock; \
	    > ./logs/http.log; \
	    > ./logs/processed_dump.log; \
	    > ./logs/processed_fail.log; \
	    > ./logs/processed_rate.log; \
	    > ./logs/processed_file.log; \
	    > ./logs/processed_info.log; \
	    > ./logs/processed_mime.log; \
	    > ./logs/processed_time.log; \
	    find ./logs \
		    ! -iname 'tmp' \
		    ! -iname 'api' -type d -depth 1 -print0 | xargs -0 rm -rf; \
		find ./logs/api -depth 1 -print0 | xargs -0 rm -rf; \
	    find ./logs/tmp -iname '*.json' -depth 1 -type f -print0 | xargs -0 rm -rf; \
	fi

clean-api:
	rm -rf include/api/application/vnd.openxmlformats-officedocument/MaliciousMacroBot
	rm -rf include/api/application/x-executable/elfparser
	rm -rf include/api/application/javascript/JaSt

mkdir-dump:
	mkdir -p ./dump

mkdir-logs:
	mkdir -p ./logs
