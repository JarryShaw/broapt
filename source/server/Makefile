.PHONY: build

include .env

build: build-darwin build-linux

bundle:
	pipenv run pyinstaller -F spec/broaptd.spec
	cp dist/broaptd bin/broaptd

build-darwin: build-macos
	mv bin/broaptd.macos bin/broaptd.darwin

build-macos: clean
	pipenv run pyinstaller -F spec/broaptd.macos.spec
	cp dist/broaptd.macos bin/broaptd.macos

build-linux: build-centos
	mv bin/broaptd.centos bin/broaptd.linux

build-centos: clean
	mkdir -p build dist
	docker build --tag broaptd:centos --file docker/CentOS.dockerfile .
	docker run \
	    --volume ${CWD}/build:/broaptd/build \
	    --volume ${CWD}/dist:/broaptd/dist broaptd:centos  -F spec/broaptd.centos.spec
	cp dist/broaptd.centos bin/broaptd.centos

build-ubuntu: clean
	mkdir -p build dist
	docker build --tag broaptd:ubuntu --file docker/Ubuntu.dockerfile .
	docker run \
	    --volume ${CWD}/build:/broaptd/build \
	    --volume ${CWD}/dist:/broaptd/dist broaptd:ubuntu -F spec/broaptd.ubuntu.spec
	cp dist/broaptd.ubuntu bin/broaptd.ubuntu

clean:
	rm -rf build dist

setup:
	cp -f bin/broaptd.linux /usr/local/bin/broaptd
	cp -f service/broaptd.env /etc/sysconfig/broaptd
	cp -f service/broaptd.service /usr/lib/systemd/system/
	systemctl enable broaptd.service
	systemctl daemon-reload
	systemctl restart broaptd.service
