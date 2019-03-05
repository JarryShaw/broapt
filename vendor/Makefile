.PHONY: all build clean recursive \
		broker file-extration zeek

all: broker file-extraction zeek
build: broker-build
clean: broker-clean file-extraction-clean zeek-clean
recursive: broker-recursive file-extraction zeek-recursive

.ONESHELL:
broker: broker-clean
	set -ex
	cd $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
	git clone https://github.com/zeek/broker.git

.ONESHELL:
broker-clean:
	set -ex
	cd $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
	rm -rf broker

.ONESHELL:
broker-build: broker-recursive
	set -ex
	cd $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))/broker
	# build & install Broker
	mkdir -p $(shell pipenv --venv)/broker
	pipenv run ./configure \
	    --prefix=$(shell pipenv --venv)/broker \
	    --python-prefix=$(shell pipenv run python -c 'import sys; print(sys.exec_prefix)') \
	    --with-python=$(shell pipenv --py) \
	    --with-openssl=/usr/local/opt/openssl
	pipenv run make install
	# reset broker submodule
	cd ..
	$(MAKE) broker

.ONESHELL:
broker-recursive: broker-clean
	set -ex
	cd $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
	git clone --recursive https://github.com/zeek/broker.git

.ONESHELL:
file-extraction: file-extraction-clean
	set -ex
	cd $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
	git clone https://github.com/hosom/file-extraction.git

.ONESHELL:
file-extraction-clean:
	set -ex
	cd $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
	rm -rf file-extraction

.ONESHELL:
zeek: zeek-clean
	cd $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
	git clone https://github.com/zeek/zeek.git

.ONESHELL:
zeek-clean:
	set -ex
	cd $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
	rm -rf zeek

.ONESHELL:
zeek-recursive: zeek-clean
	cd $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
	git clone --recursive https://github.com/zeek/zeek.git
