.PHONY: all build clean link recursive \
		broker file-extration zeek

ROOT := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))

all: broker file-extraction zeek
build: broker-build-release zeek-build-release
clean: broker-clean file-extraction-clean zeek-clean
link: link-cellar link-venv
recursive: broker-recursive zeek-recursive

.ONESHELL:
link-cellar:
	set -ex
	cd $(ROOT)
	ln -sf $(shell brew --prefix bro) Cellar

.ONESHELL:
link-venv:
	set -ex
	cd $(ROOT)
	ln -sf $(shell pipenv --venv) venv

broker: broker-clean
	git submodule add https://github.com/zeek/broker.git $(ROOT)/broker

broker-clean:
	rm -rf $(ROOT)/broker

broker-build-brew-install:
	brew install bro cmake

broker-build-brew-uninstall:
	brew uninstall cmake

broker-build-nighty:
	# install dependencies
	$(MAKE) broker-build-brew-install
	# build & install Broker
	$(MAKE) broker-build-nighty-make
	# reset broker submodule
	$(MAKE) -C $(ROOT) broker
	# uninstall build dependencies
	$(MAKE) broker-build-brew-uninstall

broker-build-nighty-make: broker-recursive
	mkdir -p $(shell pipenv --venv)/broker
	pipenv run $(ROOT)/broker/configure \
	    --build-dir=$(ROOT)/broker/build \
	    --prefix=$(shell pipenv --venv)/broker \
	    --python-prefix=$(shell pipenv run python -c 'import sys; print(sys.exec_prefix)') \
	    --with-python=$(shell pipenv --py) \
	    --with-python-config=$(shell pipenv --venv)/bin/python-config \
	    --with-bro=$(shell brew --prefix bro)/bin/bro \
	    --with-openssl=$(shell brew --prefix openssl)
	pipenv run $(MAKE) -C $(ROOT)/broker install

broker-build-release:
	# install dependencies
	$(MAKE) broker-build-brew-install
	# modify configure
	$(MAKE) broker-build-release-patch
	# build & install Broker
	$(MAKE) broker-build-release-make
	# remove arhives
	rm -rf \
	    $(ROOT)/broker\-1.1.2 \
	    $(ROOT)/broker\-1.1.2.tar.gz
	# uninstall build dependencies
	$(MAKE) broker-build-brew-uninstall

broker-build-release-download:
	@if [ ! -f $(ROOT)/broker-1.1.2.tar.gz ] ; then \
	    wget https://www.zeek.org/downloads/broker-1.1.2.tar.gz \
	        -O $(ROOT)/broker-1.1.2.tar.gz ; \
	fi
	tar -xzf $(ROOT)/broker-1.1.2.tar.gz -C $(ROOT)

broker-build-release-patch:
	cp $(ROOT)/setup-configure.py $(ROOT)/broker-1.1.2/setup-configure.py
	pipenv run python $(ROOT)/broker-1.1.2/setup-configure.py
	chmod +x $(ROOT)/broker-1.1.2/configure

broker-build-release-make: broker-build-release-download broker-build-release-patch
	mkdir -p $(shell pipenv --venv)/broker
	pipenv run $(ROOT)/broker-1.1.2/configure \
	    --build-dir=$(ROOT)/broker-1.1.2/build \
	    --prefix=$(shell pipenv --venv)/broker \
	    --python-prefix=$(shell pipenv run python -c 'import sys; print(sys.exec_prefix)') \
	    --with-python=$(shell pipenv --py) \
	    --with-bro=$(shell brew --prefix bro)/bin/bro \
	    --with-openssl=$(shell brew --prefix openssl)
	pipenv run $(MAKE) -C $(ROOT)/broker-1.1.2 install

broker-recursive: broker-clean
	git clone --recursive https://github.com/zeek/broker.git $(ROOT)/broker

file-extraction: file-extraction-clean
	git submodule add https://github.com/hosom/file-extraction.git $(ROOT)/file-extraction

file-extraction-clean:
	rm -rf $(ROOT)/file\-extraction

zeek: zeek-clean
	git submodule add https://github.com/zeek/zeek.git $(ROOT)/zeek

zeek-clean:
	rm -rf $(ROOT)/zeek

zeek-build-brew-install:
	brew install bison cmake geoip openssl swig

zeek-build-brew-uninstall:
	brew uninstall bison cmake swig

zeek-build-nighty:
	# install dependencies
	$(MAKE) zeek-build-brew-install
	# build & install Bro
	$(MAKE) zeek-build-nighty-make
	# reset broker submodule
	$(MAKE) -C $(ROOT) zeek
	# uninstall build dependencies
	$(MAKE) zeek-build-brew-uninstall

zeek-build-nighty-make: zeek-recursive
	mkdir -p $(shell pipenv --venv)/{bro,var,etc}
	pipenv run $(ROOT)/zeek/configure \
	    --builddir=$(ROOT)/zeek/build \
	    --prefix=$(shell pipenv --venv)/bro \
	    --localstatedir=$(shell pipenv --venv)/var \
	    --conf-files-dir=$(shell pipenv --venv)/etc \
	    --with-openssl=$(shell brew --prefix openssl) \
	    --with-bison=$(shell brew --prefix bison)/bin/bison \
	    --with-python=$(shell pipenv --py) \
	    --with-geoip=$(shell brew --prefix geoip) \
	    --with-swig=$(shell brew --prefix swig)/bin/swig
	pipenv run $(MAKE) -C $(ROOT)/zeek
	pipenv run $(MAKE) -C $(ROOT)/zeek install

zeek-build-release:
	# install dependencies
	$(MAKE) zeek-build-brew-install
	# build & install Bro
	$(MAKE) zeek-build-release-make
	# remove arhives
	rm -rf \
	    $(ROOT)/bro\-2.6.1 \
	    $(ROOT)/bro\-2.6.1.tar.gz
	# install dependencies
	$(MAKE) zeek-build-brew-uninstall

zeek-build-release-download:
	@if [ ! -f $(ROOT)/bro-2.6.1.tar.gz ] ; then \
	    wget https://www.zeek.org/downloads/bro-2.6.1.tar.gz \
	        -O $(ROOT)/bro-2.6.1.tar.gz ; \
	fi
	tar -xzf $(ROOT)/bro-2.6.1.tar.gz -C $(ROOT)

zeek-build-release-make: zeek-build-release-download
	mkdir -p $(shell pipenv --venv)/{bro,var,etc}
	pipenv run $(ROOT)/bro-2.6.1/configure \
	    --builddir=$(ROOT)/bro-2.6.1/build \
	    --prefix=$(shell pipenv --venv)/bro \
	    --localstatedir=$(shell pipenv --venv)/var \
	    --conf-files-dir=$(shell pipenv --venv)/etc \
	    --with-openssl=$(shell brew --prefix openssl) \
	    --with-bison=$(shell brew --prefix bison)/bin/bison \
	    --with-python=$(shell pipenv --py) \
	    --with-geoip=$(shell brew --prefix geoip) \
	    --with-swig=$(shell brew --prefix swig)/bin/swig
	pipenv run $(MAKE) -C $(ROOT)/bro-2.6.1
	pipenv run $(MAKE) -C $(ROOT)/bro-2.6.1 install

zeek-recursive: zeek-clean
	git clone --recursive https://github.com/zeek/zeek.git $(ROOT)/zeek
