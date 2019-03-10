.PHONY: all build clean link recursive \
		broker file-extration pypcapkit zeek

all: broker file-extraction pypcapkit zeek
build: broker-build-release zeek-build-release
clean: broker-clean file-extraction-clean pypcapkit-clean zeek-clean
link: link-cellar link-venv
recursive: broker-recursive file-extraction zeek-recursive

.ONESHELL:
link-cellar:
	set -ex
	cd $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
	ln -sf $(shell brew --prefix bro) Cellar

.ONESHELL:
link-venv:
	set -ex
	cd $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
	ln -sf $(shell pipenv --venv) venv

broker: broker-clean
	git clone https://github.com/zeek/broker.git $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))/broker

broker-clean:
	rm -rf $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))/broker

broker-build-nighty: broker-recursive
	# build & install Broker
	mkdir -p $(shell pipenv --venv)/broker
	pipenv run $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))/broker/configure \
	    --prefix=$(shell pipenv --venv)/broker \
	    --python-prefix=$(shell pipenv run python -c 'import sys; print(sys.exec_prefix)') \
	    --with-python=$(shell pipenv --py) \
	    --with-python-config=$(shell pipenv --venv)/bin/python-config \
	    --with-openssl=$(shell brew --prefix openssl)
	pipenv run $(MAKE) -C $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))/broker install
	# reset broker submodule
	$(MAKE) -C $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST)))) broker

.ONESHELL:
broker-build-release:
	set -ex
	cd $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
	# download Broker
	wget https://www.zeek.org/downloads/broker-1.1.2.tar.gz -O broker-1.1.2.tar.gz
	tar -xzf broker-1.1.2.tar.gz
	cd broker-1.1.2
	# modify configure
	cp ../setup-configure.py setup-configure.py
	pipenv run python setup-configure.py
	chmod +x configure
	# build & install Broker
	mkdir -p $(shell pipenv --venv)/broker
	pipenv run ./configure \
	    --prefix=$(shell pipenv --venv)/broker \
	    --python-prefix=$(shell pipenv run python -c 'import sys; print(sys.exec_prefix)') \
	    --with-python=$(shell pipenv --py) \
	    --with-openssl=$(shell brew --prefix openssl)
	pipenv run $(MAKE) install
	# remove arhives
	rm -rf \
	    broker\-1.1.2
	    broker\-1.1.2.tar.gz

broker-recursive: broker-clean
	git clone --recursive https://github.com/zeek/broker.git $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))/broker

file-extraction: file-extraction-clean
	git clone https://github.com/hosom/file-extraction.git $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))/file-extraction

file-extraction-clean:
	rm -rf $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))/file\-extraction

pypcapkit: pypcapkit-clean
	git clone https://github.com/JarryShaw/PyPCAPKit.git $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))/pypcapkit

pypcapkit-clean:
	rm -rf $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))/pypcapkit

zeek: zeek-clean
	git clone https://github.com/zeek/zeek.git $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))/zeek

zeek-clean:
	rm -rf $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))/zeek

zeek-build-nighty: zeek-recursive
	# build & install Bro
	mkdir -p $(shell pipenv --venv)/{bro,var,etc}
	pipenv run $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))/zeek/configure \
	    --prefix=$(shell pipenv --venv)/bro \
	    --localstatedir=$(shell pipenv --venv)/var \
	    --conf-files-dir=$(shell pipenv --venv)/etc \
	    --with-openssl=$(shell brew --prefix openssl)
	pipenv run $(MAKE) -C $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))/zeek
	pipenv run $(MAKE) -C $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))/zeek install
	# reset broker submodule
	$(MAKE) -C $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST)))) zeek

.ONESHELL:
zeek-build-release:
	set -ex
	cd $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
	# download Bro
	wget https://www.zeek.org/downloads/bro-2.6.1.tar.gz -O bro-2.6.1.tar.gz
	tar -xzf bro-2.6.1.tar.gz
	cd bro-2.6.1
	# build & install Bro
	mkdir -p $(shell pipenv --venv)/{bro,var,etc}
	pipenv run ./configure \
	    --prefix=$(shell pipenv --venv)/bro \
	    --localstatedir=$(shell pipenv --venv)/var \
	    --conf-files-dir=$(shell pipenv --venv)/etc \
	    --with-openssl=$(shell brew --prefix openssl)
	pipenv run $(MAKE)
	pipenv run $(MAKE) install
	# remove arhives
	rm -rf \
	    bro\-2.6.1
	    bro\-2.6.1.tar.gz

zeek-recursive: zeek-clean
	git clone --recursive https://github.com/zeek/zeek.git $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))/zeek
