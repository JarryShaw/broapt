.PHONY: all build clean link recursive \
		broker file-extration zeek

all: broker file-extraction zeek
build: broker-build-release zeek-build-release
clean: broker-clean file-extraction-clean zeek-clean
link: link-cellar link-venv
recursive: broker-recursive file-extraction zeek-recursive

link-cellar:
	set -ex
	cd $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
	ln -sf $(shell brew --prefix bro) Cellar

link-venv:
	set -ex
	cd $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
	ln -sf $(shell pipenv --venv) venv

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
broker-build-nighty: broker-recursive
	set -ex
	cd $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))/broker
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
	pipenv run make install
	# reset broker submodule
	cd ..
	$(MAKE) broker

.ONESHELL:
broker-build-release:
	set -ex
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
	pipenv run make install
	# remove arhives
	rm -rf \
	    broker\-1.1.2
	    broker\-1.1.2.tar.gz

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
zeek-build-nighty: zeek-recursive
	set -ex
	cd $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))/zeek
	# build & install Bro
	mkdir -p $(shell pipenv --venv)/{bro,var,etc}
	pipenv run ./configure \
	    --prefix=$(shell pipenv --venv)/bro \
	    --localstatedir=$(shell pipenv --venv)/var \
	    --conf-files-dir=$(shell pipenv --venv)/etc \
	    --with-openssl=$(shell brew --prefix openssl)
	pipenv run make
	pipenv run make install
	# reset broker submodule
	cd ..
	$(MAKE) zeek

.ONESHELL:
zeek-build-release:
	set -ex
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
	pipenv run make
	pipenv run make install
	# remove arhives
	rm -rf \
	    bro\-2.6.1
	    bro\-2.6.1.tar.gz

.ONESHELL:
zeek-recursive: zeek-clean
	cd $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
	git clone --recursive https://github.com/zeek/zeek.git
