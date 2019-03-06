.PHONY: all bro broker

PYTHON ?= cp36

all: bro broker

.ONESHELL:
bro:
	set -ex
	cd $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
	cp bro.sh venv/$(PYTHON)/build.sh
	cd venv/$(PYTHON) && bash build.sh
	rm venv/$(PYTHON)/build.sh

.ONESHELL:
broker:
	set -ex
	cd $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
	cp broker.sh venv/$(PYTHON)/build.sh
	cd venv/$(PYTHON) && bash build.sh
	rm venv/$(PYTHON)/build.sh
