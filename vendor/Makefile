.PHONY: all file-extration zeek

all: file-extraction zeek

.ONESHELL:
file-extraction:
	set -ex
	cd $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
	git clone https://github.com/hosom/file-extraction.git

zeek:
	cd $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
	git clone https://github.com/zeek/zeek.git
