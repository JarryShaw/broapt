.PHONY: init build link clean test

DIR ?= "random"

build: build-link build-make
init: mkdir-contents mkdir-extract_files mkdir-logs
clean: clean-contents clean-extract_files clean-logs clean-nohup clean-state
link: build-link json-link

test:
	mkdir -p ../test
	mkdir -p ../test/$(DIR)
	cp Makefile ../test/$(DIR)
	$(MAKE) -C ../test/$(DIR) init

json-link:
	cd custom && ln -sf ../../vendor/json/single_include/nlohmann/json.hpp ./json.hh

build-link:
	cd custom && ln -sf TCP\ Reassembly/TCP\ Reassembly/main.cpp ./reass.cc

build-make:
	mkdir -p build
	g++ --std=c++0x custom/reass.cc -o build/reass

clean-contents: clean-contents-dat clean-contents-part

clean-contents-dat:
	find contents -iname '*.dat' -print0 | xargs -0 rm -f

clean-contents-part:
	find contents -iname '*.part' -print0 | xargs -0 rm -f

clean-extract_files:
	find extract_files -depth 1 -type d -print0 | xargs -0 rm -rf
	find extract_files -depth 1 -type f -print0 | xargs -0 rm -rf

clean-logs: clean-logs-local clean-logs-folder

clean-logs-local:
	find . -iname '*.log' -print0 | xargs -0 rm -f

clean-logs-folder:
	find logs -iname '*.log' -print0 | xargs -0 rm -f

clean-nohup:
	rm -f nohup.out

clean-state:
	rm -rf .state

mkdir-contents:
	mkdir -p contents

mkdir-extract_files:
	mkdir -p extract_files

mkdir-logs:
	mkdir -p logs
