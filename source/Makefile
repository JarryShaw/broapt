.PHONY: init clean test

DIR ?= "random"

init: mkdir-contents mkdir-dumps mkdir-logs
clean: clean-contents clean-dumps clean-logs clean-nohup clean-state

test:
	mkdir -p ../test
	mkdir -p ../test/$(DIR)
	cp Makefile ../test/$(DIR)
	$(MAKE) -C ../test/$(DIR) init

clean-contents: clean-contents-dat clean-contents-part

clean-contents-dat:
	find contents -iname '*.dat' -print0 | xargs -0 rm -f

clean-contents-part:
	find contents -iname '*.part' -print0 | xargs -0 rm -f

clean-dumps:
	@if [[ $(shell uname) =~ Darwin ]]; then \
	    find dumps -depth 1 -type d -print0 | xargs -0 rm -rf; \
	    find dumps -depth 1 -type f -print0 | xargs -0 rm -rf; \
	else \
	    rm -rf dumps/* ; \
	fi

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

mkdir-dumps:
	mkdir -p dumps

mkdir-logs:
	mkdir -p logs
