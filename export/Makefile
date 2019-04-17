.PHONY: init clean docker f2format

init: mkdir-dump
clean: clean-dump clean-logs clean-state

docker:
	docker build --rm --tag bro .
	docker system prune --volumes -f

f2format:
	rm -rf source/python
	cp -rf source/python-dev source/python
	pipenv run f2format \
	    --no-archive \
	    --encoding='UTF-8' \
	    --python='3.7' source/python

clean-dump:
	if [[ $(shell uname) =~ Darwin ]]; then \
	    find source/dumps -depth 1 -type d -print0 | xargs -0 rm -rf; \
	    find source/dumps -depth 1 -type f -print0 | xargs -0 rm -rf; \
	else \
	    rm -rf source/dumps/* ; \
	fi

clean-logs: clean-logs-local

clean-logs-local:
	find . -iname '*.log' -print0 | xargs -0 rm -f

clean-nohup:
	rm -f nohup.out

clean-state:
	rm -rf source/.state

mkdir-dump:
	mkdir -p source/dump
