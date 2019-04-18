.PHONY: init clean docker f2format vendor

init: mkdir-dump
clean: clean-dump clean-logs clean-state

docker: clean
	sed -i "" "s/LABEL version.*/LABEL version=$(shell date +%Y.%m.%d)/" Dockerfile
	docker build --rm --tag bro .
	docker system prune --volumes -f

f2format:
	rm -rf source/python
	cp -rf source/python-dev source/python
	pipenv run f2format \
	    --no-archive \
	    --encoding='UTF-8' \
	    --python='3.7' source/python

vendor:
	rm -rf vendor
	mkdir -p vendor vendor/{archive,python}
	cp -f ../../vendor/archive/linux/bro-2.6.1.ubuntu.16.04.tar.gz vendor/archive
	$(MAKE) -C ../../vendor/python/core download
	find ../../vendor/python/core/download -iname '*.tar.gz' -type f -exec cp -f {} vendor/python \;
	find ../../vendor/python/core/download -iname '*.whl' -type f -exec cp -f {} vendor/python \;

clean-dump:
	if [ -d /home/traffic/log/extract ]; then \
	    rm -rf /home/traffic/log/extract; \
	    mkdir -p /home/traffic/log/extract; \
	else \
	    find source/dumps -depth 1 -type d -print0 | xargs -0 rm -rf; \
	    find source/dumps -depth 1 -type f -print0 | xargs -0 rm -rf; \
	fi

clean-logs: clean-logs-local clean-logs-processed

clean-logs-local:
	find . -iname '*.log' -print0 | xargs -0 rm -f

clean-logs-processed:
	if [ -d /home/traffic/pcapfile ]; then \
	    > /home/traffic/pcapfile/processed_file.log; \
	    > /home/traffic/pcapfile/processed_mime.log; \
	    > /home/traffic/pcapfile/processed_time.log; \
	else \
	    > ../../sample/processed_file.log; \
	    > ../../sample/processed_mime.log; \
	    > ../../sample/processed_time.log; \
	fi

clean-nohup:
	rm -f nohup.out

clean-state:
	rm -rf source/.state

mkdir-dump:
	mkdir -p source/dump
