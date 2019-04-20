.PHONY: init clean docker f2format vendor

init: mkdir-dump mkdir-logs
clean: clean-dump clean-logs

docker: clean f2format
	sed -i "" "s/LABEL version.*/LABEL version=$(shell date +%Y.%m.%d)/" Dockerfile
	docker build --rm --tag broapt-app .
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
	mkdir -p vendor vendor/{modules,python}
	$(MAKE) -C ../../vendor/python/app download
	find ../../vendor/python/app/download -iname '*.tar.gz' -type f -exec cp -f {} vendor/python \;
	find ../../vendor/python/app/download -iname '*.whl' -type f -exec cp -f {} vendor/python \;

clean-dump:
	if [ -d /home/traffic/log/extract ]; then \
	    rm -rf /home/traffic/log/extract; \
	    mkdir -p /home/traffic/log/extract; \
	else \
	    find ../dump -depth 1 -type d -print0 | xargs -0 rm -rf; \
	    find ../dump -depth 1 -type f -print0 | xargs -0 rm -rf; \
	fi

clean-logs:
	if [ -d /home/traffic/pcapfile ]; then \
	    > /home/traffic/pcapfile/processed_file.log; \
	    > /home/traffic/pcapfile/processed_mime.log; \
	    > /home/traffic/pcapfile/processed_time.log; \
	else \
	    > ../../sample/processed_file.log; \
	    > ../../sample/processed_mime.log; \
	    > ../../sample/processed_time.log; \
	fi

mkdir-dump:
	mkdir -p ../dump

mkdir-logs:
	mkdir -p ../logs
