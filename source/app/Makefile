.PHONY: init clean docker vendor

init: mkdir-dump mkdir-logs
clean: clean-dump clean-logs

docker: clean
	sed -i "" "s/LABEL version.*/LABEL version=$(shell date +%Y.%m.%d)/" Dockerfile
	docker build --rm --tag broapt-app .
	docker system prune --volumes -f

vendor:
	rm -rf vendor/python
	mkdir -p vendor vendor/python
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
	if [ -d /home/traffic/log/bro ]; then \
	    > /home/traffic/log/bro/processed_dump.log; \
	    > /home/traffic/log/bro/processed_fail.log; \
	    > /home/traffic/log/bro/processed_rate.log; \
	    rm -rf /home/traffic/log/bro/tmp; \
	    mkdir -p /home/traffic/log/bro/tmp; \
	else \
	    > ../logs/processed_dump.log; \
	    > ../logs/processed_fail.log; \
	    > ../logs/processed_rate.log; \
	    find ../logs/tmp -iname '*.json' -depth 1 -type f -print0 | xargs -0 rm -rf; \
	fi

mkdir-dump:
	mkdir -p ../dump

mkdir-logs:
	mkdir -p ../logs
